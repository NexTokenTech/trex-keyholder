// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![feature(trait_alias)]
#![crate_name = "enclave_runtime"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tse;
extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_crypto_helper;
extern crate sgx_rand;
#[macro_use]
extern crate lazy_static;
extern crate base64;
extern crate bit_vec;
extern crate chrono;
extern crate httparse;
extern crate itertools;
extern crate num_bigint;
extern crate rustls;
extern crate serde_json;
extern crate webpki;
extern crate webpki_roots;
extern crate yasna;

use crate::ocall::ffi;

use sgx_types::*;
use std::{
	cmp::{Ordering, Reverse},
	collections::BinaryHeap,
	io::{Read, Write},
	prelude::v1::*,
	sgxfs::SgxFile,
	slice,
	string::String,
	sync::SgxMutex as Mutex,
	time::SystemTime,
	untrusted::time::SystemTimeEx,
	vec::Vec,
};

use sgx_crypto_helper::{
	rsa3072::{Rsa3072KeyPair, Rsa3072PubKey},
	RsaKeyPair,
};
use sgx_types::{SGX_RSA3072_KEY_SIZE, SGX_RSA3072_PUB_EXP_SIZE};

use log::*;
use std::str;

mod attestation;
mod cert;
pub mod error;
mod hex;
mod ocall;
mod utils;

use crate::error::{Error, Result};
use sp_core::{crypto::Pair, Decode, Encode};
use tkp_nonce_cache::{MutateNonce, Nonce, GLOBAL_NONCE_CACHE};
use tkp_settings::files::*;
use tkp_sgx_crypto::{ed25519, Ed25519Seal};
use tkp_sgx_io::StaticSealedIO;
use utils::node_metadata::NodeMetadata;

lazy_static! {
	static ref MIN_BINARY_HEAP: Mutex<BinaryHeap<Reverse<Ext>>> = Mutex::new(BinaryHeap::new());
	pub static ref NODE_META_DATA: Mutex<Vec<u8>> = Mutex::new(Vec::<u8>::new());
}

pub struct LocalRsa3072PubKey {
	pub n: [u8; SGX_RSA3072_KEY_SIZE],
	pub e: [u8; SGX_RSA3072_PUB_EXP_SIZE],
}

#[no_mangle]
pub unsafe extern "C" fn get_rsa_encryption_pubkey(
	pubkey: *mut u8,
	pubkey_size: u32,
) -> sgx_status_t {
	if SgxFile::open(KEYFILE).is_err() {
		let rsa_keypair = Rsa3072KeyPair::new().unwrap();
		let rsa_key_json = serde_json::to_string(&rsa_keypair).unwrap();
		provisioning_key(rsa_key_json.as_ptr() as *const u8, rsa_key_json.len(), KEYFILE);
	}
	let mut keyvec: Vec<u8> = Vec::new();
	let key_json_str = match SgxFile::open(KEYFILE) {
		Ok(mut f) => match f.read_to_end(&mut keyvec) {
			Ok(len) => {
				println!("Read {} bytes from Key file", len);
				std::str::from_utf8(&keyvec).unwrap()
			},
			Err(x) => {
				println!("Read keyfile failed {}", x);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		},
		Err(x) => {
			println!("get_sealed_pcl_key cannot open keyfile, please check if key is provisioned successfully! {}", x);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let rsa_keypair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();

	let rsa_pubkey: Rsa3072PubKey = rsa_keypair.export_pubkey().unwrap();
	// Use unsafe method to copy the memory of public key.
	let pubkey_exposed: LocalRsa3072PubKey = unsafe {
		std::mem::transmute(rsa_pubkey)
	};
	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	// copy the RSA modulus to the left part and public exponent to the right part.
	let (left, right) = pubkey_slice.split_at_mut(SGX_RSA3072_KEY_SIZE);
	left.clone_from_slice(&pubkey_exposed.n);
	// fill the right side with whitespace
	right.clone_from_slice(&pubkey_exposed.e);

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_ecc_signing_pubkey(pubkey: *mut u8, pubkey_size: u32) -> sgx_status_t {
	if let Err(e) = ed25519::create_sealed_if_absent().map_err(Error::Crypto) {
		return e.into()
	}

	let signer = match Ed25519Seal::unseal_from_static_file().map_err(Error::Crypto) {
		Ok(pair) => pair,
		Err(e) => return e.into(),
	};
	debug!("Restored ECC pubkey: {:?}", signer.public());

	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	pubkey_slice.clone_from_slice(&signer.public());

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn handle_private_keys(
	key: *const u8,
	key_len: u32,
	timestamp: u32,
	enclave_index: u32,
) -> sgx_status_t {
	println!("I'm in enclave");
	// FIXME: Need to do some fault tolerance
	let mut min_heap = MIN_BINARY_HEAP.lock().unwrap();

	let private_key_text_vec = unsafe { slice::from_raw_parts(key, key_len as usize) };
	let ext_item = Ext { timestamp, enclave_index, private_key: private_key_text_vec.to_vec() };
	min_heap.push(Reverse(ext_item));

	// FIXME: replace with trusted time
	let now = SystemTime::now();
	let mut now_time: u64 = 0;
	match now.duration_since(SystemTime::UNIX_EPOCH) {
		Ok(elapsed) => {
			// it prints '2'
			println!("{}", elapsed.as_secs());
			now_time = elapsed.as_secs();
		},
		Err(e) => {
			// an error occurred!
			println!("Error: {:?}", e);
		},
	};

	loop {
		if let Some(Reverse(v)) = min_heap.peek() {
			if v.timestamp <= now_time as u32 {
				let decrpyted_msg = get_decrypt_cipher_text(
					v.private_key.as_ptr() as *const u8,
					v.private_key.len(),
				);
				let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
				let _res = unsafe {
					ffi::ocall_output_key(
						&mut rt as *mut sgx_status_t,
						decrpyted_msg.as_ptr() as *const u8,
						decrpyted_msg.len() as u32,
					);
				};
				min_heap.pop();
			} else {
				break
			}
		} else {
			break
		}
	}
	// TODO: min_heap Persistence
	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn set_nonce(nonce: *const u32) -> sgx_status_t {
	log::info!("[Ecall Set Nonce] Setting the nonce of the enclave to: {}", *nonce);

	let mut nonce_lock = match GLOBAL_NONCE_CACHE.load_for_mutation() {
		Ok(l) => l,
		Err(e) => {
			error!("Failed to set nonce in enclave: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	*nonce_lock = Nonce(*nonce);

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn set_node_metadata(
	node_metadata: *const u8,
	node_metadata_size: u32,
) -> sgx_status_t {
	let mut node_metadata_slice = slice::from_raw_parts(node_metadata, node_metadata_size as usize);
	let metadata = match NodeMetadata::decode(&mut node_metadata_slice).map_err(Error::Codec) {
		Err(e) => {
			error!("Failed to decode node metadata: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
		Ok(m) => m,
	};

	let mut node_metadata_slice_mem = NODE_META_DATA.lock().unwrap();
	node_metadata_slice_mem.clear();
	let metadata_encode = metadata.encode();
	for (_, item) in metadata_encode.iter().enumerate() {
		node_metadata_slice_mem.push(*item);
	}

	sgx_status_t::SGX_SUCCESS
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct Ext {
	timestamp: u32,
	enclave_index: u32,
	private_key: Vec<u8>,
}

impl Ord for Ext {
	fn cmp(&self, other: &Self) -> Ordering {
		self.timestamp.cmp(&other.timestamp).reverse()
	}
}

fn get_decrypt_cipher_text(cipher_text: *const u8, cipher_len: usize) -> String {
	let ciphertext_bin = unsafe { slice::from_raw_parts(cipher_text, cipher_len) };
	let mut keyvec: Vec<u8> = Vec::new();

	let key_json_str = match SgxFile::open(KEYFILE) {
		Ok(mut f) => match f.read_to_end(&mut keyvec) {
			Ok(_len) => std::str::from_utf8(&keyvec).unwrap(),
			Err(_x) => "",
		},
		Err(_x) => "",
	};
	//println!("key_json = {}", key_json_str);
	let rsa_keypair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();
	//println!("Recovered key = {:?}", rsa_keypair);

	let mut plaintext = Vec::new();
	rsa_keypair.decrypt_buffer(&ciphertext_bin, &mut plaintext).unwrap();

	let decrypted_string = String::from_utf8(plaintext).unwrap();
	decrypted_string
}

#[allow(unused)]
fn get_json_str(filename: &str) -> String {
	let mut keyvec: Vec<u8> = Vec::new();

	let key_json_str = match SgxFile::open(filename) {
		Ok(mut f) => match f.read_to_end(&mut keyvec) {
			Ok(_) => std::str::from_utf8(&keyvec).unwrap(),
			Err(_) => {
				return "".to_string()
			},
		},
		Err(_x) => std::str::from_utf8(&keyvec).unwrap(),
	};
	key_json_str.to_string()
}

fn provisioning_key(key_ptr: *const u8, some_len: usize, file_name: &str) {
	//TODO error handler
	let key_slice = unsafe { slice::from_raw_parts(key_ptr, some_len) };

	match SgxFile::create(file_name) {
		Ok(mut f) => match f.write_all(key_slice) {
			Ok(()) => {
				println!("SgxFile write key file success!");
			},
			Err(x) => {
				println!("SgxFile write key file failed! {}", x);
			},
		},
		Err(x) => {
			println!("SgxFile create file {} error {}", file_name, x);
		},
	}
}

pub fn write_slice_and_whitespace_pad(writable: &mut [u8], data: Vec<u8>) -> Result<()> {
	let (left, right) = writable.split_at_mut(data.len());
	left.clone_from_slice(&data);
	// fill the right side with whitespace
	right.iter_mut().for_each(|x| *x = 0x20);
	Ok(())
}
