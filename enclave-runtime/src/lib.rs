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
// use for rpc
use crate::attestation::hash_from_slice;
use sp_core::blake2_256;
pub use substrate_api_client::{
	compose_extrinsic_offline, ExtrinsicParams, PlainTip, PlainTipExtrinsicParams,
	PlainTipExtrinsicParamsBuilder, SubstrateDefaultSignedExtra, UncheckedExtrinsicV4,
};

lazy_static! {
	static ref MIN_BINARY_HEAP: Mutex<BinaryHeap<Reverse<KeyPiece>>> =
		Mutex::new(BinaryHeap::new());
	pub static ref NODE_META_DATA: Mutex<Vec<u8>> = Mutex::new(Vec::<u8>::new());
}

struct LocalRsa3072PubKey {
	pub n: [u8; SGX_RSA3072_KEY_SIZE],
	pub e: [u8; SGX_RSA3072_PUB_EXP_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
struct KeyPiece {
	release_time: u64,
	from_block: u32,
	key_piece: Vec<u8>,
	ext_index: u32
}

impl Ord for KeyPiece {
	fn cmp(&self, other: &Self) -> Ordering {
		self.release_time.cmp(&other.release_time).reverse()
	}
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
	let mut key_vec: Vec<u8> = Vec::new();
	let key_json_str = match SgxFile::open(KEYFILE) {
		Ok(mut f) => match f.read_to_end(&mut key_vec) {
			Ok(len) => {
				println!("Read {} bytes from Key file", len);
				std::str::from_utf8(&key_vec).unwrap()
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
	let pubkey_exposed: LocalRsa3072PubKey = std::mem::transmute(rsa_pubkey);
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
pub extern "C" fn insert_key_piece(
	key: *const u8,
	key_len: u32,
	release_time: u64,
	current_block: u32,
	ext_index: u32,
) -> sgx_status_t {
	// Decrypt key piece inside the enclave.
	let key_piece = unsafe { slice::from_raw_parts(key, key_len as usize) };
	let decrypted_key = get_decrypt_cipher_text(key_piece.as_ptr() as *const u8, key_piece.len());
	let ext_item = KeyPiece { release_time, from_block: current_block, key_piece: decrypted_key, ext_index };
	info!("Inserting a new key piece to the enclave queue!");
	let mut min_heap = MIN_BINARY_HEAP.lock().unwrap();
	min_heap.push(Reverse(ext_item));
	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn get_expired_key(
	key: *mut u8,
	key_len: u32,
	from_block: *mut u32,
	ext_index: *mut u32
) -> sgx_status_t {
	// reset the block height.
	unsafe {
		*from_block = 0;
	}
	// TODO: replace with trusted time
	let mut now_time: u64 = 0;
	let _res = unsafe {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		ffi::ocall_time_ntp(&mut rt as *mut sgx_status_t, &mut now_time);
	};
	info!("Getting an expired key piece from the enclave queue!");
	let mut min_heap = MIN_BINARY_HEAP.lock().unwrap();
	// Check if any key is expired.
	if let Some(Reverse(v)) = min_heap.peek() {
		if v.release_time <= now_time {
			let expired_key = unsafe { slice::from_raw_parts_mut(key, key_len as usize) };
			write_slice_and_whitespace_pad(expired_key, v.key_piece.clone())
				.expect("Key buffer is overflown!");
			unsafe {
				*from_block = v.from_block;
				*ext_index = v.ext_index;
			}
			min_heap.pop();
		}
	}
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

#[no_mangle]
pub unsafe extern "C" fn perform_expire_key(
	genesis_hash: *const u8,
	genesis_hash_size: u32,
	nonce: *const u32,
	expired_key: *const u8,
	expired_key_size: u32,
	block_number: *const u32,
	ext_index: *const u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	let chain_signer = Ed25519Seal::unseal_from_static_file().unwrap();
	println!("[Enclave Expire Key] Ed25519 pub raw : {:?}", chain_signer.public().0);

	println!("[Enclave] Compose extrinsic");
	let genesis_hash_slice = slice::from_raw_parts(genesis_hash, genesis_hash_size as usize);
	//let mut nonce_slice     = slice::from_raw_parts(nonce, nonce_size as usize);
	let expired_key_slice = slice::from_raw_parts(expired_key, expired_key_size as usize);
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);
	let signer = match Ed25519Seal::unseal_from_static_file() {
		Ok(pair) => pair,
		Err(e) => return e.into(),
	};
	println!("[Enclave] Restored ECC pubkey: {:?}", signer.public());

	println!("decoded nonce: {}", *nonce);
	let genesis_hash = hash_from_slice(genesis_hash_slice);
	println!("decoded genesis_hash: {:?}", genesis_hash_slice);

	let node_metadata_slice_mem = NODE_META_DATA.lock().unwrap();

	let mut metadata_slice: Vec<u8> = Vec::<u8>::new();
	for (_, item) in node_metadata_slice_mem.iter().enumerate() {
		metadata_slice.push(*item);
	}
	let metadata = match NodeMetadata::decode(&mut metadata_slice.as_slice()).map_err(Error::Codec)
	{
		Err(e) => {
			error!("Failed to decode node metadata: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
		Ok(m) => m,
	};

	let (register_enclave_call, runtime_spec_version, runtime_transaction_version) = (
		metadata.call_indexes("Trex", "send_expired_key"),
		metadata.get_runtime_version(),
		metadata.get_runtime_transaction_version(),
	);

	let call =
		match register_enclave_call {
			Ok(c) => c,
			Err(e) => {
				error!("Failed to get the indexes for the register_enclave call from the metadata: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		};

	let extrinsic_params = PlainTipExtrinsicParams::new(
		runtime_spec_version,
		runtime_transaction_version,
		*nonce,
		genesis_hash,
		PlainTipExtrinsicParamsBuilder::default(),
	);

	#[allow(clippy::redundant_clone)]
	let xt = compose_extrinsic_offline!(
		signer,
		(call, expired_key_slice.to_vec(), block_number as u32, ext_index as u32),
		extrinsic_params
	);

	let xt_encoded = xt.encode();
	let xt_hash = blake2_256(&xt_encoded);
	debug!("[Enclave] Encoded extrinsic ( len = {} B), hash {:?}", xt_encoded.len(), xt_hash);

	match write_slice_and_whitespace_pad(extrinsic_slice, xt_encoded) {
		Ok(_) => {},
		Err(e) => {
			println!("Result Error {:?}", e);
		},
	};

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn test_decrypt(
	plain: *const u8,
	plain_len: u32,
	cipher: *const u8,
	cipher_len: u32,
	res: *mut u8,
) -> sgx_status_t {
	let decrypted = get_decrypt_cipher_text(cipher, cipher_len as usize);
	let original = unsafe { slice::from_raw_parts(plain, plain_len as usize) };
	// set the compare result as 1: true, means equal.
	unsafe {
		*res = 1;
	}
	// if do not match, set as 0: false
	for (ai, bi) in decrypted.iter().zip(original.iter()) {
		match ai.cmp(&bi) {
			Ordering::Equal => continue,
			_ => unsafe {
				*res = 0;
			},
		}
	}
	if decrypted.len() != original.len() {
		unsafe {
			*res = 0;
		}
	}
	sgx_status_t::SGX_SUCCESS
}

fn get_decrypt_cipher_text(cipher_text: *const u8, cipher_len: usize) -> Vec<u8> {
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
	plaintext
}

#[allow(unused)]
fn get_json_str(filename: &str) -> String {
	let mut keyvec: Vec<u8> = Vec::new();

	let key_json_str = match SgxFile::open(filename) {
		Ok(mut f) => match f.read_to_end(&mut keyvec) {
			Ok(_) => std::str::from_utf8(&keyvec).unwrap(),
			Err(_) => return "".to_string(),
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
