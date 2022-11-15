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

mod config;
mod enclave;
mod ocall_impl;

extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;

use std::{
	env,
	net::{SocketAddr, TcpListener, TcpStream},
	os::unix::io::{AsRawFd, IntoRawFd},
	str,
};

use sgx_crypto_helper::{
	rsa3072::{Rsa3072KeyPair, Rsa3072PubKey},
	RsaKeyPair,
};
// use std::io::Write;
use std::slice;

use log::*;
use sp_runtime::generic::SignedBlock as SignedBlockG;
use substrate_api_client::{rpc::WsRpcClient, Api, AssetTipExtrinsicParams};

// local modules
use config::Config;
use enclave::{api::*, ffi};
use sp_core::{crypto::{AccountId32, Ss58Codec, Pair},ed25519};

fn main() {
	// Setup logging
	env_logger::init();
	// let config_f = std::fs::File::open("config.yml").expect("Could not open file.");
	// let config: Config = serde_yaml::from_reader(config_f).expect("Could not read values.");
	// debug!("Node server address: {}", config.node_ip);
	let enclave = match enclave_init() {
		Ok(r) => {
			println!("[+] Init Enclave Successful {}!", r.geteid());
			r
		},
		Err(x) => {
			println!("[-] Init Enclave Failed {}!", x.as_str());
			return
		},
	};

	// ------------------------------------------------------------------------
	// Get the public key of our TEE.
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let mut pubkey = [0u8; 32 as usize];

	let result = unsafe {
		ffi::get_ecc_signing_pubkey(
			enclave.geteid(),
			&mut retval,
			pubkey.as_mut_ptr(),
			pubkey.len() as u32,
		)
	};
	match result {
		sgx_status_t::SGX_SUCCESS => {
			let pubkey = ed25519::Public::from_raw(pubkey);
			let accountId = AccountId32::from(*pubkey.as_array_ref());
			println!("Enclave account {:} ", &accountId.to_ss58check());
			println!("ECALL success!");
		},
		_ => {
			println!("[-] ECALL Enclave Failed {}!", result.as_str());
			return
		},
	}

	// let mut sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
	// let mut retval = sgx_status_t::SGX_SUCCESS;
	// let result = unsafe { ffi::perform_ra(enclave.geteid(), &mut retval, sign_type) };
	// match result {
	// 	sgx_status_t::SGX_SUCCESS => {
	// 		println!("ECALL success!");
	// 	},
	// 	_ => {
	// 		println!("[-] ECALL Enclave Failed {}!", result.as_str());
	// 		return
	// 	},
	// }

	// let pubkey_size = 8192;
	// let mut pubkey = vec![0u8; pubkey_size as usize];
	//
	// let mut retval = sgx_status_t::SGX_SUCCESS;
	//
	// let result = unsafe {
	//     ffi::get_rsa_encryption_pubkey(
	//         enclave.geteid(),
	//         &mut retval,
	//         pubkey.as_mut_ptr(),
	//         pubkey.len() as u32,
	//     )
	// };
	//
	// let rsa_pubkey: Rsa3072PubKey =
	//     serde_json::from_slice(pubkey.as_slice()).expect("Invalid public key");
	// println!("got RSA pubkey {:?}", rsa_pubkey);
	//
	// //A bunch of data decrypted by time
	// for i in 0..10 {
	//     let mut retval = sgx_status_t::SGX_SUCCESS;
	//     let mut private_key = String::from("I send a private_key");
	//     private_key = private_key + &i.to_string();
	//     let private_key_slice = &private_key.into_bytes();
	//     let mut private_key_cipher = Vec::new();
	//     match rsa_pubkey.encrypt_buffer(private_key_slice, &mut private_key_cipher) {
	//         Ok(n) => println!("Generated payload {} bytes", n),
	//         Err(x) => println!("Error occured during encryption {}", x),
	//     }
	//     let result = unsafe {
	//         ffi::handle_private_keys(
	//             enclave.geteid(),
	//             &mut retval,
	//             private_key_cipher.as_ptr() as *const u8,
	//             private_key_cipher.len() as u32,
	//             1667874198 + i,
	//             2
	//         )
	//     };
	//     println!("{:?}",result);
	// }
	// // Data that has not been decrypted in time
	// for i in 10..15 {
	//     let mut retval = sgx_status_t::SGX_SUCCESS;
	//     let mut private_key = String::from("I send a private_key");
	//     private_key = private_key + &i.to_string();
	//     let private_key_slice = &private_key.into_bytes();
	//     let mut private_key_cipher = Vec::new();
	//     match rsa_pubkey.encrypt_buffer(private_key_slice, &mut private_key_cipher) {
	//         Ok(n) => println!("Generated payload {} bytes", n),
	//         Err(x) => println!("Error occured during encryption {}", x),
	//     }
	//     let result = unsafe {
	//         ffi::handle_private_keys(
	//             enclave.geteid(),
	//             &mut retval,
	//             private_key_cipher.as_ptr() as *const u8,
	//             private_key_cipher.len() as u32,
	//             1667983347 + i,
	//             2
	//         )
	//     };
	//     println!("{:?}",result);
	// }

	enclave.destroy();
}

