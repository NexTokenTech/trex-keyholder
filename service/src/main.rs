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

#[allow(unused)]
use sgx_crypto_helper::{
	rsa3072::{Rsa3072KeyPair, Rsa3072PubKey},
	RsaKeyPair,
};
#[allow(unused)]
use sp_runtime::generic::SignedBlock as SignedBlockG;
#[allow(unused)]
use substrate_api_client::{rpc::WsRpcClient, Api, AssetTipExtrinsicParams, Metadata, ApiClientError};

use clap::{load_yaml, App};
use std::path::Path;

// local modules
use config::Config;
use enclave::{api::*, ffi};
use sp_core::{crypto::{AccountId32, Ss58Codec}, ed25519, Pair};
use sp_core::sr25519;
use crate::enclave::error::Error;
use frame_support::ensure;
use tkp_settings::worker::EXTRINSIC_MAX_SIZE;

fn main() {
	// ------------------------------------------------------------------------
	// Setup logging
	env_logger::init();

	// ------------------------------------------------------------------------
	// load Config from config.yml
	let yml = load_yaml!("config.yml");
	let matches = App::from_yaml(yml).get_matches();
	let config = Config::from(&matches);

	// ------------------------------------------------------------------------
	// init enclave instance
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
	let tee_accountid = enclave_account(&enclave).unwrap();

	let url = format!("{}:{}", config.node_ip, config.node_port);
	let client = WsRpcClient::new(&url);
	let api = Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client).unwrap();

	let genesis_hash = get_genesis_hash(&config);

	// ------------------------------------------------------------------------
	// Perform a remote attestation and get an unchecked extrinsic back.
	let nonce = get_nonce(&tee_accountid,&config).unwrap();
	println!("{:?}",nonce);
	set_nonce(&enclave,&nonce);

	let metadata = api.metadata.clone();
	let runtime_spec_version = api.runtime_version.spec_version;
	let runtime_transaction_version = api.runtime_version.transaction_version;
	println!("{:?}",runtime_spec_version);
	println!("{:?}",runtime_transaction_version);

	let trusted_url = config.trusted_worker_url_external();
	// let uxt = if skip_ra {
	// 	println!(
	// 		"[!] skipping remote attestation. Registering enclave without attestation report."
	// 	);
	// 	enclave.mock_register_xt(node_api.genesis_hash, nonce, &trusted_url).unwrap()
	// } else {
	// 	enclave
	// 		.perform_ra(genesis_hash, nonce, trusted_url.as_bytes().to_vec())
	// 		.unwrap()
	// };

	let mut retval = sgx_status_t::SGX_SUCCESS;

	let unchecked_extrinsic_size = EXTRINSIC_MAX_SIZE;
	let mut unchecked_extrinsic: Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];

	let result = unsafe {
		ffi::perform_ra(
			enclave.geteid(),
			&mut retval,
			genesis_hash.as_ptr(),
			genesis_hash.len() as u32,
			&nonce,
			trusted_url.as_ptr(),
			trusted_url.len() as u32,
			unchecked_extrinsic.as_mut_ptr(),
			unchecked_extrinsic.len() as u32,
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {
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

fn set_nonce(enclave: &SgxEnclave,nonce:&u32){
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let result = unsafe { ffi::set_nonce(enclave.geteid(),&mut retval,nonce) };
	match result {
		sgx_status_t::SGX_SUCCESS => {
			println!("ECALL Set Nonce Success!");
		},
		_ => {
			println!("[-] ECALL Set Nonce Enclave Failed {}!", result.as_str());
			return
		},
	}
}

fn get_nonce(who: &AccountId32, config:&Config) -> Result<u32,ApiClientError> {
	let url = format!("{}:{}", config.node_ip, config.node_port);
	let client = WsRpcClient::new(&url);
	let api = Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client).unwrap();
	Ok(api.get_account_info(who)?.map_or_else(|| 0, |info| info.nonce))
}

fn get_genesis_hash(config:&Config) -> Vec<u8>{
	let url = format!("{}:{}", config.node_ip, config.node_port);
	let client = WsRpcClient::new(&url);
	let api = Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client).unwrap();
	let genesis_hash = Some(api.get_genesis_hash().expect("Failed to get genesis hash"));
	genesis_hash.unwrap().as_bytes().to_vec()
}

/// Get the public signing key of the TEE.
fn enclave_account(enclave: &SgxEnclave) -> Result<AccountId32,Error> {
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

	ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
	ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

	let pubkey = ed25519::Public::from_raw(pubkey);
	let tee_account_id = AccountId32::from(*pubkey.as_array_ref());
	Ok(tee_account_id)
}



