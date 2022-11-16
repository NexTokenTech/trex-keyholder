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
#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]
mod config;
mod enclave;
mod ocall_impl;
mod utils;

extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;

use frame_system::EventRecord;
use log::{debug, info};
use sgx_crypto_helper::{
	rsa3072::{Rsa3072KeyPair, Rsa3072PubKey},
	RsaKeyPair,
};
use sp_runtime::generic::SignedBlock as SignedBlockG;
use std::{sync::mpsc::channel, thread, time::Duration};
use std::path::PathBuf;
use substrate_api_client::{
	rpc::WsRpcClient, utils::FromHexString, Api, ApiClientError, AssetTipExtrinsicParams,
	Header as HeaderTrait, Metadata, XtStatus,
};

// trex modules
use pallet_trex::Event as TrexEvent;
use trex_runtime::RuntimeEvent;
// local modules
use crate::enclave::error::Error;
use config::Config;
use enclave::{api::*, ffi};
use frame_support::ensure;
use sp_core::{crypto::AccountId32, ed25519, sr25519, Decode, H256 as Hash, Encode};
use tkp_settings::worker::EXTRINSIC_MAX_SIZE;
use utils::node_metadata::NodeMetadata;

use clap::Parser;

/// Arguments for the Key-holding services.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Path of config YAML file.
	#[arg(short, long, default_value_t=("config.yml".to_string()))]
	config: String,
}

fn main() {
	// ------------------------------------------------------------------------
	// Setup logging
	env_logger::init();
	// ------------------------------------------------------------------------
	// load Config from config.yml
	let args = Args::parse();
	let config_path = PathBuf::from(args.config);
	let config_f = std::fs::File::open(config_path).expect("Could not open file.");
	let config: Config = serde_yaml::from_reader(config_f).expect("Could not read values.");
	debug!("Loaded Config from YAML: {:#?}", config);
	// ------------------------------------------------------------------------
	// init enclave instance
	let enclave = match enclave_init() {
		Ok(r) => {
			info!("[+] Init Enclave Successful {}!", r.geteid());
			r
		},
		Err(x) => {
			info!("[-] Init Enclave Failed {}!", x.as_str());
			return
		},
	};

	// ------------------------------------------------------------------------
	// Get the account ID of our TEE.
	let tee_account_id = enclave_account(&enclave).unwrap();

	// prepare websocket connection.
	let url = config.node_url();
	let client = WsRpcClient::new(&url);
	let api = Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client).unwrap();

	let genesis_hash = get_genesis_hash(&config);

	// ------------------------------------------------------------------------
	// Perform a remote attestation and get an unchecked extrinsic back.
	let nonce = get_nonce(&tee_account_id, &config).unwrap();
	set_nonce(&enclave, &nonce);

	let metadata = api.metadata.clone();
	let runtime_spec_version = api.runtime_version.spec_version;
	let runtime_transaction_version = api.runtime_version.transaction_version;

	set_node_metadata(
		&enclave,
		NodeMetadata::new(metadata, runtime_spec_version, runtime_transaction_version).encode(),
	);

	let trusted_url = config.mu_ra_url();
	let uxt = perform_ra(&enclave, genesis_hash, nonce, trusted_url.as_bytes().to_vec()).unwrap();

	let mut xthex = hex::encode(uxt);
	xthex.insert_str(0, "0x");

	info!("Generated RA EXT");
	// TODO: send extrinsic on chain
	// println!("[>] Register the enclave (send the extrinsic)");
	// let register_enclave_xt_hash = node_api.send_extrinsic(xthex, XtStatus::Finalized).unwrap();
	// println!("[<] Extrinsic got finalized. Hash: {:?}\n", register_enclave_xt_hash);

	// TODO: Get account ID of current key-holder node.
	// TODO: Send remote attestation as ext to the trex network.
	// Spawn a thread to listen to the TREX data event.
	let event_url = url.clone();
	let mut handlers = Vec::new();
	handlers.push(thread::spawn(move || {
		// Listen to TREXDataSent events.
		let client = WsRpcClient::new(&event_url);
		let api = Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client).unwrap();
		println!("Subscribe to TREX events");
		let (events_in, events_out) = channel();
		api.subscribe_events(events_in).unwrap();
		loop {
			let event_str = events_out.recv().unwrap();
			let _unhex = Vec::from_hex(event_str).unwrap();
			let mut _er_enc = _unhex.as_slice();
			let events = Vec::<EventRecord<RuntimeEvent, Hash>>::decode(&mut _er_enc).unwrap();
			// match event with trex event
			for event in &events {
				debug!("decoded: {:?} {:?}", event.phase, event.event);
				match &event.event {
					// match to trex events.
					RuntimeEvent::Trex(te) => {
						debug!(">>>>>>>>>> TREX event: {:?}", te);
						// match trex data sent event.
						match &te {
							TrexEvent::TREXDataSent(_id, _byte_data) => {
								// TODO: deserialize TREX struct data and check key pieces.
								todo!();
							},
							_ => {
								debug!("ignoring unsupported TREX event");
							},
						}
					},
					_ => debug!("ignoring unsupported module event: {:?}", event.event),
				}
			}
			// wait 100 ms for next iteration
			thread::sleep(Duration::from_millis(100));
		}
	}));
	// TODO: check the enclave and release expired key pieces.
	// join threads.
	for handler in handlers {
		handler.join().expect("The thread being joined has panicked");
	}

	enclave.destroy();
}

/// Get the remote attestation in the enclave and organize it into ext in the corresponding format of pallet-tee
fn perform_ra(
	enclave: &SgxEnclave,
	genesis_hash: Vec<u8>,
	nonce: u32,
	w_url: Vec<u8>,
) -> Result<Vec<u8>, Error> {
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
			w_url.as_ptr(),
			w_url.len() as u32,
			unchecked_extrinsic.as_mut_ptr(),
			unchecked_extrinsic.len() as u32,
		)
	};

	ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
	ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

	Ok(unchecked_extrinsic)
}

/// Put node metadata into enclave memory for temporary storage
fn set_node_metadata(enclave: &SgxEnclave, metadata: Vec<u8>) {
	let mut retval = sgx_status_t::SGX_SUCCESS;

	let result = unsafe {
		ffi::set_node_metadata(
			enclave.geteid(),
			&mut retval,
			metadata.as_ptr(),
			metadata.len() as u32,
		)
	};
	match result {
		sgx_status_t::SGX_SUCCESS => {
			println!("ECALL Set Metadata Success!");
		},
		_ => {
			println!("[-] ECALL Set Metadata Enclave Failed {}!", result.as_str());
			return
		},
	}
}

/// Put the nonce of the account into the enclave memory for temporary storage
fn set_nonce(enclave: &SgxEnclave, nonce: &u32) {
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let result = unsafe { ffi::set_nonce(enclave.geteid(), &mut retval, nonce) };
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

/// Obtain the nonce of the enclave account through rpc
fn get_nonce(who: &AccountId32, config: &Config) -> Result<u32, ApiClientError> {
	let url = format!("{}:{}", config.node_ip, config.node_port);
	let client = WsRpcClient::new(&url);
	let api = Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client).unwrap();
	Ok(api.get_account_info(who)?.map_or_else(|| 0, |info| info.nonce))
}

/// Obtain the genesis hash through rpc
fn get_genesis_hash(config: &Config) -> Vec<u8> {
	let url = format!("{}:{}", config.node_ip, config.node_port);
	let client = WsRpcClient::new(&url);
	let api = Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client).unwrap();
	let genesis_hash = Some(api.get_genesis_hash().expect("Failed to get genesis hash"));
	genesis_hash.unwrap().as_bytes().to_vec()
}

/// Get the public signing key of the TEE.
fn enclave_account(enclave: &SgxEnclave) -> Result<AccountId32, Error> {
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
