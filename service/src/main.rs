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
#[cfg(test)]
mod test;
mod utils;

extern crate core;
extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate sgx_types;
extern crate sgx_urts;

use log::{debug, info};
use clap::Parser;
use std::str;

// substrate moduels
use frame_system::EventRecord;
// use sp_runtime::generic::SignedBlock as SignedBlockG;
use std::{sync::mpsc::channel, thread,time::Duration};
use substrate_api_client::{
	rpc::WsRpcClient, utils::FromHexString, Api, AssetTipExtrinsicParams, XtStatus,
};
use sp_core::{crypto::Ss58Codec, sr25519, Decode, Encode, H256 as Hash};

// trex modules
use trex_runtime::{pallet_trex::Event as TrexEvent, RuntimeEvent, Moment, BlockNumber, AccountId};
use trex_primitives::TREXData;
// local modules
use config::Config as ApiConfig;
use enclave::{api::*};
use utils::node_metadata::NodeMetadata;
use utils::node_rpc::{get_api, get_free_balance, get_genesis_hash, get_nonce};

/// Arguments for the Key-holding services.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Path of config YAML file.
	#[arg(short, long, default_value_t=("config.yml".to_string()))]
	config: String,
	#[command(subcommand)]
	action: Action,
}

#[derive(clap::Subcommand, Debug)]
enum Action {
	Run,
	ShieldingPubKey,
	SigningPubKey,
	GetFreeBalance,
}

pub type DecodedTREXData = TREXData::<AccountId, Moment, BlockNumber>;

fn main() {
	// Setup logging
	env_logger::init();
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
	// load Config from config.yml
	let args = Args::parse();
	match args.action {
		Action::Run => {
			let config = ApiConfig::from_yaml(&args.config);
			debug!("Loaded Config from YAML: {:#?}", config);

			// ------------------------------------------------------------------------
			// Get the account ID of our TEE.
			let tee_account_id = enclave_account(&enclave).unwrap();

			// prepare websocket connection.
			let api = get_api(&config).unwrap();
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
				NodeMetadata::new(metadata, runtime_spec_version, runtime_transaction_version)
					.encode(),
			);

			let trusted_url = config.mu_ra_url();
			let uxt =
				perform_ra(&enclave, genesis_hash, nonce, trusted_url.as_bytes().to_vec()).unwrap();

			let mut xthex = hex::encode(uxt);
			xthex.insert_str(0, "0x");

			info!("Generated RA EXT");
			println!("[>] Register the enclave (send the extrinsic)");
			let register_enclave_xt_hash = api.send_extrinsic(xthex, XtStatus::Finalized).unwrap();
			println!("[<] Extrinsic got finalized. Hash: {:?}\n", register_enclave_xt_hash);

			// Spawn a thread to listen to the TREX data event.
			let event_url = config.node_url();
			let mut handlers = Vec::new();
			handlers.push(thread::spawn(move || {
				// Listen to TREXDataSent events.
				let client = WsRpcClient::new(&event_url);
				let api = Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client).unwrap();
				println!("Subscribe to TREX events");
				let (events_in, events_out) = channel();
				api.subscribe_events(events_in).unwrap();
				let timeout = Duration::from_millis(10);
				loop {
					if let Ok(msg) = events_out.recv_timeout(timeout) {
						match parse_events(msg.clone()) {
							Ok(events) => {
								for event in &events {
									debug!("decoded: {:?}", event.event);
									match &event.event {
										// match to trex events.
										RuntimeEvent::Trex(te) => {
											debug!(">>>>>>>>>> TREX event: {:?}", te);
											// match trex data sent event.
											match &te {
												TrexEvent::TREXDataSent(
													_id,
													byte_data,
												) => {
													let mut local_bytes = byte_data.as_slice();
													let trex_data = DecodedTREXData::decode(&mut local_bytes).unwrap();
													let cipher_str = str::from_utf8(&trex_data.cipher).unwrap();
													for key_piece in trex_data.key_pieces {
														if tee_account_id == key_piece.holder {
															let shielded_key = key_piece.shielded;
															println!("Found a shielded key {:X?}", shielded_key);
														}
													}
													println!("The test cipher is {:#?}", cipher_str);
												},
												_ => {
													debug!("ignoring unsupported TREX event");
												},
											}
										},
										_ => debug!(
											"ignoring unsupported module event: {:?}",
											event.event
										),
									}
								}
							},
							Err(e) => {
								println!("{:?}", e)
							},
						}
					}
					// // match event with trex event
					// wait 100 ms for next iteration
					thread::sleep(Duration::from_millis(100));
				}
			}));
			// TODO: check the enclave and release expired key pieces.
			// join threads.
			for handler in handlers {
				handler.join().expect("The thread being joined has panicked");
			}
		},
		Action::ShieldingPubKey => {
			println!("Generating shielding pub key");
			let rsa_pubkey = get_shielding_pubkey(&enclave);
			let json = serde_json::to_string(&rsa_pubkey).unwrap();
			println!("RSA public key: {json}");
		},
		Action::SigningPubKey => {
			let tee_account_id = enclave_account(&enclave).unwrap();
			println!("Enclave account {:} ", &tee_account_id.to_ss58check());
		},
		Action::GetFreeBalance => {
			// load node config.
			let config = ApiConfig::from_yaml(&args.config);
			// Get the account ID of our TEE.
			let tee_account_id = enclave_account(&enclave).unwrap();
			// Perform a remote attestation and get an unchecked extrinsic back.
			let free_balance = get_free_balance(&tee_account_id, &config).unwrap();
			println!("{:?}", free_balance);
		}
	}
	enclave.destroy();
}

type Events = Vec<EventRecord<RuntimeEvent, Hash>>;

fn parse_events(event: String) -> Result<Events, String> {
	let _unhex = Vec::from_hex(event).map_err(|_| "Decoding Events Failed".to_string())?;
	let mut _er_enc = _unhex.as_slice();
	Events::decode(&mut _er_enc).map_err(|_| "Decoding Events Failed".to_string())
}
