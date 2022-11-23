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

mod ocall;
#[cfg(test)]
mod test;
mod utils;

extern crate core;
extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate sgx_types;
extern crate sgx_urts;

use clap::Parser;
use log::{debug, info};
use std::str;

// substrate modules
use frame_system::EventRecord;
// use sp_runtime::generic::SignedBlock as SignedBlockG;
use frame_system::Phase::ApplyExtrinsic;
use sgx_urts::SgxEnclave;
use sp_core::{sr25519, Decode, Encode, H256 as Hash};
use std::{borrow::Borrow, sync::mpsc::channel, thread, time::Duration};
use substrate_api_client::{
	rpc::WsRpcClient, utils::FromHexString, Api, AssetTipExtrinsicParams, XtStatus,
};

// trex modules
use trex_primitives::TREXData;
use trex_runtime::{pallet_trex::Event as TrexEvent, AccountId, BlockNumber, Moment, RuntimeEvent};
// local modules
use config::Config as ApiConfig;
use enclave::api::*;
use utils::{
	node_metadata::NodeMetadata,
	node_rpc::{get_api, get_genesis_hash, get_nonce},
};

/// Arguments for the Key-holding services.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Path of config YAML file.
	#[arg(short, long, default_value_t=("config.yml".to_string()))]
	config: String,
}

enum PerformAction {
	Attestation,
	SendExpireKey,
}

type Events = Vec<EventRecord<RuntimeEvent, Hash>>;

pub type DecodedTREXData = TREXData<AccountId, Moment, BlockNumber>;

fn main() {
	// Setup logging
	env_logger::init();
	// init enclave instance
	let enclave = enclave_init().expect("Cannot create an enclave!");
	// load Config from config.yml
	let args = Args::parse();
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
		NodeMetadata::new(metadata, runtime_spec_version, runtime_transaction_version).encode(),
	);

	let trusted_url = config.mu_ra_url();
	let uxt =
		perform_ra(&enclave, genesis_hash.clone(), nonce, trusted_url.as_bytes().to_vec()).unwrap();

	send_uxt(&config, uxt, XtStatus::Finalized);

	// Spawn a thread to listen to the TREX data event.
	let event_url = config.node_url();
	let mut handlers = Vec::new();
	let local_enclave = enclave.clone();
	let local_tee_account_id = tee_account_id.clone();
	let local_genesis_hash = genesis_hash.clone();
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
										TrexEvent::TREXDataSent(_id, byte_data) => {
											let mut local_bytes = byte_data.as_slice();
											let trex_data =
												DecodedTREXData::decode(&mut local_bytes).unwrap();
											for key_piece in trex_data.key_pieces {
												if tee_account_id == key_piece.holder {
													let shielded_key = key_piece.shielded;
													info!(
														"Found a shielded key {:X?}",
														shielded_key.as_slice()
													);
													match event.phase {
														ApplyExtrinsic(ext_index) => {
															println!("decoded: {:?}", ext_index);
															insert_key_piece(
																local_enclave.borrow(),
																shielded_key,
																trex_data.release_time,
																trex_data.current_block,
																ext_index,
															)
															.expect("Cannot insert shielded key!");
														},
														_ => {},
													}
												}
											}
										},
										_ => {
											debug!("ignoring unsupported TREX event");
										},
									}
								},
								_ => debug!("ignoring unsupported module event: {:?}", event.event),
							}
						}
					},
					Err(e) => {
						println!("{:?}", e)
					},
				}
				// take expired key piece out of the enclave.
				while let Some(expired_key_tuple) = get_expired_key(local_enclave.borrow()) {
					println!("Get expired key piece: {:X?}", expired_key_tuple.0.as_slice());
					send_expired_key(
						&config,
						local_enclave.borrow(),
						local_tee_account_id.borrow(),
						local_genesis_hash.borrow(),
						expired_key_tuple.0,
						expired_key_tuple.1,
						expired_key_tuple.2,
					);
				}
			}
			// // match event with trex event
			// wait 100 ms for next iteration
			thread::sleep(Duration::from_millis(100));
		}
	}));
	// join threads.
	for handler in handlers {
		handler.join().expect("The thread being joined has panicked");
	}
	enclave.destroy();
}

fn parse_events(event: String) -> Result<Events, String> {
	let _unhex = Vec::from_hex(event).map_err(|_| "Decoding Events Failed".to_string())?;
	let mut _er_enc = _unhex.as_slice();
	Events::decode(&mut _er_enc).map_err(|_| "Decoding Events Failed".to_string())
}

fn send_expired_key(
	config: &ApiConfig,
	enclave: &SgxEnclave,
	tee_account_id: &AccountId,
	genesis_hash: &Vec<u8>,
	expired_key: Vec<u8>,
	block_number: u32,
	ext_index: u32,
) {
	let api = get_api(&config).unwrap();

	// ------------------------------------------------------------------------
	// Perform an unchecked extrinsic back.
	let nonce = get_nonce(&tee_account_id, &config).unwrap();
	set_nonce(&enclave, &nonce);

	let metadata = api.metadata.clone();
	let runtime_spec_version = api.runtime_version.spec_version;
	let runtime_transaction_version = api.runtime_version.transaction_version;

	set_node_metadata(
		&enclave,
		NodeMetadata::new(metadata, runtime_spec_version, runtime_transaction_version).encode(),
	);

	let uxt = perform_expire_key(
		&enclave,
		genesis_hash.to_owned(),
		nonce,
		expired_key,
		block_number,
		ext_index,
	)
	.unwrap();

	send_uxt(&config, uxt, XtStatus::SubmitOnly);
}

fn send_uxt(config: &ApiConfig, uxt: Vec<u8>, exit_on: XtStatus) {
	let api = get_api(&config).unwrap();
	let mut xthex = hex::encode(uxt);
	xthex.insert_str(0, "0x");

	debug!("Generated EXT");
	debug!("[>] Send the extrinsic");
	let register_enclave_xt_hash = api.send_extrinsic(xthex, exit_on).unwrap();
	let exit_on_status = match exit_on {
		XtStatus::SubmitOnly => "submitted",
		XtStatus::InBlock => "in block",
		XtStatus::Finalized => "finalized",
		_ => "",
	};
	debug!("[<] Extrinsic got {:?}. Hash: {:?}\n", exit_on_status, register_enclave_xt_hash);
}
