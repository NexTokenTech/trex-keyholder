/*
 Copyright 2022 NexToken Tech LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

*/
#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]
/// Config for keyholder
mod config;
/// Enclave api
mod enclave;
/// Ocall implemetation
mod ocall;
#[cfg(test)]
mod test;
/// Some utils for service
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
use std::{borrow::Borrow, sync::mpsc::channel, time::Duration};
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
	key_piece::TmpKeyPiece,
	node_metadata::NodeMetadata,
	node_rpc::{get_api, get_genesis_hash, get_nonce},
};

use std::{
	cmp::{min, Reverse},
	collections::binary_heap::BinaryHeap,
	sync::Arc
};
use std::cell::RefCell;
use futures::join;
use async_std::task;

/// Arguments for the Key-holding services.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Path of config YAML file.
	#[arg(short, long, default_value_t=("config.yml".to_string()))]
	config: String,
}

/// On chain event collection
type Events = Vec<EventRecord<RuntimeEvent, Hash>>;

/// Decoded Event of the TREXData type
pub type DecodedTREXData = TREXData<AccountId, Moment, BlockNumber>;

/// Main function executed by keyholder
#[async_std::main]
async fn main() {
	// Setup logging
	env_logger::init();
	// init enclave instance
	let enclave = Arc::new(enclave_init().expect("Cannot create an enclave!"));
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

	// startup event listener and nts time scheduler
	let nts_time_ref = RefCell::new(0u64);
	join!(events_listener(&enclave,&config,&tee_account_id),nts_time_scheduler(&enclave,&nts_time_ref),pop_keys(&enclave,&config,&tee_account_id,&genesis_hash,&nts_time_ref));
}

async fn events_listener(enclave:&Arc<SgxEnclave>,config:&ApiConfig,tee_account_id:&AccountId){
	let event_url = config.node_url();
	// Listen to TREXDataSent events.
	let client = WsRpcClient::new(&event_url);
	let api = Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client).unwrap();
	println!("Subscribe to TREX events");
	let (events_in, events_out) = channel();
	api.subscribe_events(events_in).unwrap();
	let timeout = Duration::from_millis(10);
	// Data that cannot be temporarily stored into the heap
	let mut key_piece_cache:BinaryHeap<Reverse<TmpKeyPiece>> = BinaryHeap::new();
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
											if tee_account_id.to_owned() == key_piece.holder {
												let shielded_key = key_piece.shielded;
												info!(
														"Found a shielded key {:X?}",
														shielded_key.as_slice()
													);
												match event.phase {
													ApplyExtrinsic(ext_index) => {
														debug!("Decoded Ext Index: {:?}", ext_index);
														info!("Expect Release Time {}", trex_data.release_time);
														let tmp_key_piece = TmpKeyPiece{
															release_time:trex_data.release_time,
															from_block:trex_data.current_block,
															key_piece:shielded_key.clone(),
															ext_index
														};
														handle_key_piece(enclave.clone(),tmp_key_piece, &mut key_piece_cache);
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
					eprintln!("{:?}", e)
				},
			}
		}
		// wait 100 ms for next iteration
		task::sleep(Duration::from_millis(100)).await;
	}
}

async fn pop_keys(enclave:&Arc<SgxEnclave>,config:&ApiConfig,tee_account_id:&AccountId,genesis_hash:&Vec<u8>,nts_time_ref:&RefCell<u64>){
	loop {
		let nts_time_inner_value = nts_time_ref.clone().into_inner();
		// take expired key piece out of the enclave.
		if let Some((key, block_num, ext_idx)) = get_expired_key(enclave.clone(),nts_time_inner_value) {
			info!("Get expired key piece: {:X?}", key.as_slice());
			send_expired_key(
				&config,
				enclave.clone(),
				tee_account_id.borrow(),
				&genesis_hash.to_vec(),
				key,
				block_num,
				ext_idx,
			);
		}
		task::sleep(Duration::from_millis(1)).await;
	}
}

async fn nts_time_scheduler(enclave:&Arc<SgxEnclave>,nts_time_ref:&RefCell<u64>){
	loop {
		println!("startup nts time scheduler");
		let nts_time_inner_value = nts_time_ref.clone().into_inner();
		let nts_time = perform_nts_time(&enclave).await.unwrap_or(nts_time_inner_value);
		if nts_time != 0 {
			nts_time_ref.replace(nts_time);
		}
		task::sleep(Duration::from_secs(3)).await;
	}
}

fn handle_key_piece(
	enclave: Arc<SgxEnclave>,
	tmp_key_piece: TmpKeyPiece,
	key_piece_cache: &mut BinaryHeap<Reverse<TmpKeyPiece>>,
) {
	key_piece_cache.push(Reverse(tmp_key_piece));
	// Get the remaining heap locations
	let heap_free_count = get_heap_free_count(enclave.clone()).unwrap_or(10);
	if heap_free_count > 0 && key_piece_cache.len() > 0 {
		let insert_count = min(key_piece_cache.len(), heap_free_count);
		for _i in 0..insert_count {
			if let Some(Reverse(item)) = key_piece_cache.peek() {
				insert_key_piece(
					&enclave,
					item.clone().key_piece,
					item.clone().release_time,
					item.clone().from_block,
					item.clone().ext_index,
				)
				.expect("Cannot insert shielded key!");
				key_piece_cache.pop();
			}
		}
	}
}

/// Parse the monitored events
fn parse_events(event: String) -> Result<Events, String> {
	let _unhex = Vec::from_hex(event).map_err(|_| "Decoding Events Failed".to_string())?;
	let mut _er_enc = _unhex.as_slice();
	Events::decode(&mut _er_enc).map_err(|_| "Decoding Events Failed".to_string())
}

/// Send expired keys to the chain
fn send_expired_key(
	config: &ApiConfig,
	enclave: Arc<SgxEnclave>,
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

	debug!("send utx to chain");
	send_uxt(&config, uxt, XtStatus::SubmitOnly);
}

/// Send uxt to chain
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
