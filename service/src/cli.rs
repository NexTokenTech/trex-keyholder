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
mod config;
mod enclave;
mod ocall;
mod utils;

use aes_gcm::{
	aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
	Aes256Gcm, Nonce,
};
use clap::Parser;
use config::Config as ApiConfig;
use enclave::api::{enclave_init, enclave_account};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
#[allow(unused)]
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sp_core::{
	crypto::{AccountId32 as AccountId, Ss58Codec},
	sr25519, Encode, Pair,
};
use std::{sync::Arc, time::SystemTime};
use substrate_api_client::{
	compose_extrinsic_offline, ExtrinsicParams, PlainTipExtrinsicParams,
	PlainTipExtrinsicParamsBuilder, XtStatus,
};
#[allow(unused)]
use tee_primitives::Enclave;
use trex_primitives::{KeyPiece, ShieldedKey};
use tkp_settings::keyholder::AES_KEY_MAX_SIZE;
use utils::{
	node_metadata::NodeMetadata,
	node_rpc::{
		get_api, get_enclave_count, get_free_balance, get_genesis_hash, get_nonce,
		get_shielding_key, TREX,
	},
};
use crate::enclave::api::get_shielding_pubkey;

/// Arguments for the cli.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	#[command(subcommand)]
	action: Action,
	/// Path of config YAML file.
	#[arg(short, long, default_value_t=("config.yml".to_string()))]
	config: String,
	#[arg(short, long, default_value_t=("seed.yml".to_string()))]
	seed: String,
}

#[derive(clap::Subcommand, Debug)]
enum Action {
	Test,
	ShieldingPubKey,
	SigningPubKey,
	GetFreeBalance,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(transparent)]
struct Seed {
	#[serde(with = "hex::serde")]
	hex: Vec<u8>,
}

/// one minute in milliseconds.
const ONE_MINUTE: u64 = 60 * 1000;
const KEY_SIZE: usize = 32;
// This nonce must be 12 bytes long.
const AES_NONCE: &[u8; 12] = b"unique nonce";

fn main() {
	// Setup logging
	env_logger::init();
	// init enclave instance
	let enclave = Arc::new(enclave_init().expect("Cannot create an enclave!"));
	// parse arguments
	let args = Args::parse();
	// Load config
	let config = ApiConfig::from_yaml(&args.config);
	match args.action {
		Action::Test => {
			// obtain enclave count through rpc
			let enclave_count = get_enclave_count(&config, None).unwrap();
			if enclave_count < 1 {
				error!("Enclaves not registered on-chain");
				return
			}
			// load testing seed file.
			let f = std::fs::File::open(&args.seed).unwrap();
			let seed: Seed = serde_yaml::from_reader(f).expect("Could not read seed.");
			let signer = sr25519::Pair::from_seed_slice(seed.hex.as_slice()).unwrap();
			let pubkey = signer.public();
			let tx_sender_account_id = AccountId::from(*pubkey.as_array_ref());
			info!("Account ID: {:?}", tx_sender_account_id.to_ss58check());
			// prepare websocket connection.
			let api = get_api(&config).unwrap();
			// obtain metadata genesis_hash nonce runtime_spec_version runtime_transaction_version.
			let metadata = api.metadata.clone();
			let genesis_hash_slice = get_genesis_hash(&config);
			let genesis_hash = hash_from_slice(&genesis_hash_slice);
			let nonce = get_nonce(&tx_sender_account_id, &config).unwrap();
			let runtime_spec_version = api.runtime_version.spec_version;
			let runtime_transaction_version = api.runtime_version.transaction_version;
			let node_metadata =
				NodeMetadata::new(metadata, runtime_spec_version, runtime_transaction_version);
			// construct send trex data call
			let send_trex_data_call = node_metadata.call_indexes(TREX, "send_trex_data");

			// get ras pubkey and enclave account id, will insert into ShieldedKey.
			let (rsa_pubkey, tee_account_id) = get_shielding_key(&config).unwrap();
			// get aes key
			let mut key_slice = [0u8; KEY_SIZE];
			let nonce_slice = AES_NONCE;
			OsRng.fill_bytes(&mut key_slice);
			let cipher = Aes256Gcm::new_from_slice(&key_slice).expect("Random key slice does not match the size!");
			let aes_nonce = Nonce::from_slice(nonce_slice);
			// create cipher text
			let ciphertext = cipher.encrypt(aes_nonce, b"a test cipher text".as_ref()).unwrap();
			// encrypt private key through rsa pubkey
			let mut key_piece = [0u8; AES_KEY_MAX_SIZE];
			let (first, second) = key_piece.split_at_mut(KEY_SIZE);
			first.copy_from_slice(&key_slice);
			second.copy_from_slice(nonce_slice);
			let mut cipher_private_key: Vec<u8> = Vec::new();
			rsa_pubkey
				.encrypt_buffer(&key_piece, &mut cipher_private_key)
				.expect("Cannot shield key pieces!");
			// construct key_pieces
			let key: ShieldedKey = cipher_private_key;
			let key_piece = KeyPiece { holder: tee_account_id.clone(), shielded: key.clone() };
			let key_pieces = vec![key_piece];

			// send ext to TREX node.
			if let Ok(call) = send_trex_data_call {
				let extrinsic_params = PlainTipExtrinsicParams::new(
					runtime_spec_version,
					runtime_transaction_version,
					nonce,
					genesis_hash,
					PlainTipExtrinsicParamsBuilder::default(),
				);
				let xt = compose_extrinsic_offline!(
					signer,
					(call, ciphertext.clone(), release_time(), key_pieces.clone()),
					extrinsic_params
				);

				let xt_encoded = xt.encode();
				debug!("{:?}", xt_encoded);
				let mut xthex = hex::encode(xt_encoded);
				xthex.insert_str(0, "0x");

				info!("[>] Send the TREX data)");
				let send_xt_hash = api.send_extrinsic(xthex, XtStatus::Finalized).unwrap();
				info!("[<] Extrinsic got finalized. Hash: {:?}\n", send_xt_hash);
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
			// Get the account ID of our TEE.
			let tee_account_id = enclave_account(&enclave).unwrap();
			// Perform a remote attestation and get an unchecked extrinsic back.
			let free_balance = get_free_balance(&tee_account_id, &config).unwrap();
			println!("{:?}", free_balance);
		},
	}
}

fn release_time() -> u64 {
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
	// convert to milliseconds!
	now_time * 1000 + ONE_MINUTE
}

// TODO: consolidate with the same method in enclave-runtime.
pub fn hash_from_slice(hash_slize: &[u8]) -> sp_core::H256 {
	let mut g = [0; 32];
	g.copy_from_slice(hash_slize);
	sp_core::H256::from(&mut g)
}
