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
/// Config for cli
mod config;
/// Enclave api
mod enclave;
/// Ocall implemetation
mod ocall;
/// test
mod test;
/// Some utils for service
mod utils;

use clap::Parser;
use config::Config as ApiConfig;
use enclave::api::{enclave_account, enclave_init, get_rsa_pubkey};
use serde::{Deserialize, Serialize};
use sp_core::crypto::Ss58Codec;
use std::sync::Arc;
#[allow(unused)]
use tee_primitives::Enclave;
use utils::node_rpc::get_free_balance;

/// Arguments for the cli.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Action for Subcommand
	#[command(subcommand)]
	action: Action,
	/// Path of config YAML file.
	#[arg(short, long, default_value_t=("config.yml".to_string()))]
	config: String,
	/// Path of seed YAML file
	#[arg(short, long, default_value_t=("seed.yml".to_string()))]
	seed: String,
}

/// Enum for Subcommand
#[derive(clap::Subcommand, Debug)]
enum Action {
	/// Generate the rsa3072 pubkey for shielding
	GenerateRsa3072PubKey,
	/// Get the pubkey for signature in enclave
	SigningPubKey,
	/// Obtain the balance in the account
	GetFreeBalance,
}

/// Seed of signature keypair for testing
#[derive(Serialize, Deserialize, Debug)]
#[serde(transparent)]
struct Seed {
	#[serde(with = "hex::serde")]
	hex: Vec<u8>,
}

/// Main function executed by cli
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
		Action::GenerateRsa3072PubKey => {
			get_rsa_pubkey(&enclave);
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

// TODO: consolidate with the same method in enclave-runtime.
/// Convert slice type to hash type
pub fn hash_from_slice(hash_slize: &[u8]) -> sp_core::H256 {
	let mut g = [0; 32];
	g.copy_from_slice(hash_slize);
	sp_core::H256::from(&mut g)
}
