mod config;
mod utils;

use clap::Parser;
use config::Config as ApiConfig;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
#[allow(unused)]
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sp_core::{
	crypto::{AccountId32 as AccountId, Ss58Codec},
	sr25519, Encode, Pair,
};
use std::time::SystemTime;
use substrate_api_client::{
	compose_extrinsic_offline, ExtrinsicParams, PlainTipExtrinsicParams,
	PlainTipExtrinsicParamsBuilder, XtStatus,
};
#[allow(unused)]
use tee_primitives::Enclave;
use trex_primitives::{KeyPiece, ShieldedKey};
use utils::{
	node_metadata::NodeMetadata,
	node_rpc::{get_api, get_enclave_count, get_genesis_hash, get_nonce, get_shielding_key, TREX},
};

/// Arguments for the cli.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
	/// Path of config YAML file.
	#[arg(short, long, default_value_t=("config.yml".to_string()))]
	config: String,
	#[arg(short, long, default_value_t=("seed.yml".to_string()))]
	seed: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(transparent)]
struct Seed {
	#[serde(with = "hex::serde")]
	hex: Vec<u8>,
}

pub const ONE_HOUR: u64 = 3600;

fn main() {
	// Setup logging
	env_logger::init();
	let args = Args::parse();
	// Load config
	let config = ApiConfig::from_yaml(&args.config);

	// obtain enclave count through rpc
	let enclave_count = get_enclave_count(&config, None).unwrap();
	if enclave_count < 1 {
		error!("Enclaves not registered on-chain");
		return
	}

	let f = std::fs::File::open(&args.seed).unwrap();
	let seed: Seed = serde_yaml::from_reader(f).expect("Could not read seed.");
	let signer = sr25519::Pair::from_seed_slice(seed.hex.as_slice()).unwrap();
	let pubkey = signer.public();
	let tx_sender_account_id = AccountId::from(*pubkey.as_array_ref());
	println!("Account ID: {:?}", tx_sender_account_id.to_ss58check());
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

	// TODO: generate keypair to encrypt plaintext,replace private_key with the real keypair's private key.
	// get ras pubkey and enclave account id, will insert into ShieldedKey.
	let (rsa_pubkey, tee_account_id) = get_shielding_key(&config).unwrap();
	// encrypt private key through rsa pubkey
	let private_key: Vec<u8> = "this is a private key".to_string().into_bytes();
	let mut cipher_private_key: Vec<u8> = Vec::new();
	rsa_pubkey
		.encrypt_buffer(&private_key, &mut cipher_private_key)
		.expect("Encrypt Error");

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
			(call, "a test cipher".as_bytes(), release_time(), key_pieces.clone()),
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
	now_time + ONE_HOUR
}

// TODO: consolidate with the same method in enclave-runtime.
pub fn hash_from_slice(hash_slize: &[u8]) -> sp_core::H256 {
	let mut g = [0; 32];
	g.copy_from_slice(hash_slize);
	sp_core::H256::from(&mut g)
}
