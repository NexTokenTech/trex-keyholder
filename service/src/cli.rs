mod config;
mod utils;

use serde::{Deserialize, Serialize};
use config::Config as ApiConfig;
use log::{info, debug};
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	sr25519, Encode, Pair,
};
use substrate_api_client::{
	compose_extrinsic_offline, ExtrinsicParams, PlainTipExtrinsicParams,
	PlainTipExtrinsicParamsBuilder, XtStatus,
};
use trex_primitives::{KeyPiece, ShieldedKey};
use utils::{
	node_metadata::NodeMetadata,
	node_rpc::{get_api, get_genesis_hash, get_nonce},
};
use clap::Parser;

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


fn main() {
    // Setup logging
    env_logger::init();
	let args = Args::parse();
    // Load config
	let config = ApiConfig::from_yaml(&args.config);
	let f = std::fs::File::open(&args.seed).unwrap();
	let seed: Seed = serde_yaml::from_reader(f).expect("Could not read seed.");
	let signer = sr25519::Pair::from_seed_slice(seed.hex.as_slice()).unwrap();
	let pubkey = signer.public();
	let tee_account_id = AccountId32::from(*pubkey.as_array_ref());
	println!("Account ID: {:?}", tee_account_id.to_ss58check());
	// prepare websocket connection.
	let api = get_api(&config).unwrap();
	let metadata = api.metadata.clone();
	let genesis_hash_slice = get_genesis_hash(&config);
	let genesis_hash = hash_from_slice(&genesis_hash_slice);
	let nonce = get_nonce(&tee_account_id, &config).unwrap();
	let runtime_spec_version = api.runtime_version.spec_version;
	let runtime_transaction_version = api.runtime_version.transaction_version;
	let node_metadata =
		NodeMetadata::new(metadata, runtime_spec_version, runtime_transaction_version);
	let send_trex_data_call = node_metadata.call_indexes("Trex", "send_trex_data");

	let key: ShieldedKey = vec![1u8; 32];
	let key_piece = KeyPiece { holder: tee_account_id.clone(), shielded: key.clone() };
	let key_pieces = vec![key_piece; 8];

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
			(call, "cipher".as_bytes(), 1668760701 as u64, key_pieces.clone()),
			extrinsic_params
		);

		let xt_encoded = xt.encode();
		debug!("{:?}", xt_encoded);
		let mut xthex = hex::encode(xt_encoded);
		xthex.insert_str(0, "0x");

		info!("[>] Send the TREX data)");
		let register_enclave_xt_hash = api.send_extrinsic(xthex, XtStatus::Finalized).unwrap();
		info!("[<] Extrinsic got finalized. Hash: {:?}\n", register_enclave_xt_hash);
	}
}

// TODO: consolidate with the same method in enclave-runtime.
pub fn hash_from_slice(hash_slize: &[u8]) -> sp_core::H256 {
	let mut g = [0; 32];
	g.copy_from_slice(hash_slize);
	sp_core::H256::from(&mut g)
}
