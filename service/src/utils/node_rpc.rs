use crate::config::Config;
use sp_core::{crypto::AccountId32, sr25519};
use substrate_api_client::{rpc::WsRpcClient, Api, ApiClientError, AssetTipExtrinsicParams};

pub type RpcApi<C> = Api<sr25519::Pair, C, AssetTipExtrinsicParams>;

pub fn get_api(config: &Config) -> Result<RpcApi<WsRpcClient>, ApiClientError> {
	let url = config.node_url();
	let client = WsRpcClient::new(&url);
	Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client)
}

/// Obtain the nonce of the enclave account through rpc
pub fn get_nonce(who: &AccountId32, config: &Config) -> Result<u32, ApiClientError> {
	let api = get_api(config).unwrap();
	Ok(api.get_account_info(who)?.map_or_else(|| 0, |info| info.nonce))
}

/// Obtain the free balance of the enclave account through rpc
#[allow(dead_code)]
pub fn get_free_balance(who: &AccountId32, config: &Config) -> Result<u128, ApiClientError> {
	let api = get_api(config).unwrap();
	// Ok(api.get_account_info(who)?.map_or_else(|| 0, |info| info.nonce))
	Ok(api.get_account_data(who)?.map_or_else(|| 0, |data| data.free))
}

/// Obtain the genesis hash through rpc
pub fn get_genesis_hash(config: &Config) -> Vec<u8> {
	let api = get_api(config).unwrap();
	let genesis_hash = Some(api.get_genesis_hash().expect("Failed to get genesis hash"));
	genesis_hash.unwrap().as_bytes().to_vec()
}
