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
use codec::Encode;
use crate::config::Config;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use sp_core::{
	crypto::{AccountId32, AccountId32 as AccountId},
	sr25519, H256,
};
use substrate_api_client::{
	rpc::WsRpcClient, Api, ApiClientError, ApiResult, AssetTipExtrinsicParams, Balance,
	GenericAddress, XtStatus,
};
use tee_primitives::Enclave;
use sp_keyring::AccountKeyring;
pub const EXISTENTIAL_DEPOSIT_FACTOR_FOR_INIT_FUNDS: u128 = 200_000;

/// Const str "Tee"
#[allow(unused)]
pub const TEE: &str = "Tee";
/// Const tr "Trex"
#[allow(unused)]
pub const TREX: &str = "Trex";
/// First enclave index,default: 1.
#[allow(unused)]
pub const FIRST_ENCLAVE_INDEX: u64 = 1;

/// Node Rpc Api alias
pub type RpcApi<C> = Api<sr25519::Pair, C, AssetTipExtrinsicParams>;

/// Get the node rpc api instance
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
#[allow(unused)]
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

/// Obtain the enclave count through rpc
#[allow(unused)]
pub fn get_enclave_count(config: &Config, at_block: Option<H256>) -> ApiResult<u64> {
	let api = get_api(config).unwrap();
	Ok(api.get_storage_value(TEE, "EnclaveCount", at_block)?.unwrap_or(0u64))
}

pub fn transfer_from_alice(config: &Config, accountid: &AccountId32) {
	println!("[+] bootstrap funding Enclave from Alice's funds");
	let alice = AccountKeyring::Alice.pair();
	let mut api = get_api(config).unwrap();
	api.signer = Some(alice);
	let xt =
		api.balance_transfer(GenericAddress::Id(accountid.clone()), EXISTENTIAL_DEPOSIT_FACTOR_FOR_INIT_FUNDS);
	let mut xthex = hex::encode(xt.encode());
	xthex.insert_str(0, "0x");
	let xt_hash = api.send_extrinsic(xthex, XtStatus::InBlock);
	println!("[<] Extrinsic got included in a block. Hash: {:?}\n", xt_hash);
}

/// Obtain the enclave through rpc
#[allow(unused)]
fn enclave(
	config: &Config,
	index: u64,
	at_block: Option<H256>,
) -> ApiResult<Option<Enclave<AccountId, Vec<u8>, Vec<u8>>>> {
	let api = get_api(config).unwrap();
	api.get_storage_map(TEE, "EnclaveRegistry", index, at_block)
}

/// Obtain the shielding key through enclave
#[allow(unused)]
pub fn get_shielding_key(config: &Config) -> ApiResult<(Rsa3072PubKey, AccountId)> {
	// fetch first registered enclave by rpc
	let first_enclave = enclave(&config, FIRST_ENCLAVE_INDEX, None).unwrap().unwrap();
	let account = first_enclave.pubkey;
	// transmute shielding_key to rsa_pubkey
	let pubkey: [u8; SGX_RSA3072_KEY_SIZE + SGX_RSA3072_PUB_EXP_SIZE] =
		first_enclave.shielding_key.clone().try_into().unwrap();
	let rsa_pubkey: Rsa3072PubKey = unsafe { std::mem::transmute(pubkey) };
	Ok((rsa_pubkey, account))
}
