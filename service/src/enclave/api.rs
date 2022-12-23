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
use crate::enclave::{error::Error, ffi};
use frame_support::ensure;
use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use sp_core::{crypto::AccountId32, ed25519};
/// keep this api free from chain-specific types!
use std::io::{Read, Write};
use std::{fs::File, path::PathBuf};
use std::sync::Arc;
use tkp_settings::{
	files::{ENCLAVE_FILE, ENCLAVE_TOKEN},
	keyholder::{KEY_EXT_MAX_SIZE, AES_KEY_MAX_SIZE, RA_EXT_MAX_SIZE},
};
use async_std::io::Result as IoResult;

/// init enclave
pub fn enclave_init() -> SgxResult<SgxEnclave> {
	const LEN: usize = 1024;
	let mut launch_token = [0; LEN];
	let mut launch_token_updated = 0;

	// Step 1: try to retrieve the launch token saved by last transaction
	//         if there is no token, then create a new one.
	//
	// try to get the token saved in $HOME */
	let mut home_dir = PathBuf::new();
	let use_token = match dirs::home_dir() {
		Some(path) => {
			info!("[+] Home dir is {}", path.display());
			home_dir = path;
			true
		},
		None => {
			error!("[-] Cannot get home dir");
			false
		},
	};
	let token_file = home_dir.join(ENCLAVE_TOKEN);
	if use_token {
		match File::open(&token_file) {
			Err(_) => {
				info!(
					"[-] Token file {} not found! Will create one.",
					token_file.as_path().to_str().unwrap()
				);
			},
			Ok(mut f) => {
				info!("[+] Open token file success! ");
				match f.read(&mut launch_token) {
					Ok(LEN) => {
						info!("[+] Token file valid!");
					},
					_ => info!("[+] Token file invalid, will create new token file"),
				}
			},
		}
	}

	// Step 2: call sgx_create_enclave to initialize an enclave instance
	// Debug Support: 1 = debug mode, 0 = not debug mode
	#[cfg(not(feature = "production"))]
	let debug = 1;
	#[cfg(feature = "production")]
	let debug = 0;

	let mut misc_attr =
		sgx_misc_attribute_t { secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 }, misc_select: 0 };
	let enclave = SgxEnclave::create(
		ENCLAVE_FILE,
		debug,
		&mut launch_token,
		&mut launch_token_updated,
		&mut misc_attr,
	);

	// Step 3: save the launch token if it is updated
	if use_token && launch_token_updated != 0 {
		// reopen the file with write capability
		match File::create(&token_file) {
			Ok(mut f) => match f.write_all(&launch_token) {
				Ok(()) => info!("[+] Saved updated launch token!"),
				Err(_) => error!("[-] Failed to save updated launch token!"),
			},
			Err(_) => {
				warn!("[-] Failed to save updated enclave token, but doesn't matter");
			},
		}
	}
	enclave
}

/// Get the remote attestation in the enclave and organize it into ext in the corresponding format of pallet-tee
#[allow(unused)]
pub fn perform_ra(
	enclave: &SgxEnclave,
	genesis_hash: Vec<u8>,
	nonce: u32,
	w_url: Vec<u8>,
) -> Result<Vec<u8>, Error> {
	let mut retval = sgx_status_t::SGX_SUCCESS;

	let unchecked_extrinsic_size = RA_EXT_MAX_SIZE;
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

/// get shielding pubkey from enclave
#[allow(unused)]
pub fn get_shielding_pubkey(enclave: &SgxEnclave) -> Rsa3072PubKey {
	let mut pubkey = [0u8; SGX_RSA3072_KEY_SIZE + SGX_RSA3072_PUB_EXP_SIZE];
	let mut retval = sgx_status_t::SGX_SUCCESS;
	unsafe {
		ffi::get_rsa_encryption_pubkey(
			enclave.geteid(),
			&mut retval,
			pubkey.as_mut_ptr(),
			pubkey.len() as u32,
		);
	};
	let rsa_pubkey: Rsa3072PubKey = unsafe { std::mem::transmute(pubkey) };
	debug!("Enclave's RSA pubkey:\n{:?}", rsa_pubkey);
	rsa_pubkey
}

/// Put node metadata into enclave memory for temporary storage
#[allow(unused)]
pub fn set_node_metadata(enclave: &SgxEnclave, metadata: Vec<u8>) {
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
#[allow(unused)]
pub fn set_nonce(enclave: &SgxEnclave, nonce: &u32) {
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

/// Get the public signing key of the TEE.
#[allow(unused)]
pub fn enclave_account(enclave: &SgxEnclave) -> Result<AccountId32, Error> {
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

/// Get the remaining heap locations
#[allow(unused)]
pub fn get_heap_free_count(
	enclave: Arc<SgxEnclave>
) -> Result<usize, Error>{
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let mut heap_free_count:usize = 0;
	let result = unsafe {
		ffi::get_heap_free_count(
			enclave.geteid(),
			&mut retval,
			&mut heap_free_count
		)
	};
	match result {
		sgx_status_t::SGX_SUCCESS => {
			println!("ECALL Get Heap Free Count Success!");
		},
		_ => {
			println!("[-] ECALL Get Heap Free Count Enclave Failed {}!", result.as_str());
		},
	}
	Ok(heap_free_count)
}

/// clear heap for uni-test using.
#[allow(unused)]
pub fn clear_heap(
	enclave: &SgxEnclave
) -> Result<(), Error>{
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		ffi::clear_heap(
			enclave.geteid(),
			&mut retval
		)
	};
	ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
	ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));
	Ok(())
}

/// Insert private key piece according to the release time
#[allow(unused)]
pub fn insert_key_piece(
	enclave: &SgxEnclave,
	key: Vec<u8>,
	release_time: u64,
	current_block: u32,
	ext_index: u32,
) -> Result<(), Error> {
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		ffi::insert_key_piece(
			enclave.geteid(),
			&mut retval,
			key.as_ptr(),
			key.len() as u32,
			release_time,
			current_block,
			ext_index,
		)
	};
	ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
	ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));
	Ok(())
}

/// Get the private key that needs to be released at the time
/// check if the key piece is expired and extract it from the enclave if so.
#[allow(unused)]
pub fn get_expired_key(enclave: Arc<SgxEnclave>) -> Option<(Vec<u8>, u32, u32)> {
	let mut key: Vec<u8> = vec![0u8; AES_KEY_MAX_SIZE];
	let mut from_block: u32 = 0;
	let mut ext_index: u32 = 0;
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let res = unsafe {
		ffi::get_expired_key(
			enclave.geteid(),
			&mut retval,
			key.as_mut_ptr(),
			AES_KEY_MAX_SIZE as u32,
			&mut from_block,
			&mut ext_index,
		)
	};
	match res {
		sgx_status_t::SGX_SUCCESS => {
			debug!("ECALL Get Key Success!");
		},
		_ => {
			debug!("[-] ECALL Get Key Enclave Failed {}!", res.as_str());
		},
	}
	if from_block > 0 {
		Some((key, from_block, ext_index))
	} else {
		None
	}
}

/// The expired key to be released will be constructed as uxt on the chain
/// generate remote attestation report and construct an unchecked extrinsic which will send by pallet-teerex
#[allow(unused)]
pub fn perform_expire_key(
	enclave: &Arc<SgxEnclave>,
	genesis_hash: Vec<u8>,
	nonce: u32,
	expired_key: Vec<u8>,
	block_number: u32,
	ext_index: u32,
) -> Result<Vec<u8>, Error> {
	let mut retval = sgx_status_t::SGX_SUCCESS;

	let unchecked_extrinsic_size = KEY_EXT_MAX_SIZE;
	let mut unchecked_extrinsic: Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];

	let result = unsafe {
		ffi::perform_expire_key(
			enclave.geteid(),
			&mut retval,
			genesis_hash.as_ptr(),
			genesis_hash.len() as u32,
			&nonce,
			expired_key.as_ptr(),
			expired_key.len() as u32,
			&block_number,
			&ext_index,
			unchecked_extrinsic.as_mut_ptr(),
			unchecked_extrinsic.len() as u32,
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {
			println!("ECALL Perform Expired Key Success!");
		},
		_ => {
			println!("[-] ECALL Perform Expired Key Enclave Failed {}!", result.as_str());
		},
	}

	Ok(unchecked_extrinsic)
}

#[allow(unused)]
pub async fn perform_nts_time(
	enclave: &SgxEnclave
) -> IoResult<()> {
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		ffi::obtain_nts_time(
			enclave.geteid(),
			&mut retval
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {
			println!("ECALL Nts Time Success!");
		},
		_ => {
			println!("[-] ECALL Nts Time Enclave Failed {}!", result.as_str());
		},
	}
	Ok(())
}
