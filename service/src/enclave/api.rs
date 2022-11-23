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
use tkp_settings::{
	files::{ENCLAVE_FILE, ENCLAVE_TOKEN},
	worker::EXTRINSIC_MAX_SIZE,
};

/// 256bit key plus 96bit nonce
pub const MAX_KEY_SIZE: usize = 32+12;

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
pub fn perform_ra(
	enclave: &SgxEnclave,
	genesis_hash: Vec<u8>,
	nonce: u32,
	w_url: Vec<u8>,
) -> Result<Vec<u8>, Error> {
	let mut retval = sgx_status_t::SGX_SUCCESS;

	let unchecked_extrinsic_size = EXTRINSIC_MAX_SIZE;
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

/// Insert private key piece according to the release time
pub fn insert_key_piece(
	enclave: &SgxEnclave,
	key: Vec<u8>,
	release_time: u64,
	current_block: u32,
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
		)
	};
	ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
	ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));
	Ok(())
}

pub fn get_expired_key(enclave: &SgxEnclave) -> Option<Vec<u8>> {
	let mut key: Vec<u8> = vec![0u8; MAX_KEY_SIZE];
	let mut from_block: u32 = 0;
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let res = unsafe {
		ffi::get_expired_key(
			enclave.geteid(),
			&mut retval,
			key.as_mut_ptr(),
			MAX_KEY_SIZE as u32,
			&mut from_block,
		)
	};
	if retval != sgx_status_t::SGX_SUCCESS || res != sgx_status_t::SGX_SUCCESS {
		info!("[-] ECALL Get Key Failed {}!", res.as_str());
		return None
	}
	if from_block > 0 {
		Some(key)
	} else {
		None
	}
}
