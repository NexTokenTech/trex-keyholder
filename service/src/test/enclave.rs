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
use crate::enclave::{
	api::{enclave_init, get_shielding_pubkey},
	ffi,
};
use aes_gcm::{
	aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
	Aes256Gcm, Nonce,
};
use log::info;
use sgx_types::sgx_status_t;
use sgx_urts::SgxEnclave;
use trex_primitives::ShieldedKey;
use crate::utils::node_rpc::get_shielding_key;
use super::primitive::consts::{TEST_CIPHER,TEST_KEY_PIECE};

#[test]
fn shielding_key_decryption() {
	let enclave = match enclave_init() {
		Ok(r) => {
			info!("[+] Init Enclave Successful {}!", r.geteid());
			r
		},
		Err(x) => {
			info!("[-] Init Enclave Failed {}!", x.as_str());
			return
		},
	};
	println!("shielding pub key");
	let rsa_pubkey = get_shielding_pubkey(&enclave);
	let plaintext: Vec<u8> = "test encrypt text and decrypt cipher".to_string().into_bytes();
	let mut ciphertext: Vec<u8> = Vec::new();
	rsa_pubkey.encrypt_buffer(&plaintext, &mut ciphertext).expect("Encrypt Error");

	let mut retval = sgx_status_t::SGX_SUCCESS;
	let mut res: u8 = 1;
	unsafe {
		ffi::test_decrypt(
			enclave.geteid(),
			&mut retval,
			plaintext.as_ptr(),
			plaintext.len() as u32,
			ciphertext.as_ptr(),
			ciphertext.len() as u32,
			&mut res,
		);
	};
	assert_eq!(res, 0, "Decrypted message does not match original!");
	assert_eq!(retval, sgx_status_t::SGX_SUCCESS, "SGX ECall is not successful!")
}

#[test]
fn aes_key_generate_decryption_works() {
	// get aes key
	let mut key_slice = [0u8; KEY_SIZE];
	let nonce_slice = AES_NONCE;
	OsRng.fill_bytes(&mut key_slice);
	let cipher =
		Aes256Gcm::new_from_slice(&key_slice).expect("Random key slice does not match the size!");
	let aes_nonce = Nonce::from_slice(nonce_slice);
	// create cipher text
	let ciphertext = cipher.encrypt(aes_nonce, b"a test cipher text".as_ref()).unwrap();
	let decrypted_msg_slice = cipher.decrypt(aes_nonce,ciphertext.as_ref()).unwrap();
	let decrypted_msg = String::from_utf8(decrypted_msg_slice.to_vec()).unwrap_or("".to_string());
	assert_eq!(decrypted_msg, "a test cipher text", "Cipher text does not match original!");
}

#[test]
fn aes_key_derive_decryption_works(){
	let mut key_piece = TEST_KEY_PIECE;
	let (key_slice, nonce_slice) = key_piece.split_at_mut(KEY_SIZE);
	let ciphertext = TEST_CIPHER;
	let cipher = Aes256Gcm::new_from_slice(&key_slice)
		.expect("Random key slice does not match the size!");
	let aes_nonce = Nonce::from_slice(nonce_slice);
	let decrypted_msg_slice = cipher.decrypt(aes_nonce,ciphertext.as_ref()).unwrap();
	let decrypted_msg = String::from_utf8(decrypted_msg_slice.to_vec()).unwrap_or("".to_string());
	assert_eq!(decrypted_msg,"a test cipher text","Decrypted message does not match original!");
}

#[test]
fn aes_key_release_time_hash_works(){
	let enclave = match enclave_init() {
		Ok(r) => {
			info!("[+] Init Enclave Successful {}!", r.geteid());
			r
		},
		Err(x) => {
			info!("[-] Init Enclave Failed {}!", x.as_str());
			return
		},
	};
	// get ras pubkey and enclave account id, will insert into ShieldedKey.
	let (rsa_pubkey, tee_account_id) = get_shielding_key(&config).unwrap();
	let mut key_piece = TEST_KEY_PIECE;
	// generate hash of Sha256PrivateKeyTime which contains key_piece and release_time
	let release_time = release_time();
	let key_time = Sha256PrivateKeyTime {
		aes_private_key: key_piece.clone().to_vec(),
		timestamp: release_time.clone(),
	};
	let key_time_hash = key_time.hash();
	// construct key hash struct for shielding
	let key_hash =
		Sha256PrivateKeyHash { aes_private_key: key_piece.clone().to_vec(), hash: key_time_hash };
	let key_hash_encode = key_hash.encode();
	// shielding key hash struct
	let mut cipher_private_key: Vec<u8> = Vec::new();
	rsa_pubkey
		.encrypt_buffer(&key_hash_encode, &mut cipher_private_key)
		.expect("Cannot shield key pieces!");
	// construct key_pieces
	let key: ShieldedKey = cipher_private_key;
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let mut res: u8 = 1;
	unsafe {
		ffi::test_key_piece(
			enclave.geteid(),
			&mut retval,
			key.as_ptr(),
			key.len() as u32,
			release_time,
			&mut res,
		);
	};
	assert_eq!(res, 1, "Decrypted key time hash does not match original!");
	assert_eq!(retval, sgx_status_t::SGX_SUCCESS, "SGX ECall is not successful!")
}
