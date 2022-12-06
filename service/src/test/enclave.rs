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
use crate::{
	enclave::{
		api::{enclave_init, get_shielding_pubkey},
		ffi,
	},
	test::primitive::consts::{
		TEST_CIPHER, TEST_CONFIG_PATH, TEST_KEY_PIECE, TEST_KEY_SLICE, TEST_NONCE_SLICE,ONE_DAY
	},
	utils::node_rpc::get_shielding_key,
	utils::key_piece::TmpKeyPiece
};
use aes_gcm::{
	aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
	Aes256Gcm, Nonce,
};
use log::info;
use sgx_types::sgx_status_t;
use sgx_urts::SgxEnclave;
use tkp_settings::keyholder::{AES_KEY_MAX_SIZE,MIN_HEAP_MAX_SIZE};
use trex_primitives::ShieldedKey;
use crate::enclave::api::{clear_heap, get_heap_free_count, insert_key_piece};
use std::cmp::{min, Ordering, Reverse};
use std::collections::binary_heap::BinaryHeap;

const HEAP_CLEAN_INTERVAL: u32 = 12;

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
	let decrypted_msg_slice = cipher.decrypt(aes_nonce, ciphertext.as_ref()).unwrap();
	let decrypted_msg = String::from_utf8(decrypted_msg_slice.to_vec()).unwrap_or("".to_string());
	assert_eq!(decrypted_msg, "a test cipher text", "Cipher text does not match original!");
}

#[test]
fn aes_key_derive_works() {
	let mut key_piece = TEST_KEY_PIECE.to_vec();
	let (key_slice, nonce_slice) = key_piece.split_at_mut(KEY_SIZE);
	assert_eq!(key_slice, TEST_KEY_SLICE, "key slice does not match original!");
	assert_eq!(nonce_slice, TEST_NONCE_SLICE, "nonce slice does not match original!");
}

#[test]
fn aes_key_release_time_hash_works() {
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
	let config = ApiConfig::from_yaml(TEST_CONFIG_PATH);
	let release_time = release_time();
	let key = generate_shielding_key(&config,release_time.clone());
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

#[test]
pub fn enclave_heap_over_head_works(){
	let mut counter = 0;
	let config = ApiConfig::from_yaml(TEST_CONFIG_PATH);
	let mut key_piece_cache:BinaryHeap<Reverse<TmpKeyPiece>> = BinaryHeap::new();
	loop {
		let release_time = release_time() + ONE_DAY;
		let key = generate_shielding_key(&config,release_time);
		let current_block = 1u32;
		let ext_index = 1u32;
		let key_piece = TmpKeyPiece{
			release_time,
			from_block:current_block,
			key_piece:key,
			ext_index
		};
		key_piece_cache.push(Reverse(key_piece));
		// Get the remaining heap locations
		let heap_free_count = get_heap_free_count(&enclave).unwrap_or(0);
		println!("~~~~~~~~~~~~~~~~~~~~~left:{:?}",heap_free_count);
		if heap_free_count > 0 && key_piece_cache.len() > 0{
			let insert_count = min(key_piece_cache.len(),heap_free_count);
			for i in 0..insert_count {
				if let Some(Reverse(item)) = key_piece_cache.peek() {
					insert_key_piece(
						&enclave.clone(),
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
		println!("key_piece_cache length{:?}",key_piece_cache.len());
		counter += 1;
		if counter % HEAP_CLEAN_INTERVAL == 0 {
			clear_heap(&enclave.clone()).expect("clear heap error");
		}
		if counter == MIN_HEAP_MAX_SIZE {
			return;
		}
	}
}

fn generate_shielding_key(config: &ApiConfig, release_time: u64) -> ShieldedKey {
	// get ras pubkey and enclave account id, will insert into ShieldedKey.
	let (rsa_pubkey, tee_account_id) = get_shielding_key(&config).unwrap();
	let mut key_piece = TEST_KEY_PIECE.to_vec();
	// generate hash of Sha256PrivateKeyTime which contains key_piece and release_time
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
	key
}
