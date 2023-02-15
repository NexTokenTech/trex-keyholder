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
///! FFI's that call into the enclave. These functions need to be added to the
/// enclave edl file and be implemented within the enclave.
use sgx_types::{sgx_enclave_id_t, sgx_status_t,c_int};

extern "C" {
	/// get rsa shielding pubkey from enclave
	#[allow(unused)]
	pub fn get_rsa_encryption_pubkey(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		pubkey: *mut u8,
		pubkey_size: u32,
	) -> sgx_status_t;

	/// get pubkey of sp_core key pair from enclave
	#[allow(unused)]
	pub fn get_ecc_signing_pubkey(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		pubkey: *mut u8,
		pubkey_size: u32,
	) -> sgx_status_t;

	/// handle sealed keys on chain, and insert it to the queue
	#[allow(unused)]
	pub fn insert_key_piece(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		key: *const u8,
		key_len: u32,
		release_time: u64,
		current_block: u32,
		ext_index: u32,
	) -> sgx_status_t;

	/// check if the key piece is expired and extract it from the enclave if so.
	#[allow(unused)]
	pub fn get_expired_key(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		key: *mut u8,
		key_len: u32,
		from_block: *mut u32,
		ext_index: *mut u32,
	) -> sgx_status_t;

	/// generate remote attestation report and construct an unchecked extrinsic which will send by pallet-teerex
	#[allow(unused)]
	pub fn perform_ra(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		genesis_hash: *const u8,
		genesis_hash_size: u32,
		nonce: *const u32,
		w_url: *const u8,
		w_url_size: u32,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32,
		skip_ra: c_int,
	) -> sgx_status_t;

	/// store nonce in enclave memory
	#[allow(unused)]
	pub fn set_nonce(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		nonce: *const u32,
	) -> sgx_status_t;

	/// store node metadata in enclave memory
	#[allow(unused)]
	pub fn set_node_metadata(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		node_metadata: *const u8,
		node_metadata_size: u32,
	) -> sgx_status_t;

	/// Construct ext for expired key
	#[allow(unused)]
	pub fn perform_expire_key(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		genesis_hash: *const u8,
		genesis_hash_size: u32,
		nonce: *const u32,
		expired_key: *const u8,
		expired_key_size: u32,
		block_number: *const u32,
		ext_index: *const u32,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32,
	) -> sgx_status_t;

	/// test decrypt cipher
	#[allow(unused)]
	pub fn test_decrypt(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		plain: *const u8,
		plain_len: u32,
		cipher: *const u8,
		cipher_len: u32,
		res: *mut u8,
	) -> sgx_status_t;

	/// test key piece timestamp
	#[allow(unused)]
	pub fn test_key_piece(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		key: *const u8,
		key_len: u32,
		release_time: u64,
		res: *mut u8,
	) -> sgx_status_t;

	/// Get the remaining heap locations
	#[allow(unused)]
	pub fn get_heap_free_count(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		heap_free_count: *mut usize,
	) -> sgx_status_t;

	/// Clear heap for uni-test using
	pub fn clear_heap(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t
	) -> sgx_status_t;

	pub fn obtain_nts_time(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
	) -> sgx_status_t;
}
