///! FFI's that call into the enclave. These functions need to be added to the
/// enclave edl file and be implemented within the enclave.
use sgx_types::{sgx_enclave_id_t, sgx_status_t};

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
	#[allow(unused)]

	/// handle sealed keys on chain, and decrypt them by time
	pub fn handle_private_keys(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		key: *const u8,
		key_len: u32,
		timestamp: u32,
		enclave_index: u32,
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
	) -> sgx_status_t;

	/// store nonce in enclave memory
	pub fn set_nonce(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		nonce: *const u32,
	) -> sgx_status_t;

	/// store node metadata in enclave memory
	pub fn set_node_metadata(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		node_metadata: *const u8,
		node_metadata_size: u32,
	) -> sgx_status_t;
}
