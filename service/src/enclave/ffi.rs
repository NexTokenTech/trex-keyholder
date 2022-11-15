///! FFI's that call into the enclave. These functions need to be added to the
/// enclave edl file and be implemented within the enclave.
use sgx_types::{sgx_enclave_id_t, sgx_quote_sign_type_t, sgx_status_t};

extern "C" {
	#[allow(unused)]
	pub fn get_rsa_encryption_pubkey(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		pubkey: *mut u8,
		pubkey_size: u32,
	) -> sgx_status_t;
	#[allow(unused)]
	pub fn get_ecc_signing_pubkey(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		pubkey: *mut u8,
		pubkey_size: u32,
	) -> sgx_status_t;
	#[allow(unused)]
	pub fn handle_private_keys(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		key: *const u8,
		key_len: u32,
		timestamp: u32,
		enclave_index: u32,
	) -> sgx_status_t;
	#[allow(unused)]
	pub fn perform_ra(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		sign_type: sgx_quote_sign_type_t,
	) -> sgx_status_t;
}
