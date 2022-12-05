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

//! Common settings for the worker and the enclave. It is strictly `no_std`

#![no_std]

/// File Settings concerning the keyholder
pub mod files {
	// used by worker
	pub static ENCLAVE_TOKEN: &str = "enclave.token";
	pub static ENCLAVE_FILE: &str = "enclave.signed.so";
	pub static SHIELDING_KEY_FILE: &str = "enclave-shielding-pubkey.json";
	pub static SIGNING_KEY_FILE: &str = "enclave-signing-pubkey.bin";

	// used by enclave
	pub const RSA3072_SEALED_KEY_FILE: &str = "rsa3072_key_sealed.bin";
	pub const SEALED_SIGNER_SEED_FILE: &str = "ed25519_key_sealed.bin";
	pub const AES_KEY_FILE_AND_INIT_V: &str = "aes_key_sealed.bin";

	pub const RA_DUMP_CERT_DER_FILE: &str = "ra_dump_cert.der";

	pub const ENCLAVE_CERTIFICATE_FILE_PATH: &str = "cert.pem";
	pub const ENCLAVE_CERTIFICATE_PRIVATE_KEY_PATH: &str = "private_key.pem";

	#[cfg(feature = "production")]
	pub static RA_SPID_FILE: &str = "spid_production.txt";
	#[cfg(feature = "production")]
	pub static RA_API_KEY_FILE: &str = "key_production.txt";

	#[cfg(not(feature = "production"))]
	pub static RA_SPID_FILE: &str = "spid.txt";
	#[cfg(not(feature = "production"))]
	pub static RA_API_KEY_FILE: &str = "key.txt";

	pub const SPID_MIN_LENGTH: usize = 32;

	pub const KEYFILE: &'static str = "prov_key.bin";
	pub const MINHEAPFILE: &'static str = "minheap.bin";
	pub const CERTEXPIRYDAYS: i64 = 90i64;
}

/// Settings concerning the keyholder
pub mod keyholder {
	/// the maximum size of RA extrinsic that the enclave will ever generate.
	pub const RA_EXT_MAX_SIZE: usize = 4196;
	/// the max size of expired key ext that the enclave generates.
	pub const KEY_EXT_MAX_SIZE: usize = 256;
	/// 256bit AES key plus 96bit nonce
	pub const AES_KEY_MAX_SIZE: usize = 32 + 12;
	/// the maximum size of the header
	pub const HEADER_MAX_SIZE: usize = 200;
	/// maximum size of shielding key
	/// (this size is significantly inflated by using JSON serialization)
	pub const SHIELDING_KEY_SIZE: usize = 8192;
	/// maximum size of signing key
	pub const SIGNING_KEY_SIZE: usize = 32;
	/// size of the MR enclave
	pub const MR_ENCLAVE_SIZE: usize = 32;
	/// Factors to tune the initial amount of enclave funding:
	/// Should be set to a value that ensures that the enclave can register itself
	/// and the worker can run for a certain time. Only for development.
	pub const EXISTENTIAL_DEPOSIT_FACTOR_FOR_INIT_FUNDS: u128 = 200_000;
	/// Should be set to a value that ensures that the enclave can register itself
	/// and that the worker can start.
	pub const REGISTERING_FEE_FACTOR_FOR_INIT_FUNDS: u128 = 10;
	// max size of min heap
	pub const MIN_HEAP_MAX_SIZE:usize = 8000;
}
