// Copyright 2021 Integritee AG and Supercomputing Systems AG
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{
	error::{Error, Result},
	traits::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt},
};
use sgx_crypto_helper::{
	rsa3072::{Rsa3072KeyPair, Rsa3072PubKey},
	RsaKeyPair,
};
use std::vec::Vec;

// Reexport sgx module
#[cfg(feature = "sgx")]
pub use sgx::*;

impl ShieldingCryptoEncrypt for Rsa3072KeyPair {
	type Error = Error;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut cipher_buffer = Vec::new();
		self.encrypt_buffer(data, &mut cipher_buffer)
			.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(cipher_buffer)
	}
}

impl ShieldingCryptoDecrypt for Rsa3072KeyPair {
	type Error = Error;

	fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut decrypted_buffer = Vec::new();
		self.decrypt_buffer(data, &mut decrypted_buffer)
			.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(decrypted_buffer)
	}
}

impl ShieldingCryptoEncrypt for Rsa3072PubKey {
	type Error = Error;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut cipher_buffer = Vec::new();
		self.encrypt_buffer(data, &mut cipher_buffer)
			.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(cipher_buffer)
	}
}

#[cfg(feature = "sgx")]
pub mod sgx {
	use super::*;
	use derive_more::Display;
	use tkp_settings::files::RSA3072_SEALED_KEY_FILE;
	use tkp_sgx_io::{seal, unseal, SealedIO, StaticSealedIO};
	use log::*;
	use std::sgxfs::SgxFile;

	impl Rsa3072Seal {
		pub fn unseal_pubkey() -> Result<Rsa3072PubKey> {
			let pair = Self::unseal_from_static_file()?;
			let pubkey =
				pair.export_pubkey().map_err(|e| Error::Other(format!("{:?}", e).into()))?;
			Ok(pubkey)
		}
	}

	pub fn create_sealed_if_absent() -> Result<()> {
		if SgxFile::open(RSA3072_SEALED_KEY_FILE).is_err() {
			info!("[Enclave] Keyfile not found, creating new! {}", RSA3072_SEALED_KEY_FILE);
			return create_sealed()
		}
		Ok(())
	}

	pub fn create_sealed() -> Result<()> {
		let rsa_keypair =
			Rsa3072KeyPair::new().map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		// println!("[Enclave] generated RSA3072 key pair. Cleartext: {}", rsa_key_json);
		Rsa3072Seal::seal_to_static_file(&rsa_keypair)
	}

	#[derive(Copy, Clone, Debug, Display)]
	pub struct Rsa3072Seal;

	impl StaticSealedIO for Rsa3072Seal {
		type Error = Error;
		type Unsealed = Rsa3072KeyPair;
		fn unseal_from_static_file() -> Result<Self::Unsealed> {
			let raw = unseal(RSA3072_SEALED_KEY_FILE)?;
			let key: Rsa3072KeyPair = serde_json::from_slice(&raw)
				.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
			Ok(key.into())
		}

		fn seal_to_static_file(unsealed: &Self::Unsealed) -> Result<()> {
			let key_json = serde_json::to_vec(&unsealed)
				.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
			Ok(seal(&key_json, RSA3072_SEALED_KEY_FILE)?)
		}
	}

	impl SealedIO for Rsa3072Seal {
		type Error = Error;
		type Unsealed = Rsa3072KeyPair;

		fn unseal(&self) -> Result<Self::Unsealed> {
			Self::unseal_from_static_file()
		}

		fn seal(&self, unsealed: &Self::Unsealed) -> Result<()> {
			Self::seal_to_static_file(unsealed)
		}
	}
}
