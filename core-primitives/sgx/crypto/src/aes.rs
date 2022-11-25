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

use crate::{
	error::{Error, Result},
	traits::StateCrypto,
};
use aes::Aes128;
use codec::{Decode, Encode};
use derive_more::Display;
use ofb::{
	cipher::{NewStreamCipher, SyncStreamCipher},
	Ofb,
};
use std::convert::{TryFrom, TryInto};

type AesOfb = Ofb<Aes128>;

#[derive(Debug, Default, Encode, Decode, Clone, Copy, PartialEq, Eq)]
pub struct Aes {
	pub key: [u8; 16],
	pub init_vec: [u8; 16],
}

impl Aes {
	pub fn new(key: [u8; 16], init_vec: [u8; 16]) -> Self {
		Self { key, init_vec }
	}
}

#[derive(Copy, Clone, Debug, Display)]
pub struct AesSeal;

impl StateCrypto for Aes {
	type Error = Error;

	fn encrypt(&self, data: &mut [u8]) -> Result<()> {
		de_or_encrypt(self, data)
	}

	fn decrypt(&self, data: &mut [u8]) -> Result<()> {
		de_or_encrypt(self, data)
	}
}

impl TryFrom<&Aes> for AesOfb {
	type Error = Error;

	fn try_from(aes: &Aes) -> std::result::Result<Self, Self::Error> {
		AesOfb::new_var(&aes.key, &aes.init_vec).map_err(|_| Error::InvalidNonceKeyLength)
	}
}

/// If AES acts on the encrypted data it decrypts and vice versa
pub fn de_or_encrypt(aes: &Aes, data: &mut [u8]) -> Result<()> {
	aes.try_into().map(|mut ofb: AesOfb| ofb.apply_keystream(data))
}

#[cfg(feature = "sgx")]
pub use sgx::*;

#[cfg(feature = "sgx")]
pub mod sgx {

	use super::*;
	use tkp_settings::files::AES_KEY_FILE_AND_INIT_V;
	use tkp_sgx_io::{seal, unseal, SealedIO, StaticSealedIO};
	use log::info;
	use sgx_rand::{Rng, StdRng};
	use std::sgxfs::SgxFile;

	impl StaticSealedIO for AesSeal {
		type Error = Error;
		type Unsealed = Aes;

		fn unseal_from_static_file() -> Result<Self::Unsealed> {
			Ok(unseal(AES_KEY_FILE_AND_INIT_V).map(|b| Decode::decode(&mut b.as_slice()))??)
		}

		fn seal_to_static_file(unsealed: &Self::Unsealed) -> Result<()> {
			Ok(unsealed.using_encoded(|bytes| seal(bytes, AES_KEY_FILE_AND_INIT_V))?)
		}
	}

	impl SealedIO for AesSeal {
		type Error = Error;
		type Unsealed = Aes;

		fn unseal(&self) -> Result<Self::Unsealed> {
			Self::unseal_from_static_file()
		}

		fn seal(&self, unsealed: &Self::Unsealed) -> Result<()> {
			Self::seal_to_static_file(&unsealed)
		}
	}

	pub fn create_sealed_if_absent() -> Result<()> {
		if SgxFile::open(AES_KEY_FILE_AND_INIT_V).is_err() {
			info!("[Enclave] Keyfile not found, creating new! {}", AES_KEY_FILE_AND_INIT_V);
			return create_sealed()
		}
		Ok(())
	}

	pub fn create_sealed() -> Result<()> {
		let mut key = [0u8; 16];
		let mut iv = [0u8; 16];

		let mut rand = StdRng::new()?;

		rand.fill_bytes(&mut key);
		rand.fill_bytes(&mut iv);
		AesSeal::seal_to_static_file(&Aes::new(key, iv))
	}
}
