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

use derive_more::Display;

#[derive(Copy, Clone, Debug, Display)]
pub struct Ed25519Seal;

#[cfg(feature = "sgx")]
pub use sgx::*;

#[cfg(feature = "sgx")]
pub mod sgx {

	use super::*;
	use crate::error::{Error, Result};
	use codec::Encode;
	use tkp_settings::files::SEALED_SIGNER_SEED_FILE;
	use tkp_sgx_io::{seal, unseal, SealedIO, StaticSealedIO};
	use log::*;
	use sgx_rand::{Rng, StdRng};
	use sp_core::{crypto::Pair, ed25519};
	use std::{path::Path, sgxfs::SgxFile};

	impl StaticSealedIO for Ed25519Seal {
		type Error = Error;
		type Unsealed = ed25519::Pair;

		fn unseal_from_static_file() -> Result<ed25519::Pair> {
			let raw = unseal(SEALED_SIGNER_SEED_FILE)?;

			let key = ed25519::Pair::from_seed_slice(&raw)
				.map_err(|e| Error::Other(format!("{:?}", e).into()))?;

			Ok(key.into())
		}

		fn seal_to_static_file(unsealed: &Self::Unsealed) -> Result<()> {
			Ok(unsealed.seed().using_encoded(|bytes| seal(bytes, SEALED_SIGNER_SEED_FILE))?)
		}
	}

	impl SealedIO for Ed25519Seal {
		type Error = Error;
		type Unsealed = ed25519::Pair;

		fn unseal(&self) -> Result<Self::Unsealed> {
			Self::unseal_from_static_file()
		}

		fn seal(&self, unsealed: &Self::Unsealed) -> Result<()> {
			Self::seal_to_static_file(unsealed)
		}
	}

	pub fn create_sealed_if_absent() -> Result<()> {
		if SgxFile::open(SEALED_SIGNER_SEED_FILE).is_err() {
			if Path::new(SEALED_SIGNER_SEED_FILE).exists() {
				panic!("[Enclave] Keyfile {} exists but can't be opened. has it been written by the same enclave?", SEALED_SIGNER_SEED_FILE);
			}
			info!("[Enclave] Keyfile not found, creating new! {}", SEALED_SIGNER_SEED_FILE);
			return create_sealed_seed()
		}
		Ok(())
	}

	pub fn create_sealed_seed() -> Result<()> {
		let mut seed = [0u8; 32];
		let mut rand = StdRng::new()?;
		rand.fill_bytes(&mut seed);

		Ok(seal(&seed, SEALED_SIGNER_SEED_FILE)?)
	}
}
