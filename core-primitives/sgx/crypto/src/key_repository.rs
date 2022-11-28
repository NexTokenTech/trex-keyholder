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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::error::{Error, Result};
use tkp_sgx_io::SealedIO;
use std::sync::Arc;

/// Access a cryptographic key.
pub trait AccessKey {
	type KeyType;

	fn retrieve_key(&self) -> Result<Self::KeyType>;
}

/// Mutate a cryptographic key.
pub trait MutateKey<KeyType> {
	fn update_key(&self, key: KeyType) -> Result<()>;
}

/// Repository implementation. Stores a cryptographic key in-memory and in a file backed.
/// Uses the SealedIO trait for the file backend.
pub struct KeyRepository<KeyType, SealedIo> {
	key_lock: RwLock<KeyType>,
	sealed_io: Arc<SealedIo>,
}

impl<KeyType, SealedIo> KeyRepository<KeyType, SealedIo> {
	pub fn new(key: KeyType, sealed_io: Arc<SealedIo>) -> Self {
		KeyRepository { key_lock: RwLock::new(key), sealed_io }
	}
}

impl<KeyType, SealedIo> AccessKey for KeyRepository<KeyType, SealedIo>
where
	KeyType: Clone,
	SealedIo: SealedIO<Unsealed = KeyType, Error = crate::error::Error>,
{
	type KeyType = KeyType;

	fn retrieve_key(&self) -> Result<Self::KeyType> {
		self.key_lock.read().map_err(|_| Error::LockPoisoning).map(|l| l.clone())
	}
}

impl<KeyType, SealedIo> MutateKey<KeyType> for KeyRepository<KeyType, SealedIo>
where
	KeyType: Clone,
	SealedIo: SealedIO<Unsealed = KeyType, Error = crate::error::Error>,
{
	fn update_key(&self, key: KeyType) -> Result<()> {
		let mut key_lock = self.key_lock.write().map_err(|_| Error::LockPoisoning)?;

		self.sealed_io.seal(&key)?;
		*key_lock = self.sealed_io.unseal()?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{aes::Aes, mocks::AesSealMock};

	type TestKeyRepository = KeyRepository<Aes, AesSealMock>;

	#[test]
	fn update_and_retrieve_key_works() {
		let seal_mock = Arc::new(AesSealMock::default());
		let key_repository = TestKeyRepository::new(seal_mock.unseal().unwrap(), seal_mock.clone());

		assert_eq!(seal_mock.unseal().unwrap(), key_repository.retrieve_key().unwrap());

		let updated_key = Aes::new([2u8; 16], [0u8; 16]);
		key_repository.update_key(updated_key).unwrap();

		assert_eq!(updated_key, key_repository.retrieve_key().unwrap());
		assert_eq!(updated_key, seal_mock.unseal().unwrap());
	}
}
