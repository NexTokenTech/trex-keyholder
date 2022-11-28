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

use crate::{
	aes::Aes,
	error::{Error, Result},
	key_repository::{AccessKey, MutateKey},
};
use tkp_sgx_io::{SealedIO, StaticSealedIO};
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;

#[derive(Default)]
pub struct KeyRepositoryMock<KeyType>
where
	KeyType: Clone + Default,
{
	key: RwLock<KeyType>,
}

impl<KeyType> KeyRepositoryMock<KeyType>
where
	KeyType: Clone + Default,
{
	pub fn new(key: KeyType) -> Self {
		KeyRepositoryMock { key: RwLock::new(key) }
	}
}

impl<KeyType> AccessKey for KeyRepositoryMock<KeyType>
where
	KeyType: Clone + Default,
{
	type KeyType = KeyType;

	fn retrieve_key(&self) -> Result<Self::KeyType> {
		Ok(self.key.read().unwrap().clone())
	}
}

impl<KeyType> MutateKey<KeyType> for KeyRepositoryMock<KeyType>
where
	KeyType: Clone + Default,
{
	fn update_key(&self, key: KeyType) -> Result<()> {
		let mut lock = self.key.write().unwrap();
		*lock = key;
		Ok(())
	}
}

#[derive(Default)]
pub struct AesSealMock {
	aes: RwLock<Aes>,
}

impl StaticSealedIO for AesSealMock {
	type Error = Error;
	type Unsealed = Aes;

	fn unseal_from_static_file() -> Result<Self::Unsealed> {
		Ok(Aes::default())
	}

	fn seal_to_static_file(_unsealed: &Self::Unsealed) -> Result<()> {
		Ok(())
	}
}

impl SealedIO for AesSealMock {
	type Error = Error;
	type Unsealed = Aes;

	fn unseal(&self) -> std::result::Result<Self::Unsealed, Self::Error> {
		self.aes.read().map_err(|e| Error::Other(format!("{:?}", e).into())).map(|k| *k)
	}

	fn seal(&self, unsealed: &Self::Unsealed) -> Result<()> {
		let mut aes_lock = self.aes.write().map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		*aes_lock = *unsealed;
		Ok(())
	}
}

#[derive(Default)]
pub struct Rsa3072SealMock {}

impl StaticSealedIO for Rsa3072SealMock {
	type Error = Error;
	type Unsealed = Rsa3072KeyPair;

	fn unseal_from_static_file() -> Result<Self::Unsealed> {
		Ok(Rsa3072KeyPair::default())
	}

	fn seal_to_static_file(_unsealed: &Self::Unsealed) -> Result<()> {
		Ok(())
	}
}
