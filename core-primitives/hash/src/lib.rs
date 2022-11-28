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
#![cfg_attr(not(feature = "std"), no_std)]
#![feature(assert_matches)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

#[cfg(feature = "std")]
use sha2::{Digest, Sha256};
#[cfg(feature = "std")]
use sp_core::U256;

use std::vec::Vec;

use codec::{Decode, Encode};
/// A not-yet-computed attempt to solve the proof of work. Calling the
/// compute method will compute the SHA256 hash and return the seal.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub struct Sha256PrivateKeyTime {
	pub aes_private_key: Vec<u8>,
	pub timestamp: u64,
}

#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub struct Sha256PrivateKeyHash {
	pub aes_private_key: Vec<u8>,
	pub hash: Vec<u8>,
}

/// Methods related to hashing and nonce updating in block headers.
#[cfg(feature = "std")]
pub trait Hash<I, E: Encode> {
	fn hash(&self) -> I;
}

#[cfg(feature = "std")]
impl Hash<Vec<u8>, U256> for Sha256PrivateKeyTime {
	fn hash(&self) -> Vec<u8> {
		// digest nonce by hashing with header data.
		let data = &self.encode()[..];
		let mut hasher = Sha256::new();
		hasher.update(&data);
		// convert hash results to integer in little endian order.
		hasher.finalize().as_slice().to_vec()
	}
}
