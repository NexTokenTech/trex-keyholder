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
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(feature = "sgx")]
extern crate sgx_tstd as std;

use codec::{Decode, Encode};
use derive_more::{Deref, DerefMut, From};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, vec::Vec};

pub use scope_limited::{set_and_run_with_externalities, with_externalities};

// Unfortunately we cannot use `serde_with::serde_as` to serialize our map (which would be very convenient)
// because it has pulls in the serde and serde_json dependency with `std`, not `default-features=no`.
// Instead we use https://github.com/DenisKolodin/vectorize which is very little code, copy-pasted
// directly into this code base.
//use serde_with::serde_as;

mod codec_impl;
mod scope_limited;
// These are used to serialize a map with keys that are not string.
mod bypass;
mod vectorize;

type InternalMap<V> = BTreeMap<Vec<u8>, V>;

#[derive(From, Deref, DerefMut, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SgxExternalitiesType(#[serde(with = "vectorize")] InternalMap<Vec<u8>>);

#[derive(From, Deref, DerefMut, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SgxExternalitiesDiffType(#[serde(with = "vectorize")] InternalMap<Option<Vec<u8>>>);

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct SgxExternalities {
	pub state: SgxExternalitiesType,
	pub state_diff: SgxExternalitiesDiffType,
}

pub trait SgxExternalitiesTrait {
	fn new() -> Self;
	fn state(&self) -> &SgxExternalitiesType;
	fn state_diff(&self) -> &SgxExternalitiesDiffType;
	fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Option<Vec<u8>>;
	fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>>;
	fn get(&self, k: &[u8]) -> Option<&Vec<u8>>;
	fn contains_key(&self, k: &[u8]) -> bool;
	fn prune_state_diff(&mut self);
	fn execute_with<R>(&mut self, f: impl FnOnce() -> R) -> R;
}

impl SgxExternalitiesTrait for SgxExternalities {
	/// Create a new instance of `BasicExternalities`
	fn new() -> Self {
		Default::default()
	}

	fn state(&self) -> &SgxExternalitiesType {
		&self.state
	}

	fn state_diff(&self) -> &SgxExternalitiesDiffType {
		&self.state_diff
	}

	/// Insert key/value
	fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Option<Vec<u8>> {
		self.state_diff.insert(k.clone(), Some(v.clone()));
		self.state.insert(k, v)
	}

	/// remove key
	fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>> {
		self.state_diff.insert(k.to_vec(), None);
		self.state.remove(k)
	}

	/// get value from state of key
	fn get(&self, k: &[u8]) -> Option<&Vec<u8>> {
		self.state.get(k)
	}

	/// check if state contains key
	fn contains_key(&self, k: &[u8]) -> bool {
		self.state.contains_key(k)
	}

	/// prunes the state diff
	fn prune_state_diff(&mut self) {
		self.state_diff.clear();
	}

	/// Execute the given closure while `self` is set as externalities.
	///
	/// Returns the result of the given closure.
	fn execute_with<R>(&mut self, f: impl FnOnce() -> R) -> R {
		set_and_run_with_externalities(self, f)
	}
}

/// Results concerning an operation to remove many keys.
#[derive(codec::Encode, codec::Decode)]
#[must_use]
pub struct MultiRemovalResults {
	/// A continuation cursor which, if `Some` must be provided to the subsequent removal call.
	/// If `None` then all removals are complete and no further calls are needed.
	pub maybe_cursor: Option<Vec<u8>>,
	/// The number of items removed from the backend database.
	pub backend: u32,
	/// The number of unique keys removed, taking into account both the backend and the overlay.
	pub unique: u32,
	/// The number of iterations (each requiring a storage seek/read) which were done.
	pub loops: u32,
}

impl MultiRemovalResults {
	/// Deconstruct into the internal components.
	///
	/// Returns `(maybe_cursor, backend, unique, loops)`.
	pub fn deconstruct(self) -> (Option<Vec<u8>>, u32, u32, u32) {
		(self.maybe_cursor, self.backend, self.unique, self.loops)
	}
}

#[cfg(test)]
pub mod tests {

	use super::*;

	#[test]
	fn mutating_externalities_through_environmental_variable_works() {
		let mut externalities = SgxExternalities::default();

		externalities.execute_with(|| {
			with_externalities(|e| {
				e.insert("building".encode(), "empire_state".encode());
				e.insert("house".encode(), "ginger_bread".encode());
			})
			.unwrap()
		});

		let state_len =
			externalities.execute_with(|| with_externalities(|e| e.state.0.len()).unwrap());

		assert_eq!(2, state_len);
	}

	#[test]
	fn basic_externalities_is_empty() {
		let ext = SgxExternalities::default();
		assert!(ext.state.0.is_empty());
	}

	#[test]
	#[should_panic(expected = "already borrowed: BorrowMutError")]
	fn nested_with_externalities_panics() {
		let mut ext = SgxExternalities::default();

		ext.execute_with(|| {
			with_externalities(|_| with_externalities(|_| unreachable!("panics before")).unwrap())
				.unwrap();
		});
	}

	#[test]
	fn nesting_execute_with_uses_the_latest_externalities() {
		let mut ext = SgxExternalities::default();
		let mut ext2 = ext.clone();

		let hello = b"hello".to_vec();
		let world = b"world".to_vec();

		ext.execute_with(|| {
			with_externalities(|e| {
				e.insert(hello.clone(), hello.clone());
			})
			.unwrap();

			ext2.execute_with(|| {
				// `with_externalities` uses the latest set externalities defined by the last
				// `set_and_run_with_externalities` call.
				with_externalities(|e| {
					e.insert(world.clone(), world.clone());
				})
				.unwrap();
			});
		});

		assert_eq!(ext.get(&hello), Some(&hello));
		assert_eq!(ext2.get(&world), Some(&world));

		// ext1 and ext2 are unrelated.
		assert_eq!(ext.get(&world), None);
	}
}
