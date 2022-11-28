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

//! Implement `parity-scale-codec` for the externalities.
//!
//! This is necessary workaround, as `Encode` and `Decode` can't directly be implemented on `HashMap` or `BTreeMap`.

use codec::{Decode, Encode, Input};
use serde::{de::DeserializeOwned, Serialize};
use std::{vec, vec::Vec};

use crate::{SgxExternalitiesDiffType, SgxExternalitiesType};

impl Encode for SgxExternalitiesType {
	fn encode(&self) -> Vec<u8> {
		encode_with_serialize(&self)
	}
}

impl Decode for SgxExternalitiesType {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		decode_with_deserialize(input)
	}
}

impl Encode for SgxExternalitiesDiffType {
	fn encode(&self) -> Vec<u8> {
		encode_with_serialize(&self)
	}
}

impl Decode for SgxExternalitiesDiffType {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		decode_with_deserialize(input)
	}
}

fn encode_with_serialize<T: Serialize>(source: &T) -> Vec<u8> {
	// We unwrap on purpose here in order to make sure we notice when something goes wrong.
	// Before we returned an empty vec and logged the error. But this could go unnoticed in the
	// caller and cause problems (in case the empty vec is also something valid)
	postcard::to_allocvec(source).unwrap()
}

fn decode_with_deserialize<I: Input, T: DeserializeOwned>(
	input: &mut I,
) -> Result<T, codec::Error> {
	let input_length = input
		.remaining_len()?
		.ok_or_else(|| codec::Error::from("Could not read length from input data"))?;

	let mut buff = vec![0u8; input_length];

	input.read(&mut buff)?;

	postcard::from_bytes::<'_, T>(buff.as_slice()).map_err(|e| {
		log::error!("deserialization failed: {:?}", e);
		codec::Error::from("Could not decode with deserialize")
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{InternalMap, SgxExternalities};
	use std::{
		collections::hash_map::DefaultHasher,
		hash::{Hash, Hasher},
	};

	#[test]
	fn serializing_externalities_type_works() {
		ensure_serialize_roundtrip_succeeds(create_default_state());
	}

	#[test]
	fn serializing_externalities_diff_type_works() {
		ensure_serialize_roundtrip_succeeds(create_default_state_diff());
	}

	#[test]
	fn serializing_externalities_works() {
		let externalities = SgxExternalities {
			state: create_default_state(),
			state_diff: create_default_state_diff(),
		};

		ensure_serialize_roundtrip_succeeds(externalities);
	}

	#[test]
	fn encoding_decoding_preserves_order() {
		let externalities = create_default_state();
		let encoded_externalities = externalities.encode();
		let decoded_externalities: SgxExternalitiesType =
			Decode::decode(&mut encoded_externalities.as_slice()).unwrap();
		let encoded_second_time_externalities = decoded_externalities.encode();

		assert_eq!(
			calculate_hash(&encoded_externalities),
			calculate_hash(&encoded_second_time_externalities)
		);
	}

	fn create_default_state_diff() -> SgxExternalitiesDiffType {
		let mut map = InternalMap::<Option<Vec<u8>>>::new();
		map.insert(Encode::encode("dings"), Some(Encode::encode("other")));
		map.insert(Encode::encode("item"), Some(Encode::encode("crate")));
		map.insert(Encode::encode("key"), None);
		SgxExternalitiesDiffType(map)
	}

	fn create_default_state() -> SgxExternalitiesType {
		let mut map = InternalMap::<Vec<u8>>::new();
		map.insert(Encode::encode("dings"), Encode::encode("other"));
		map.insert(Encode::encode("item"), Encode::encode("crate"));
		SgxExternalitiesType(map)
	}

	fn ensure_serialize_roundtrip_succeeds<
		T: Serialize + DeserializeOwned + std::cmp::PartialEq + std::fmt::Debug,
	>(
		item: T,
	) {
		let serialized_item = postcard::to_allocvec(&item).unwrap();
		let deserialized_item = postcard::from_bytes::<'_, T>(serialized_item.as_slice()).unwrap();
		assert_eq!(item, deserialized_item);
	}

	fn calculate_hash<T: Hash>(t: &T) -> u64 {
		let mut s = DefaultHasher::new();
		t.hash(&mut s);
		s.finish()
	}
}
