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

//! Converts maps to vecs for serialization.
//! from https://github.com/DenisKolodin/vectorize

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{iter::FromIterator, vec::Vec};

pub fn serialize<'a, T, K, V, S>(target: T, ser: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
	T: IntoIterator<Item = (&'a K, &'a V)>,
	K: Serialize + 'a,
	V: Serialize + 'a,
{
	let container: Vec<_> = target.into_iter().collect();
	serde::Serialize::serialize(&container, ser)
}

pub fn deserialize<'de, T, K, V, D>(des: D) -> Result<T, D::Error>
where
	D: Deserializer<'de>,
	T: FromIterator<(K, V)>,
	K: Deserialize<'de>,
	V: Deserialize<'de>,
{
	let container: Vec<_> = serde::Deserialize::deserialize(des)?;
	Ok(container.into_iter().collect())
}

#[cfg(test)]
mod tests {
	use crate::vectorize;
	use serde::{Deserialize, Serialize};
	use std::collections::HashMap;

	#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
	struct MyKey {
		one: String,
		two: u16,
		more: Vec<u8>,
	}

	#[derive(Debug, Serialize, Deserialize)]
	struct MyComplexType {
		#[serde(with = "vectorize")]
		map: HashMap<MyKey, String>,
	}

	#[test]
	fn it_works() -> Result<(), Box<dyn std::error::Error>> {
		let key = MyKey { one: "1".into(), two: 2, more: vec![1, 2, 3] };
		let mut map = HashMap::new();
		map.insert(key.clone(), "value".into());
		let instance = MyComplexType { map };
		let serialized = postcard::to_allocvec(&instance)?;
		let deserialized: MyComplexType = postcard::from_bytes(&serialized)?;
		let expected_value = "value".to_string();
		assert_eq!(deserialized.map.get(&key), Some(&expected_value));
		Ok(())
	}
}
