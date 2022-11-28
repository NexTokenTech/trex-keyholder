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
//!
//! `bypass` is necessary to force deriving serialization of complex type specs.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[allow(unused)]
pub fn serialize<'a, T, S>(target: T, ser: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
	T: Serialize + 'a,
{
	serde::Serialize::serialize(&target, ser)
}

#[allow(unused)]
pub fn deserialize<'de, T, D>(des: D) -> Result<T, D::Error>
where
	D: Deserializer<'de>,
	T: Deserialize<'de>,
{
	serde::Deserialize::deserialize(des)
}

#[cfg(test)]
mod tests {
	use serde::{de::DeserializeOwned, Deserialize, Serialize};
	use std::fmt;

	trait Requirement:
		DeserializeOwned + Serialize + Clone + fmt::Debug + Sync + Send + 'static
	{
	}

	trait ComplexSpec: Requirement {}

	#[derive(Debug, Serialize, Deserialize)]
	struct MyComplexType<T: ComplexSpec> {
		#[serde(with = "super")] // = "vectorize::bypass"
		inner: Option<T>,
	}
}
