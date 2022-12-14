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
use std::sync::SgxRwLock as RwLock;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxRwLockWriteGuard as RwLockWriteGuard;

#[cfg(feature = "std")]
use std::sync::RwLock;
#[cfg(feature = "std")]
use std::sync::RwLockWriteGuard;

use crate::{
	error::{Error, Result},
	GetNonce, MutateNonce, Nonce,
};

/// Local nonce cache
///
/// stores the nonce internally, protected by a RW lock for concurrent access
#[derive(Default)]
pub struct NonceCache {
	nonce_lock: RwLock<Nonce>,
}

impl NonceCache {
	pub fn new(nonce_lock: RwLock<Nonce>) -> Self {
		NonceCache { nonce_lock }
	}
}

impl MutateNonce for NonceCache {
	fn load_for_mutation(&self) -> Result<RwLockWriteGuard<'_, Nonce>> {
		self.nonce_lock.write().map_err(|_| Error::LockPoisoning)
	}
}

impl GetNonce for NonceCache {
	fn get_nonce(&self) -> Result<Nonce> {
		let nonce_lock = self.nonce_lock.read().map_err(|_| Error::LockPoisoning)?;
		Ok(*nonce_lock)
	}
}

#[cfg(test)]
pub mod tests {
	use super::*;
	use std::{sync::Arc, thread};

	#[test]
	pub fn nonce_defaults_to_zero() {
		let nonce_cache = NonceCache::default();
		assert_eq!(Nonce(0), nonce_cache.get_nonce().unwrap());
	}

	#[test]
	pub fn set_nonce_works() {
		let nonce_cache = NonceCache::default();
		let mut nonce_lock = nonce_cache.load_for_mutation().unwrap();
		*nonce_lock = Nonce(42);
		std::mem::drop(nonce_lock);
		assert_eq!(Nonce(42), nonce_cache.get_nonce().unwrap());
	}

	#[test]
	pub fn concurrent_read_access_blocks_until_write_is_done() {
		let nonce_cache = Arc::new(NonceCache::default());

		let mut nonce_write_lock = nonce_cache.load_for_mutation().unwrap();

		// spawn a new thread that reads the nonce
		// this thread should be blocked until the write lock is released, i.e. until
		// the new nonce is written. We can verify this, by trying to read that nonce variable
		// that will be inserted further down below
		let new_thread_nonce_cache = nonce_cache.clone();
		let join_handle = thread::spawn(move || {
			let nonce_read = new_thread_nonce_cache.get_nonce().unwrap();
			assert_eq!(Nonce(3108), nonce_read);
		});

		*nonce_write_lock = Nonce(3108);
		std::mem::drop(nonce_write_lock);

		join_handle.join().unwrap();
	}
}
