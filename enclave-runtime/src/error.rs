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
use derive_more::{Display, From};
use sgx_types::sgx_status_t;
use std::{boxed::Box, result::Result as StdResult};

/// A specialized Result type for threads in enclave.
///
/// Indicates the manner in which a thread exited.
///
/// The value contained in the Result::Err variant is the value the thread panicked with; that is, the argument the panic! macro was called with. Unlike with normal errors, this value doesn’t implement the Error trait.
///
/// A thread that completes without panicking is considered to exit successfully.
pub type Result<T> = StdResult<T, Error>;

/// A specialized Error type
#[derive(Debug, Display, From)]
pub enum Error {
    /// Failed to decode NodeMetadata or Sha256PrivateKeyHash
    Codec(codec::Error),
    /// Failed to create sealed or unseal Ed25519
    Crypto(tkp_sgx_crypto::Error),
    /// Failed due to IO
    IO(std::io::Error),
    /// Failed to execute enclave function
    Sgx(sgx_status_t),
    /// Failed to access Mutex
    MutexAccess,
    /// Failed due to other reason
    Other(Box<dyn std::error::Error>),
}
impl From<Error> for sgx_status_t {
    /// return sgx_status for top level enclave functions
    fn from(error: Error) -> sgx_status_t {
        match error {
            Error::Sgx(status) => status,
            _ => {
                log::error!("Returning error {:?} as sgx unexpected.", error);
                sgx_status_t::SGX_ERROR_UNEXPECTED
            },
        }
    }
}

impl<T> From<Error> for StdResult<T, Error> {
    fn from(error: Error) -> StdResult<T, Error> {
        Err(error)
    }
}
