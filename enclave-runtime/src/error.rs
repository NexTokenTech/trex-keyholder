use derive_more::{Display, From};
use sgx_types::sgx_status_t;
use std::{boxed::Box, result::Result as StdResult};

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, Display, From)]
pub enum Error {
    Codec(codec::Error),
    Crypto(tkp_sgx_crypto::Error),
    IO(std::io::Error),
    Sgx(sgx_status_t),
    MutexAccess,
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
