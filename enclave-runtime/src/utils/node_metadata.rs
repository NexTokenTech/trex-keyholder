use codec::{Decode, Encode};
use substrate_api_client::{Metadata, MetadataError};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Metadata has not been set
    MetadataNotSet,
    /// Api-client metadata error
    NodeMetadata(substrate_api_client::MetadataError),
}

pub type MetaResult<T> = core::result::Result<T, Error>;

#[derive(Default, Encode, Decode, Debug, Clone)]
pub struct NodeMetadata {
    node_metadata: Option<Metadata>,
    runtime_spec_version: u32,
    runtime_transaction_version: u32,
}

impl NodeMetadata {
    /// Return the substrate chain runtime version.
    pub fn get_runtime_version(&self) -> u32 {
        self.runtime_spec_version
    }

    /// Return the substrate chain runtime transaction version.
    pub fn get_runtime_transaction_version(&self) -> u32 {
        self.runtime_transaction_version
    }

    /// Generic call indexes:
    /// Get the array [pallet index, call index] corresponding to a pallet's call over the metadata.
    pub fn call_indexes(
        &self,
        pallet_name: &'static str,
        call_name: &'static str,
    ) -> MetaResult<[u8; 2]> {
        let pallet = match &self.node_metadata {
            None => return Err(Error::MetadataNotSet),
            Some(m) => m.pallet(pallet_name).map_err(Error::NodeMetadata)?,
        };
        let call_index = pallet
            .calls
            .get(call_name)
            .ok_or(Error::NodeMetadata(MetadataError::CallNotFound(call_name)))?;
        Ok([pallet.index, *call_index])
    }
}
