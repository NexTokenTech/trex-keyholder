use codec::{Decode, Encode};
use substrate_api_client::{Metadata, MetadataError};

/// Code duplication due to the key holder using substrate/polkadot 0.9.30 but runtime use 0.9.27.
/// The code will be resolved after above issue is fixed.
#[allow(dead_code)]
pub type MetaResult<T> = Result<T, Error>;
// TODO: consolidate with error type in enclave-runtime.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// Metadata has not been set
	MetadataNotSet,
	/// Api-client metadata error
	NodeMetadata(MetadataError),
}

#[derive(Default, Encode, Decode, Debug, Clone)]
pub struct NodeMetadata {
	node_metadata: Option<Metadata>,
	runtime_spec_version: u32,
	runtime_transaction_version: u32,
}

// TODO: consolidate with struct type in enclave-runtime.
impl NodeMetadata {
	pub fn new(
		node_metadata: Metadata,
		runtime_spec_version: u32,
		runtime_transaction_version: u32,
	) -> Self {
		Self {
			node_metadata: Some(node_metadata),
			runtime_spec_version,
			runtime_transaction_version,
		}
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