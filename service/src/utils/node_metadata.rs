use codec::{Decode, Encode};
use substrate_api_client::{Metadata};

#[derive(Default, Encode, Decode, Debug, Clone)]
pub struct NodeMetadata {
    node_metadata: Option<Metadata>,
    runtime_spec_version: u32,
    runtime_transaction_version: u32,
}

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
}
