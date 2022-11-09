/*
    Copyright 2022 NexToken Technology LLC
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

mod config;

use log::debug;
use substrate_api_client::rpc::WsRpcClient;
use substrate_api_client::{Api, AssetTipExtrinsicParams};

use sp_runtime::generic::SignedBlock as SignedBlockG;
use trex_runtime::Block;
type SignedBlock = SignedBlockG<Block>;

// local modules
use config::Config;

fn main(){
    // Setup logging
    env_logger::init();
    let config_f = std::fs::File::open("config.yml").expect("Could not open file.");
    let config: Config = serde_yaml::from_reader(config_f).expect("Could not read values.");
    debug!("Node server address: {}", config.node_ip);
}