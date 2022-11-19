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
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

static DEFAULT_NODE_SERVER: &str = "ws://127.0.0.1";
static DEFAULT_NODE_PORT: u16 = 9944;
static DEFAULT_MU_RA_PORT: u16 = 3443;
static DEFAULT_METRICS_PORT: u16 = 8787;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub node_ip: String,
    pub node_port: u16,
    pub keyholder_ip: String,
    /// Mutual remote attestation address that will be returned by the dedicated trusted ws rpc call.
    pub mu_ra_external_address: Option<String>,
    /// Port for mutual-remote attestation requests.
    pub mu_ra_port: u16,
    /// Enable the metrics server
    pub enable_metrics_server: bool,
    /// Port for the metrics server
    pub metrics_server_port: u16,
}

impl Config {
    /// A new API config struct with default settings.
    #[allow(unused)]
    pub fn new(
        keyholder_ip: String,
        mu_ra_external_address: Option<String>,
        enable_metrics_server: bool,
    ) -> Self {
        Self {
            node_ip: DEFAULT_NODE_SERVER.to_string(),
            node_port: DEFAULT_NODE_PORT,
            keyholder_ip,
            mu_ra_external_address,
            mu_ra_port: DEFAULT_MU_RA_PORT,
            enable_metrics_server,
            metrics_server_port: DEFAULT_METRICS_PORT,
        }
    }

    pub fn from_yaml(path_str: &str) -> Self {
        let config_path = PathBuf::from(path_str);
        let config_f = std::fs::File::open(config_path).expect("Could not open file.");
        serde_yaml::from_reader(config_f).expect("Could not read config.")
    }

    /// Returns the client url of the node (including ws://).
    pub fn node_url(&self) -> String {
        format!("{}:{}", self.node_ip, self.node_port)
    }

    /// Returns the worker's url for remote attestation.
    #[allow(dead_code)]
    pub fn mu_ra_url(&self) -> String {
        format!("{}:{}", self.keyholder_ip, self.mu_ra_port)
    }
}
