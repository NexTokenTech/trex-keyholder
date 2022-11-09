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

use serde::{Deserialize, Serialize};

static DEFAULT_NODE_SERVER: &str = "ws://127.0.0.1";
static DEFAULT_NODE_PORT: u16 = 9944;
static DEFAULT_MU_RA_PORT: u16 = 3443;
static DEFAULT_METRICS_PORT: u16 = 8787;
static DEFAULT_UNTRUSTED_HTTP_PORT: u16 = 4545;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub node_ip: String,
    pub node_port: u16,
    pub worker_ip: String,
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
    pub fn new(
        node_ip: String,
        node_port: u16,
        worker_ip: String,
        mu_ra_external_address: Option<String>,
        mu_ra_port: u16,
        enable_metrics_server: bool,
        metrics_server_port: u16,
    ) -> Self {
        Self {
            node_ip,
            node_port,
            worker_ip,
            mu_ra_external_address,
            mu_ra_port,
            enable_metrics_server,
            metrics_server_port,
        }
    }

    /// Returns the client url of the node (including ws://).
    pub fn node_url(&self) -> String {
        format!("{}:{}", self.node_ip, self.node_port)
    }

    pub fn mu_ra_url(&self) -> String {
        format!("{}:{}", self.worker_ip, self.mu_ra_port)
    }

    /// Returns the mutual remote attestion worker url that should be addressed by external workers.
    pub fn mu_ra_url_external(&self) -> String {
        match &self.mu_ra_external_address {
            Some(external_address) => external_address.to_string(),
            None => format!("{}:{}", self.worker_ip, self.mu_ra_port),
        }
    }

    pub fn try_parse_metrics_server_port(&self) -> u16 {
        self.metrics_server_port
    }
}

fn add_port_if_necessary(url: &str, port: &str) -> String {
    // [Option("ws(s)"), ip, Option(port)]
    match url.split(':').count() {
        3 => url.to_string(),
        2 => {
            if url.contains("ws") {
                // url is of format ws://127.0.0.1, no port added
                format!("{}:{}", url, port)
            } else {
                // url is of format 127.0.0.1:4000, port was added
                url.to_string()
            }
        },
        1 => format!("{}:{}", url, port),
        _ => panic!("Invalid worker url format in url input {:?}", url),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn ensure_no_port_is_added_to_url_with_port() {
        let url = "ws://hello:4000";
        let port = "0";

        let resulting_url = add_port_if_necessary(url, port);

        assert_eq!(resulting_url, url);
    }

    #[test]
    fn ensure_port_is_added_to_url_without_port() {
        let url = "wss://hello";
        let port = "0";

        let resulting_url = add_port_if_necessary(url, port);

        assert_eq!(resulting_url, format!("{}:{}", url, port));
    }

    #[test]
    fn ensure_no_port_is_added_to_url_with_port_without_prefix() {
        let url = "hello:10001";
        let port = "012";

        let resulting_url = add_port_if_necessary(url, port);

        assert_eq!(resulting_url, url);
    }

    #[test]
    fn ensure_port_is_added_to_url_without_port_without_prefix() {
        let url = "hello_world";
        let port = "10";

        let resulting_url = add_port_if_necessary(url, port);

        assert_eq!(resulting_url, format!("{}:{}", url, port));
    }
}
