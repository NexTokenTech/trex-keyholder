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
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
// substrate modules
use sp_core::{sr25519, H256 as Hash, Decode};
use frame_system::EventRecord;
use substrate_api_client::rpc::WsRpcClient;
use substrate_api_client::{Api, utils::FromHexString, AssetTipExtrinsicParams};

// use sp_runtime::generic::SignedBlock as SignedBlockG;
// use trex_runtime::Block;
// type SignedBlock = SignedBlockG<Block>;

// trex modules
use trex_runtime::RuntimeEvent;
use pallet_trex::Event as TrexEvent;
// local modules
use config::Config;

fn main(){
    // Setup logging
    env_logger::init();
    let config_f = std::fs::File::open("config.yml").expect("Could not open file.");
    let config: Config = serde_yaml::from_reader(config_f).expect("Could not read values.");
    debug!("Node server address: {}", config.node_ip);
    // TODO: Get account ID of current key-holder node.
    // TODO: Send remote attestation as ext to the trex network.
    // Spawn a thread to listen to the TREX data event.
    let event_url = config.node_ip.clone();
    let mut handlers = Vec::new();
    handlers.push(thread::spawn(move || {
        // Listen to TREXDataSent events.
        let client = WsRpcClient::new(&event_url);
        let api = Api::<sr25519::Pair, _, AssetTipExtrinsicParams>::new(client).unwrap();
        println!("Subscribe to TREX events");
        let (events_in, events_out) = channel();
        api.subscribe_events(events_in).unwrap();
        loop {
            let event_str = events_out.recv().unwrap();
            let _unhex = Vec::from_hex(event_str).unwrap();
            let mut _er_enc = _unhex.as_slice();
            let events = Vec::<EventRecord<RuntimeEvent, Hash>>::decode(&mut _er_enc).unwrap();
            // match event with trex event
            for event in &events {
                debug!("decoded: {:?} {:?}", event.phase, event.event);
                match &event.event {
                    // match to trex events.
                    RuntimeEvent::Trex(te) => {
                        debug!(">>>>>>>>>> TREX event: {:?}", te);
                        // match trex data sent event.
                        match &te {
                            TrexEvent::TREXDataSent(id, byte_data) => {
                                // TODO: deserialize TREX struct data and check key pieces.
                                todo!();
                            },
                            _ => {
                                debug!("ignoring unsupported TREX event");
                            },
                        }
                    },
                    _ => debug!("ignoring unsupported module event: {:?}", event.event),
                }
            }
            // wait 100 ms for next iteration
            thread::sleep(Duration::from_millis(100));
        }
    }));
    // TODO: check the enclave and release expired key pieces.
    // join threads.
    for handler in handlers {
        handler.join().expect("The thread being joined has panicked");
    }
}