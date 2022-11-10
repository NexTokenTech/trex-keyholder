// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "keyholderenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate serde_json;
extern crate sgx_crypto_helper;
#[macro_use]
extern crate lazy_static;

pub const KEYFILE: &'static str = "prov_key.bin";
pub const MINHEAPFILE: &'static str = "minheap.bin";

use sgx_types::*;
use std::io::{Read, Write};
use std::prelude::v1::*;
use std::sgxfs::SgxFile;
use std::slice;
use std::string::String;
use std::vec::Vec;
use std::sync::SgxMutex as Mutex;
use std::{cmp::Ordering,cmp::Reverse, collections::BinaryHeap};
use std::time::{SystemTime};
use std::untrusted::time::SystemTimeEx;

use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair,Rsa3072PubKey};

lazy_static! {
    static ref MIN_BINARY_HEAP: Mutex<BinaryHeap<Reverse<Ext>>> = Mutex::new(BinaryHeap::new());
}

extern "C" {
    pub fn ocall_output_key(
        ret_val : *mut sgx_status_t,
        key: *const u8,
        key_len: u32,
    ) -> sgx_status_t;
}

#[no_mangle]
pub unsafe extern "C" fn get_rsa_encryption_pubkey(
    pubkey: *mut u8,
    pubkey_size: u32,
) -> sgx_status_t {
    if SgxFile::open(KEYFILE).is_err() {
        let rsa_keypair =
            Rsa3072KeyPair::new().unwrap();
        let rsa_key_json = serde_json::to_string(&rsa_keypair).unwrap();
        provisioning_key(rsa_key_json.as_ptr() as *const u8,
                         rsa_key_json.len(),KEYFILE);
    }
    let mut keyvec: Vec<u8> = Vec::new();
    let key_json_str = match SgxFile::open(KEYFILE) {
        Ok(mut f) => match f.read_to_end(&mut keyvec) {
            Ok(len) => {
                println!("Read {} bytes from Key file", len);
                std::str::from_utf8(&keyvec).unwrap()
            }
            Err(x) => {
                println!("Read keyfile failed {}", x);
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        },
        Err(x) => {
            println!("get_sealed_pcl_key cannot open keyfile, please check if key is provisioned successfully! {}", x);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let rsa_keypair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();

    let rsa_pubkey: Rsa3072PubKey = rsa_keypair.export_pubkey().unwrap();

    let rsa_pubkey_json = match serde_json::to_string(&rsa_pubkey) {
        Ok(k) => k,
        Err(x) => {
            println!(
                "[Enclave] can't serialize rsa_pubkey {:?} {}",
                rsa_pubkey, x
            );
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);

    let data = rsa_pubkey_json.as_bytes().to_vec();
    let (left, right) = pubkey_slice.split_at_mut(data.len());
    left.clone_from_slice(&data);
    // fill the right side with whitespace
    right.iter_mut().for_each(|x| *x = 0x20);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn handle_private_keys(key:*const u8,key_len: u32,timestamp:u32,enclave_index:u32) -> sgx_status_t{
    println!("I'm in enclave");
    // FIXME: Need to do some fault tolerance
    let mut min_heap = MIN_BINARY_HEAP.lock().unwrap();

    let private_key_text_vec = unsafe { slice::from_raw_parts(key, key_len as usize) };
    let ext_item = Ext{
        timestamp,
        enclave_index,
        private_key:private_key_text_vec.to_vec()
    };
    min_heap.push(Reverse(ext_item));

    // FIXME: replace with trusted time
    let now = SystemTime::now();
    let mut now_time:u64 = 0;
    match now.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(elapsed) => {
            // it prints '2'
            println!("{}", elapsed.as_secs());
            now_time = elapsed.as_secs();
        }
        Err(e) => {
            // an error occurred!
            println!("Error: {:?}", e);
        }
    };

    loop {
        if let Some(Reverse(v)) = min_heap.peek() {
            if v.timestamp <=  now_time as u32 {
                let decrpyted_msg = get_decrypt_cipher_text(v.private_key.as_ptr() as *const u8,v.private_key.len());
                let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
                let res = unsafe {
                    ocall_output_key(&mut rt as *mut sgx_status_t,decrpyted_msg.as_ptr() as *const u8,decrpyted_msg.len() as u32);
                };
                min_heap.pop();
            }else{
                break;
            }
        }else{
            break;
        }
    }
    // TODO: min_heap Persistence
    sgx_status_t::SGX_SUCCESS
}

#[derive(Debug,Clone,PartialEq,Eq,PartialOrd)]
pub struct Ext{
    timestamp:u32,
    enclave_index:u32,
    private_key:Vec<u8>,
}

impl Ord for Ext {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp).reverse()
    }
}

fn get_decrypt_cipher_text(cipher_text: *const u8, cipher_len: usize) -> String{
    let ciphertext_bin = unsafe { slice::from_raw_parts(cipher_text, cipher_len) };
    let mut keyvec: Vec<u8> = Vec::new();

    let key_json_str = match SgxFile::open(KEYFILE) {
        Ok(mut f) => match f.read_to_end(&mut keyvec) {
            Ok(_len) => {
                std::str::from_utf8(&keyvec).unwrap()
            }
            Err(_x) => {
                ""
            }
        },
        Err(_x) => {
            ""
        }
    };
    //println!("key_json = {}", key_json_str);
    let rsa_keypair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();
    //println!("Recovered key = {:?}", rsa_keypair);

    let mut plaintext = Vec::new();
    rsa_keypair.decrypt_buffer(&ciphertext_bin, &mut plaintext).unwrap();

    let decrypted_string = String::from_utf8(plaintext).unwrap();
    decrypted_string
}

fn get_json_str(filename:&str) -> String{
    let mut keyvec: Vec<u8> = Vec::new();

    let key_json_str = match SgxFile::open(filename) {
        Ok(mut f) => match f.read_to_end(&mut keyvec) {
            Ok(_) => {
                std::str::from_utf8(&keyvec).unwrap()
            }
            Err(_) => {
                return "".to_string();
            }
        },
        Err(_x) => {
            std::str::from_utf8(&keyvec).unwrap()
        }
    };
    key_json_str.to_string()
}

fn provisioning_key(key_ptr: *const u8, some_len: usize, file_name:&str){
    //TODO error handler
    let key_slice = unsafe { slice::from_raw_parts(key_ptr, some_len) };

    match SgxFile::create(file_name) {
        Ok(mut f) => match f.write_all(key_slice) {
            Ok(()) => {
                println!("SgxFile write key file success!");
            }
            Err(x) => {
                println!("SgxFile write key file failed! {}", x);
            }
        },
        Err(x) => {
            println!("SgxFile create file {} error {}", file_name, x);
        }
    }
}

