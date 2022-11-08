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

pub const KEYFILE: &'static str = "prov_key.bin";
pub const EXTMAPFILE: &'static str = "ext_map.bin";
pub const MINHEAPSOURCEFILE: &'static str = "minheap_source.bin";

use sgx_types::*;
use std::io::{Read, Write};
use std::prelude::v1::*;
use std::sgxfs::SgxFile;
use std::slice;
use std::string::String;
use std::vec::Vec;
use std::collections::HashMap;
// use std::{cmp::Reverse, collections::BinaryHeap};

use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair,Rsa3072PubKey};


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
pub extern "C" fn decrypt_cipher_text(cipher_text: *const u8, cipher_len: usize) -> sgx_status_t{
    let ciphertext_bin = unsafe { slice::from_raw_parts(cipher_text, cipher_len) };
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
    //println!("key_json = {}", key_json_str);
    let rsa_keypair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();
    //println!("Recovered key = {:?}", rsa_keypair);

    let mut plaintext = Vec::new();
    rsa_keypair.decrypt_buffer(&ciphertext_bin, &mut plaintext).unwrap();

    let decrypted_string = String::from_utf8(plaintext).unwrap();
    println!("decrypted data = {}", decrypted_string);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn handle_private_keys(key:*const u8,key_len: u32,timestamp:u32,enclave_index:u32) -> sgx_status_t{
    println!("I'm in enclave");
    //minheap read from file
    let mut minheap:Vec<u32> = Vec::new();
    let minheap_json_str = get_json_str(MINHEAPSOURCEFILE);
    minheap = serde_json::from_str(&minheap_json_str).unwrap_or(minheap);
    //insert new timestamp
    minheap.push(timestamp);
    // derive string from key and key_len
    let private_key_text_vec = unsafe { slice::from_raw_parts(key, key_len as usize) };
    let private_key = String::from_utf8(private_key_text_vec.to_vec()).unwrap_or("".to_string());
    // ext_map read from file
    let mut ext_map:HashMap<String,u32> = HashMap::<String,u32>::new();
    let ext_map_json_str = get_json_str(EXTMAPFILE);
    ext_map = serde_json::from_str(&ext_map_json_str).unwrap_or(ext_map);
    //insert new private_key,timestamp
    ext_map.insert(private_key,timestamp);
    // store minheap to sgxfile
    let minheap_json_new = serde_json::to_string(&minheap).unwrap();
    provisioning_key(minheap_json_new.as_ptr() as * const u8,
                     minheap_json_new.len(),
                     MINHEAPSOURCEFILE);
    println!("{:?}",minheap_json_new);
    // store ext_map to sgxfile
    let ext_map_json_new = serde_json::to_string(&ext_map).unwrap();
    provisioning_key(ext_map_json_new.as_ptr() as *const u8,
                     ext_map_json_new.len(),
                     EXTMAPFILE);
    println!("{}",ext_map_json_new);
    sgx_status_t::SGX_SUCCESS
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

