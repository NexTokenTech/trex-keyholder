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

use sgx_types::*;
use std::io::{self, Write};
use std::prelude::v1::*;
#[allow(unused)]
use std::sgxfs::SgxFile;
use std::slice;
#[allow(unused)]
use std::vec::Vec;

use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_crypto_helper::RsaKeyPair;

pub const KEYFILE: &'static str = "prov_key.bin";
#[allow(unused)]
static ENCLAVE_FILE: &'static str = "enclave.signed.so";

#[no_mangle]
pub extern "C" fn ecall_test(some_string: *const u8, some_len: usize) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);

    println!("Message from the enclave");

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_rsa_encryption_pubkey(
    pubkey: *mut u8,
    pubkey_size: u32,
) -> sgx_status_t {
    // Step 1: Generate a pair of RSA key
    let rsa_keypair = Rsa3072KeyPair::new().unwrap();
    //TODO: store rsa_keypair in SgxFile
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
