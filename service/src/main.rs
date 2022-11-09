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

extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;

use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair, Rsa3072PubKey};
// use std::io::Write;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";


extern "C" {
    pub fn get_rsa_encryption_pubkey(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        pubkey: *mut u8,
        pubkey_size: u32,
    ) -> sgx_status_t;
    pub fn handle_private_keys(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        key:*const u8,
        key_len: u32,
        timestamp:u32,
        enclave_index:u32
    ) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    let pubkey_size = 8192;
    let mut pubkey = vec![0u8; pubkey_size as usize];

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        get_rsa_encryption_pubkey(
            enclave.geteid(),
            &mut retval,
            pubkey.as_mut_ptr(),
            pubkey.len() as u32,
        )
    };

    let rsa_pubkey: Rsa3072PubKey =
        serde_json::from_slice(pubkey.as_slice()).expect("Invalid public key");
    println!("got RSA pubkey {:?}", rsa_pubkey);

    //A bunch of data decrypted by time
    for i in 0..10 {
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let mut private_key = String::from("I send a private_key");
        private_key = private_key + &i.to_string();
        let private_key_slice = &private_key.into_bytes();
        let mut private_key_cipher = Vec::new();
        match rsa_pubkey.encrypt_buffer(private_key_slice, &mut private_key_cipher) {
            Ok(n) => println!("Generated payload {} bytes", n),
            Err(x) => println!("Error occured during encryption {}", x),
        }
        let result = unsafe {
            handle_private_keys(
                enclave.geteid(),
                &mut retval,
                private_key_cipher.as_ptr() as *const u8,
                private_key_cipher.len() as u32,
                1667874198 + i,
                2
            )
        };
        println!("{:?}",result);
    }
    // Data that has not been decrypted in time
    for i in 10..15 {
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let mut private_key = String::from("I send a private_key");
        private_key = private_key + &i.to_string();
        let private_key_slice = &private_key.into_bytes();
        let mut private_key_cipher = Vec::new();
        match rsa_pubkey.encrypt_buffer(private_key_slice, &mut private_key_cipher) {
            Ok(n) => println!("Generated payload {} bytes", n),
            Err(x) => println!("Error occured during encryption {}", x),
        }
        let result = unsafe {
            handle_private_keys(
                enclave.geteid(),
                &mut retval,
                private_key_cipher.as_ptr() as *const u8,
                private_key_cipher.len() as u32,
                1667983347 + i,
                2
            )
        };
        println!("{:?}",result);
    }

    enclave.destroy();
}
