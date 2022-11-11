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

mod config;

extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;
use sgx_urts::SgxEnclave;

use std::os::unix::io::{IntoRawFd, AsRawFd};
use std::env;
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::str;

use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair, Rsa3072PubKey};
// use std::io::Write;
use std::slice;

use log::debug;
use substrate_api_client::rpc::WsRpcClient;
use substrate_api_client::{Api, AssetTipExtrinsicParams};
use sp_runtime::generic::SignedBlock as SignedBlockG;

// local modules
use config::Config;

const BUFFER_SIZE: usize = 1024;
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
    fn perform_ra(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,sign_type: sgx_quote_sign_type_t) -> sgx_status_t;
}

#[no_mangle]
pub unsafe extern "C" fn ocall_output_key(
    key: *const u8,
    key_len: u32,
) -> sgx_status_t {
    let private_key_text_vec = unsafe { slice::from_raw_parts(key, key_len as usize) };
    let str = String::from_utf8(private_key_text_vec.to_vec());
    println!("I'm in ocall function {:?}",str);
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C"
fn ocall_sgx_init_quote(ret_ti: *mut sgx_target_info_t,
                        ret_gid : *mut sgx_epid_group_id_t) -> sgx_status_t {
    println!("Entering ocall_sgx_init_quote");
    unsafe {sgx_init_quote(ret_ti, ret_gid)}
}

pub fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}


#[no_mangle]
pub extern "C"
fn ocall_get_ias_socket(ret_fd : *mut c_int) -> sgx_status_t {
    let port = 443;
    let hostname = "api.trustedservices.intel.com";
    let addr = lookup_ipv4(hostname, port);
    let sock = TcpStream::connect(&addr).expect("[-] Connect tls server failed!");

    unsafe {*ret_fd = sock.into_raw_fd();}

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C"
fn ocall_get_quote (p_sigrl            : *const u8,
                    sigrl_len          : u32,
                    p_report           : *const sgx_report_t,
                    quote_type         : sgx_quote_sign_type_t,
                    p_spid             : *const sgx_spid_t,
                    p_nonce            : *const sgx_quote_nonce_t,
                    p_qe_report        : *mut sgx_report_t,
                    p_quote            : *mut u8,
                    _maxlen             : u32,
                    p_quote_len        : *mut u32) -> sgx_status_t {
    println!("Entering ocall_get_quote");

    let mut real_quote_len : u32 = 0;

    let ret = unsafe {
        sgx_calc_quote_size(p_sigrl, sigrl_len, &mut real_quote_len as *mut u32)
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    println!("quote size = {}", real_quote_len);
    unsafe { *p_quote_len = real_quote_len; }

    let ret = unsafe {
        sgx_get_quote(p_report,
                      quote_type,
                      p_spid,
                      p_nonce,
                      p_sigrl,
                      sigrl_len,
                      p_qe_report,
                      p_quote as *mut sgx_quote_t,
                      real_quote_len)
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        println!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    println!("sgx_calc_quote_size returned {}", ret);
    ret
}

#[no_mangle]
pub extern "C"
fn ocall_get_update_info (platform_blob: * const sgx_platform_info_t,
                          enclave_trusted: i32,
                          update_info: * mut sgx_update_info_bit_t) -> sgx_status_t {
    unsafe{
        sgx_report_attestation_status(platform_blob, enclave_trusted, update_info)
    }
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
    // Setup logging
    env_logger::init();
    let config_f = std::fs::File::open("config.yml").expect("Could not open file.");
    let config: Config = serde_yaml::from_reader(config_f).expect("Could not read values.");
    debug!("Node server address: {}", config.node_ip);
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
    let mut sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        perform_ra(enclave.geteid(), &mut retval,  sign_type)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            println!("ECALL success!");
        },
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }

    // let pubkey_size = 8192;
    // let mut pubkey = vec![0u8; pubkey_size as usize];
    //
    // let mut retval = sgx_status_t::SGX_SUCCESS;
    //
    // let result = unsafe {
    //     get_rsa_encryption_pubkey(
    //         enclave.geteid(),
    //         &mut retval,
    //         pubkey.as_mut_ptr(),
    //         pubkey.len() as u32,
    //     )
    // };
    //
    // let rsa_pubkey: Rsa3072PubKey =
    //     serde_json::from_slice(pubkey.as_slice()).expect("Invalid public key");
    // println!("got RSA pubkey {:?}", rsa_pubkey);
    //
    // //A bunch of data decrypted by time
    // for i in 0..10 {
    //     let mut retval = sgx_status_t::SGX_SUCCESS;
    //     let mut private_key = String::from("I send a private_key");
    //     private_key = private_key + &i.to_string();
    //     let private_key_slice = &private_key.into_bytes();
    //     let mut private_key_cipher = Vec::new();
    //     match rsa_pubkey.encrypt_buffer(private_key_slice, &mut private_key_cipher) {
    //         Ok(n) => println!("Generated payload {} bytes", n),
    //         Err(x) => println!("Error occured during encryption {}", x),
    //     }
    //     let result = unsafe {
    //         handle_private_keys(
    //             enclave.geteid(),
    //             &mut retval,
    //             private_key_cipher.as_ptr() as *const u8,
    //             private_key_cipher.len() as u32,
    //             1667874198 + i,
    //             2
    //         )
    //     };
    //     println!("{:?}",result);
    // }
    // // Data that has not been decrypted in time
    // for i in 10..15 {
    //     let mut retval = sgx_status_t::SGX_SUCCESS;
    //     let mut private_key = String::from("I send a private_key");
    //     private_key = private_key + &i.to_string();
    //     let private_key_slice = &private_key.into_bytes();
    //     let mut private_key_cipher = Vec::new();
    //     match rsa_pubkey.encrypt_buffer(private_key_slice, &mut private_key_cipher) {
    //         Ok(n) => println!("Generated payload {} bytes", n),
    //         Err(x) => println!("Error occured during encryption {}", x),
    //     }
    //     let result = unsafe {
    //         handle_private_keys(
    //             enclave.geteid(),
    //             &mut retval,
    //             private_key_cipher.as_ptr() as *const u8,
    //             private_key_cipher.len() as u32,
    //             1667983347 + i,
    //             2
    //         )
    //     };
    //     println!("{:?}",result);
    // }

    enclave.destroy();
}
