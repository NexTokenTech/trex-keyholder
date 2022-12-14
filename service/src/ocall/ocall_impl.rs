/*
 Copyright 2022 NexToken Tech LLC

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
extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;

use std::{
	net::{SocketAddr, TcpStream, ToSocketAddrs},
	os::unix::io::IntoRawFd,
	str,
};

use tkp_settings::nts::{DEFAULT_KE_PORT, NTS_HOSTNAME};

/// Ocall: init quote
#[no_mangle]
pub extern "C" fn ocall_sgx_init_quote(
	ret_ti: *mut sgx_target_info_t,
	ret_gid: *mut sgx_epid_group_id_t,
) -> sgx_status_t {
	println!("Entering ocall_sgx_init_quote");
	unsafe { sgx_init_quote(ret_ti, ret_gid) }
}

/// Construct socket address
pub fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
	let addrs = (host, port).to_socket_addrs().unwrap();
	for addr in addrs {
		if let SocketAddr::V4(_) = addr {
			return addr
		}
	}

	unreachable!("Cannot lookup address");
}

/// Ocall: get ias socket
#[no_mangle]
pub extern "C" fn ocall_get_ias_socket(ret_fd: *mut c_int) -> sgx_status_t {
	let port = 443;
	let hostname = "api.trustedservices.intel.com";
	let addr = lookup_ipv4(hostname, port);
	let sock = TcpStream::connect(&addr).expect("[-] Connect tls server failed!");

	unsafe {
		*ret_fd = sock.into_raw_fd();
	}

	sgx_status_t::SGX_SUCCESS
}

/// Ocall: get quote
#[no_mangle]
pub extern "C" fn ocall_get_quote(
	p_sigrl: *const u8,
	sigrl_len: u32,
	p_report: *const sgx_report_t,
	quote_type: sgx_quote_sign_type_t,
	p_spid: *const sgx_spid_t,
	p_nonce: *const sgx_quote_nonce_t,
	p_qe_report: *mut sgx_report_t,
	p_quote: *mut u8,
	_maxlen: u32,
	p_quote_len: *mut u32,
) -> sgx_status_t {
	println!("Entering ocall_get_quote");

	let mut real_quote_len: u32 = 0;

	let ret = unsafe { sgx_calc_quote_size(p_sigrl, sigrl_len, &mut real_quote_len as *mut u32) };

	if ret != sgx_status_t::SGX_SUCCESS {
		println!("sgx_calc_quote_size returned {}", ret);
		return ret
	}

	println!("quote size = {}", real_quote_len);
	unsafe {
		*p_quote_len = real_quote_len;
	}

	let ret = unsafe {
		sgx_get_quote(
			p_report,
			quote_type,
			p_spid,
			p_nonce,
			p_sigrl,
			sigrl_len,
			p_qe_report,
			p_quote as *mut sgx_quote_t,
			real_quote_len,
		)
	};

	if ret != sgx_status_t::SGX_SUCCESS {
		println!("sgx_calc_quote_size returned {}", ret);
		return ret
	}

	println!("sgx_calc_quote_size returned {}", ret);
	ret
}

/// Ocall: get update info
#[no_mangle]
pub extern "C" fn ocall_get_update_info(
	platform_blob: *const sgx_platform_info_t,
	enclave_trusted: i32,
	update_info: *mut sgx_update_info_bit_t,
) -> sgx_status_t {
	unsafe { sgx_report_attestation_status(platform_blob, enclave_trusted, update_info) }
}

#[no_mangle]
pub extern "C" fn ocall_get_nts_socket(ret_fd: *mut c_int) -> sgx_status_t {
	let port = DEFAULT_KE_PORT;
	// let hostname = "time.cloudflare.com";
	let hostname = NTS_HOSTNAME;
	let addr = lookup_ipv4(hostname, port);
	println!("{:?}", addr);
	let sock = TcpStream::connect(&addr).expect("[-] Connect tls server failed!");

	unsafe {
		*ret_fd = sock.into_raw_fd();
	}

	sgx_status_t::SGX_SUCCESS
}
