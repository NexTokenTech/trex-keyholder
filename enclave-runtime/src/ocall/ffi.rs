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
use sgx_types::{
	sgx_epid_group_id_t, sgx_platform_info_t, sgx_quote_nonce_t, sgx_quote_sign_type_t,
	sgx_report_t, sgx_spid_t, sgx_status_t, sgx_target_info_t, sgx_update_info_bit_t,
};

extern "C" {
	/// obtain current time from ntp server
	pub fn ocall_time_ntp(
		ret_val: *mut sgx_status_t,
		time: *mut u64
	) -> sgx_status_t;

	/// init quote, used by remote attestation
	pub fn ocall_sgx_init_quote(
		ret_val: *mut sgx_status_t,
		ret_ti: *mut sgx_target_info_t,
		ret_gid: *mut sgx_epid_group_id_t,
	) -> sgx_status_t;

	/// get ias socket, used by remote attestation
	pub fn ocall_get_ias_socket(ret_val: *mut sgx_status_t, ret_fd: *mut i32) -> sgx_status_t;

	/// get quote, used by remote attestation
	pub fn ocall_get_quote(
		ret_val: *mut sgx_status_t,
		p_sigrl: *const u8,
		sigrl_len: u32,
		p_report: *const sgx_report_t,
		quote_type: sgx_quote_sign_type_t,
		p_spid: *const sgx_spid_t,
		p_nonce: *const sgx_quote_nonce_t,
		p_qe_report: *mut sgx_report_t,
		p_quote: *mut u8,
		maxlen: u32,
		p_quote_len: *mut u32,
	) -> sgx_status_t;

	/// get update info, used by remote attestation
	#[allow(unused)]
	pub fn ocall_get_update_info(
		ret_val: *mut sgx_status_t,
		platform_blob: *const sgx_platform_info_t,
		enclave_trusted: i32,
		update_info: *mut sgx_update_info_bit_t,
	) -> sgx_status_t;

	/// get nts socket, used by nts time
	pub fn ocall_get_nts_socket(ret_val: *mut sgx_status_t, ret_fd: *mut i32) -> sgx_status_t;
}
