/*
	Copyright 2022 NexToken Tech LLC
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::{cert, hex, ocall::ffi};
use core::default::Default;
use itertools::Itertools;

use crate::{
	get_rsa_encryption_pubkey, utils::node_metadata::NodeMetadata, write_slice_and_whitespace_pad,
	Error, NODE_META_DATA,
};
use log::*;
use sgx_rand::*;
use sgx_tcrypto::*;
use sgx_tse::*;
use sgx_types::{SGX_RSA3072_KEY_SIZE, *};
use sp_core::{blake2_256, Decode, Encode, Pair};
use std::{
	io::{Read, Write},
	net::TcpStream,
	prelude::v1::*,
	ptr, slice, str,
	string::String,
	sync::Arc,
	untrusted::fs,
	vec::Vec,
};
#[allow(unused)]
pub use substrate_api_client::{
	compose_extrinsic_offline, ExtrinsicParams, PlainTip, PlainTipExtrinsicParams,
	PlainTipExtrinsicParamsBuilder, SubstrateDefaultSignedExtra, UncheckedExtrinsicV4,
};
use tkp_settings::files::{RA_API_KEY_FILE, RA_SPID_FILE};
use tkp_sgx_crypto::Ed25519Seal;
use tkp_sgx_io::StaticSealedIO;

pub const DEV_HOSTNAME: &'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &'static str = "/sgx/dev/attestation/v4/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v4/report";

pub type Hash = sp_core::H256;
pub fn hash_from_slice(hash_slize: &[u8]) -> Hash {
	let mut g = [0; 32];
	g.copy_from_slice(hash_slize);
	Hash::from(&mut g)
}

#[no_mangle]
pub unsafe extern "C" fn perform_ra(
	genesis_hash: *const u8,
	genesis_hash_size: u32,
	nonce: *const u32,
	w_url: *const u8,
	w_url_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	// our certificate is unlinkable
	let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;

	let chain_signer = Ed25519Seal::unseal_from_static_file().unwrap();
	info!("[Enclave Attestation] Ed25519 pub raw : {:?}", chain_signer.public().0);

	// Generate Keypair
	let ecc_handle = SgxEccHandle::new();
	let _result = ecc_handle.open();
	let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

	let (attn_report, sig, cert) = match create_attestation_report(&chain_signer.public().0, sign_type) {
		Ok(r) => {
			println!("Success in create_attestation_report: {:?}", r);
			r
		},
		Err(e) => {
			debug!("Error in create_attestation_report: {:?}", e);
			return e
		},
	};

	let payload = attn_report + "|" + &sig + "|" + &cert;
	let (_key_der, cert_der) = match cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
		Ok(r) => r,
		Err(e) => {
			debug!("Error in gen_ecc_cert: {:?}", e);
			return e
		},
	};
	let _result = ecc_handle.close();

	debug!("[Enclave] Compose extrinsic");
	let genesis_hash_slice = slice::from_raw_parts(genesis_hash, genesis_hash_size as usize);
	//let mut nonce_slice     = slice::from_raw_parts(nonce, nonce_size as usize);
	let url_slice = slice::from_raw_parts(w_url, w_url_size as usize);
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);
	let signer = match Ed25519Seal::unseal_from_static_file() {
		Ok(pair) => pair,
		Err(e) => return e.into(),
	};
	info!("[Enclave] Restored ECC pubkey: {:?}", signer.public());

	debug!("decoded nonce: {}", *nonce);
	let genesis_hash = hash_from_slice(genesis_hash_slice);
	debug!("decoded genesis_hash: {:?}", genesis_hash_slice);
	debug!("worker url: {}", str::from_utf8(url_slice).unwrap());

	let node_metadata_slice_mem = NODE_META_DATA.lock().unwrap();

	let mut metadata_slice: Vec<u8> = Vec::<u8>::new();
	for (_, item) in node_metadata_slice_mem.iter().enumerate() {
		metadata_slice.push(*item);
	}
	let metadata = match NodeMetadata::decode(&mut metadata_slice.as_slice()).map_err(Error::Codec)
	{
		Err(e) => {
			error!("Failed to decode node metadata: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
		Ok(m) => m,
	};

	let (register_enclave_call, runtime_spec_version, runtime_transaction_version) = (
		metadata.call_indexes("Tee", "register_enclave"),
		metadata.get_runtime_version(),
		metadata.get_runtime_transaction_version(),
	);

	let call =
		match register_enclave_call {
			Ok(c) => c,
			Err(e) => {
				error!("Failed to get the indexes for the register_enclave call from the metadata: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		};

	let extrinsic_params = PlainTipExtrinsicParams::new(
		runtime_spec_version,
		runtime_transaction_version,
		*nonce,
		genesis_hash,
		PlainTipExtrinsicParamsBuilder::default(),
	);
	// Generate shielding pubkey. This vector contains two parts, the first part is rsa modules
	// (384 bytes), the second part is the public exponent (4 bytes).
	let pubkey_size = SGX_RSA3072_KEY_SIZE + SGX_RSA3072_PUB_EXP_SIZE;
	let mut pubkey = vec![0u8; pubkey_size as usize];
	get_rsa_encryption_pubkey(pubkey.as_mut_ptr(), pubkey.len() as u32);
	info!("RSA pub key: {:?}", pubkey);
	#[allow(clippy::redundant_clone)]
	let xt = compose_extrinsic_offline!(
		signer,
		(call, cert_der.to_vec(), url_slice.to_vec(), pubkey.to_vec()),
		extrinsic_params
	);

	let xt_encoded = xt.encode();
	let xt_hash = blake2_256(&xt_encoded);
	debug!("[Enclave] Encoded extrinsic ( len = {} B), hash {:?}", xt_encoded.len(), xt_hash);

	match write_slice_and_whitespace_pad(extrinsic_slice, xt_encoded) {
		Ok(_) => {},
		Err(e) => {
			println!("Result Error {:?}", e);
		},
	};

	sgx_status_t::SGX_SUCCESS
}

/// remote attestation report
fn parse_response_attn_report(resp: &[u8]) -> (String, String, String) {
	debug!("parse_response_attn_report");
	let mut headers = [httparse::EMPTY_HEADER; 16];
	let mut respp = httparse::Response::new(&mut headers);
	let result = respp.parse(resp);
	debug!("parse result {:?}", result);

	let msg: &'static str;

	match respp.code {
		Some(200) => msg = "OK Operation Successful",
		Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
		Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
		Some(500) => msg = "Internal error occurred",
		Some(503) =>
			msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. ",
		_ => {
			debug!("DBG:{}", respp.code.unwrap());
			msg = "Unknown error occured"
		},
	}

	debug!("{}", msg);
	let mut len_num: u32 = 0;

	let mut sig = String::new();
	let mut cert = String::new();
	let mut attn_report = String::new();

	for i in 0..respp.headers.len() {
		let h = respp.headers[i];
		//debug!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
		match h.name {
			"Content-Length" => {
				let len_str = String::from_utf8(h.value.to_vec()).unwrap();
				len_num = len_str.parse::<u32>().unwrap();
				debug!("content length = {}", len_num);
			},
			"X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
			"X-IASReport-Signing-Certificate" =>
				cert = str::from_utf8(h.value).unwrap().to_string(),
			_ => (),
		}
	}

	// Remove %0A from cert, and only obtain the signing cert
	cert = cert.replace("%0A", "");
	cert = cert::percent_decode(cert);
	let v: Vec<&str> = cert.split("-----").collect();
	let sig_cert = v[2].to_string();

	if len_num != 0 {
		let header_len = result.unwrap().unwrap();
		let resp_body = &resp[header_len..];
		attn_report = str::from_utf8(resp_body).unwrap().to_string();
		debug!("Attestation report: {}", attn_report);
	}

	// len_num == 0
	(attn_report, sig, sig_cert)
}

fn parse_response_sigrl(resp: &[u8]) -> Vec<u8> {
	debug!("parse_response_sigrl");
	let mut headers = [httparse::EMPTY_HEADER; 16];
	let mut respp = httparse::Response::new(&mut headers);
	let result = respp.parse(resp);
	debug!("parse result {:?}", result);
	debug!("parse response{:?}", respp);

	let msg: &'static str;

	match respp.code {
		Some(200) => msg = "OK Operation Successful",
		Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
		Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
		Some(500) => msg = "Internal error occurred",
		Some(503) =>
			msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. ",
		_ => msg = "Unknown error occured",
	}

	debug!("{}", msg);
	let mut len_num: u32 = 0;

	for i in 0..respp.headers.len() {
		let h = respp.headers[i];
		if h.name == "content-length" {
			let len_str = String::from_utf8(h.value.to_vec()).unwrap();
			len_num = len_str.parse::<u32>().unwrap();
			debug!("content length = {}", len_num);
		}
	}

	if len_num != 0 {
		let header_len = result.unwrap().unwrap();
		let resp_body = &resp[header_len..];
		debug!("Base64-encoded SigRL: {:?}", resp_body);

		return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap()
	}

	// len_num == 0
	Vec::new()
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
	let mut config = rustls::ClientConfig::new();

	config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

	config
}

pub fn get_sigrl_from_intel(fd: c_int, gid: u32) -> Vec<u8> {
	debug!("get_sigrl_from_intel fd = {:?}", fd);
	let config = make_ias_client_config();
	//let sigrl_arg = SigRLArg { group_id : gid };
	//let sigrl_req = sigrl_arg.to_httpreq();
	let ias_key = get_ias_api_key();

	let req = format!("GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
                      SIGRL_SUFFIX,
                      gid,
                      DEV_HOSTNAME,
                      ias_key);
	debug!("{}", req);

	let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
	let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
	let mut sock = TcpStream::new(fd).unwrap();
	let mut tls = rustls::Stream::new(&mut sess, &mut sock);

	let _result = tls.write(req.as_bytes());
	let mut plaintext = Vec::new();

	debug!("write complete");

	match tls.read_to_end(&mut plaintext) {
		Ok(_) => (),
		Err(e) => {
			debug!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
			panic!("haha");
		},
	}
	debug!("read_to_end complete");
	let resp_string = String::from_utf8(plaintext.clone()).unwrap();

	debug!("{}", resp_string);

	parse_response_sigrl(&plaintext)
}

// TODO: support pse
pub fn get_report_from_intel(fd: c_int, quote: Vec<u8>) -> (String, String, String) {
	debug!("get_report_from_intel fd = {:?}", fd);
	let config = make_ias_client_config();
	let encoded_quote = base64::encode(&quote[..]);
	let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

	let ias_key = get_ias_api_key();

	let req = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                      REPORT_SUFFIX,
                      DEV_HOSTNAME,
                      ias_key,
                      encoded_json.len(),
                      encoded_json);
	debug!("{}", req);
	let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
	let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
	let mut sock = TcpStream::new(fd).unwrap();
	let mut tls = rustls::Stream::new(&mut sess, &mut sock);

	let _result = tls.write(req.as_bytes());
	let mut plaintext = Vec::new();

	debug!("write complete");

	tls.read_to_end(&mut plaintext).unwrap();
	debug!("read_to_end complete");
	let resp_string = String::from_utf8(plaintext.clone()).unwrap();

	debug!("resp_string = {}", resp_string);

	let (attn_report, sig, cert) = parse_response_attn_report(&plaintext);

	(attn_report, sig, cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
	((array[0] as u32) << 0)
		+ ((array[1] as u32) << 8)
		+ ((array[2] as u32) << 16)
		+ ((array[3] as u32) << 24)
}

#[allow(const_err)]
pub fn create_attestation_report(
	pub_k: &[u8; 32],
	sign_type: sgx_quote_sign_type_t,
) -> Result<(String, String, String), sgx_status_t> {
	// Workflow:
	// (1) ocall to get the target_info structure (ti) and epid group id (eg)
	// (1.5) get sigrl
	// (2) call sgx_create_report with ti+data, produce an sgx_report_t
	// (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

	// (1) get ti + eg
	let mut ti: sgx_target_info_t = sgx_target_info_t::default();
	let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
	let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

	let res = unsafe {
		ffi::ocall_sgx_init_quote(
			&mut rt as *mut sgx_status_t,
			&mut ti as *mut sgx_target_info_t,
			&mut eg as *mut sgx_epid_group_id_t,
		)
	};

	debug!("eg = {:?}", eg);

	if res != sgx_status_t::SGX_SUCCESS {
		return Err(res)
	}

	if rt != sgx_status_t::SGX_SUCCESS {
		return Err(rt)
	}

	let eg_num = as_u32_le(&eg);

	// (1.5) get sigrl
	let mut ias_sock: i32 = 0;

	let res = unsafe {
		ffi::ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32)
	};

	if res != sgx_status_t::SGX_SUCCESS {
		return Err(res)
	}

	if rt != sgx_status_t::SGX_SUCCESS {
		return Err(rt)
	}

	//debug!("Got ias_sock = {}", ias_sock);

	// Now sigrl_vec is the revocation list, a vec<u8>
	let sigrl_vec: Vec<u8> = get_sigrl_from_intel(ias_sock, eg_num);

	// (2) Generate the report
	let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
	report_data.d[..32].clone_from_slice(&pub_k[..]);
	// Fill ecc256 public key into report_data
	// let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
	// let mut pub_k_gx = pub_k.gx.clone();
	// pub_k_gx.reverse();
	// let mut pub_k_gy = pub_k.gy.clone();
	// pub_k_gy.reverse();
	// report_data.d[..32].clone_from_slice(&pub_k_gx);
	// report_data.d[32..].clone_from_slice(&pub_k_gy);

	let rep = match rsgx_create_report(&ti, &report_data) {
		Ok(r) => {
			debug!("Report creation => success {:?}", r.body.mr_signer.m);
			Some(r)
		},
		Err(e) => {
			debug!("Report creation => failed {:?}", e);
			None
		},
	};

	let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
	let mut os_rng = os::SgxRng::new().unwrap();
	os_rng.fill_bytes(&mut quote_nonce.rand);
	debug!("rand finished");
	let mut qe_report = sgx_report_t::default();
	const RET_QUOTE_BUF_LEN: u32 = 2048;
	let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
	let mut quote_len: u32 = 0;

	// (3) Generate the quote
	// Args:
	//       1. sigrl: ptr + len
	//       2. report: ptr 432bytes
	//       3. linkable: u32, unlinkable=0, linkable=1
	//       4. spid: sgx_spid_t ptr 16bytes
	//       5. sgx_quote_nonce_t ptr 16bytes
	//       6. p_sig_rl + sigrl size ( same to sigrl)
	//       7. [out]p_qe_report need further check
	//       8. [out]p_quote
	//       9. quote_size
	let (p_sigrl, sigrl_len) = if sigrl_vec.len() == 0 {
		(ptr::null(), 0)
	} else {
		(sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
	};
	let p_report = (&rep.unwrap()) as *const sgx_report_t;
	let quote_type = sign_type;

	let spid: sgx_spid_t = load_spid(RA_SPID_FILE);

	let p_spid = &spid as *const sgx_spid_t;
	let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
	let p_qe_report = &mut qe_report as *mut sgx_report_t;
	let p_quote = return_quote_buf.as_mut_ptr();
	let maxlen = RET_QUOTE_BUF_LEN;
	let p_quote_len = &mut quote_len as *mut u32;

	let result = unsafe {
		ffi::ocall_get_quote(
			&mut rt as *mut sgx_status_t,
			p_sigrl,
			sigrl_len,
			p_report,
			quote_type,
			p_spid,
			p_nonce,
			p_qe_report,
			p_quote,
			maxlen,
			p_quote_len,
		)
	};

	if result != sgx_status_t::SGX_SUCCESS {
		return Err(result)
	}

	if rt != sgx_status_t::SGX_SUCCESS {
		debug!("ocall_get_quote returned {}", rt);
		return Err(rt)
	}

	// Added 09-28-2018
	// Perform a check on qe_report to verify if the qe_report is valid
	match rsgx_verify_report(&qe_report) {
		Ok(()) => debug!("rsgx_verify_report passed!"),
		Err(x) => {
			debug!("rsgx_verify_report failed with {:?}", x);
			return Err(x)
		},
	}

	// Check if the qe_report is produced on the same platform
	if ti.mr_enclave.m != qe_report.body.mr_enclave.m
		|| ti.attributes.flags != qe_report.body.attributes.flags
		|| ti.attributes.xfrm != qe_report.body.attributes.xfrm
	{
		debug!("qe_report does not match current target_info!");
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	debug!("qe_report check passed");

	// Debug
	// for i in 0..quote_len {
	//     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
	// }
	// debug!("");

	// Check qe_report to defend against replay attack
	// The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
	// it received is not modified by the untrusted SW stack, and not a replay.
	// The implementation in QE is to generate a REPORT targeting the ISV
	// enclave (target info from p_report) , with the lower 32Bytes in
	// report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
	// p_qe_report and report.data to confirm the QUOTE has not be modified and
	// is not a replay. It is optional.

	let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
	rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
	let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
	let lhs_hash = &qe_report.body.report_data.d[..32];

	debug!("rhs hash = {:02X}", rhs_hash.iter().format(""));
	debug!("report hs= {:02X}", lhs_hash.iter().format(""));

	if rhs_hash != lhs_hash {
		debug!("Quote is tampered!");
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	let quote_vec: Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
	let res = unsafe {
		ffi::ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32)
	};

	if res != sgx_status_t::SGX_SUCCESS {
		return Err(res)
	}

	if rt != sgx_status_t::SGX_SUCCESS {
		return Err(rt)
	}

	let (attn_report, sig, cert) = get_report_from_intel(ias_sock, quote_vec);
	Ok((attn_report, sig, cert))
}

fn load_spid(filename: &str) -> sgx_spid_t {
	let mut spidfile = fs::File::open(filename).expect("cannot open spid file");
	let mut contents = String::new();
	spidfile.read_to_string(&mut contents).expect("cannot read the spid file");

	hex::decode_spid(&contents)
}

fn get_ias_api_key() -> String {
	let mut keyfile = fs::File::open(RA_API_KEY_FILE).expect("cannot open ias key file");
	let mut key = String::new();
	keyfile.read_to_string(&mut key).expect("cannot read the ias key file");

	key.trim_end().to_owned()
}
