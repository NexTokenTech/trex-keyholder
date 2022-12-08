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

use crate::ocall::ffi;
use crate::records::{
	deserialize,
	gen_key,
	process_record,

	// Functions.
	serialize,
	// Records.
	AeadAlgorithmRecord,
	// Errors.
	DeserializeError,

	EndOfMessageRecord,

	// Enums.
	KnownAeadAlgorithm,
	KnownNextProtocol,
	NTSKeys,
	NextProtocolRecord,
	NtsKeParseError,
	Party,

	// Structs.
	ReceivedNtsKeRecordState,

	// Constants.
	HEADER_SIZE,
};
use log::*;
use rand::Rng;
use sgx_tcrypto::*;
use sgx_tse::*;
use sgx_types::{SGX_RSA3072_KEY_SIZE, *};
use sp_core::{blake2_256, Decode, Encode, Pair};
use std::{
	error::Error,
	fmt,
	io::{Read, Write},
	net::{Shutdown, TcpStream},
	prelude::v1::*,
	ptr, slice, str,
	string::String,
	sync::Arc,
	untrusted::fs,
	vec::Vec,
};
use webpki;
use webpki_roots;

use std::{
	net::{ToSocketAddrs, UdpSocket},
	time::{Duration, SystemTime},
	untrusted::time::SystemTimeEx,
};

use crate::nts_protocol::protocol::{
	parse_nts_packet, serialize_nts_packet, LeapState, NtpExtension, NtpExtensionType::*,
	NtpPacketHeader, NtsPacket, PacketMode::Client, TWO_POW_32, UNIX_OFFSET,
};

use aes_siv::{aead::generic_array::GenericArray, Aes128SivAead, KeyInit};

use self::NtpClientError::*;

const BUFF_SIZE: usize = 2048;

pub struct NtpResult {
	pub stratum: u8,
	pub time_diff: f64,
}

#[derive(Debug, Clone)]
pub enum NtpClientError {
	NoIpv4AddrFound,
	NoIpv6AddrFound,
	InvalidUid,
}

const DEFAULT_NTP_PORT: u16 = 123;
const DEFAULT_KE_PORT: u16 = 4460;
const DEFAULT_SCHEME: u16 = 0;
const TIMEOUT: Duration = Duration::from_secs(15);
pub const NTS_HOSTNAME: &'static str = "time.cloudflare.com";

type Cookie = Vec<u8>;

#[derive(Clone, Debug)]
pub struct NtsKeResult {
	pub cookies: Vec<Cookie>,
	pub next_protocols: Vec<u16>,
	pub aead_scheme: u16,
	pub next_server: String,
	pub next_port: u16,
	pub keys: NTSKeys,
	pub use_ipv4: Option<bool>,
}

impl Error for NtpClientError {
	fn description(&self) -> &str {
		match self {
			_ => "Connection to server failed because address could not be resolved",
		}
	}
	fn cause(&self) -> Option<&dyn Error> {
		None
	}
}

impl std::fmt::Display for NtpClientError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "Ntp Client Error ")
	}
}

/// Returns a float representing the system time as NTP
fn system_to_ntpfloat(time: SystemTime) -> f64 {
	let unix_time = time.duration_since(SystemTime::UNIX_EPOCH).unwrap(); // Safe absent time machines
	let unix_offset = Duration::new(UNIX_OFFSET, 0);
	let epoch_time = unix_offset + unix_time;
	epoch_time.as_secs() as f64 + (epoch_time.subsec_nanos() as f64) / 1.0e9
}

/// Returns a float representing the ntp timestamp
fn timestamp_to_float(time: u64) -> f64 {
	let ts_secs = time >> 32;
	let ts_frac = time - (ts_secs << 32);
	(ts_secs as f64) + (ts_frac as f64) / TWO_POW_32
}

#[no_mangle]
pub unsafe extern "C" fn obtain_nts_time() -> sgx_status_t {
	let res = run_nts_ke_client();

	let state = res.unwrap();

	let res = run_nts_ntp_client(state);
	match res {
		Err(err) => {
			debug!("failure of client: {}", err);
			// process::exit(1)
		},
		Ok(result) => {
			println!("stratum: {:}", result.stratum);
			println!("offset: {:.6}", result.time_diff);
		},
	}

	sgx_status_t::SGX_SUCCESS
}

pub fn run_nts_ke_client() -> Result<NtsKeResult, Box<dyn Error>> {
	let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
	// (1.5) get sigrl
	let mut nts_sock: i32 = 0;

	let res = unsafe {
		ffi::ocall_get_nts_socket(&mut rt as *mut sgx_status_t, &mut nts_sock as *mut i32)
	};

	if res != sgx_status_t::SGX_SUCCESS {
		debug!("{:?}", res);
	}

	if rt != sgx_status_t::SGX_SUCCESS {
		debug!("{:?}", rt);
	}

	let mut tls_config = rustls::ClientConfig::new();
	let alpn_proto = String::from("ntske/1");
	let alpn_bytes = alpn_proto.into_bytes();
	tls_config.set_protocols(&[alpn_bytes]);
	tls_config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

	let rc_config = Arc::new(tls_config);
	let hostname = webpki::DNSNameRef::try_from_ascii_str(NTS_HOSTNAME).unwrap();
	let mut client = rustls::ClientSession::new(&rc_config, hostname);

	let mut sock = TcpStream::new(nts_sock).unwrap();
	let mut tls_stream = rustls::Stream::new(&mut client, &mut sock);

	let next_protocol_record = NextProtocolRecord::from(vec![KnownNextProtocol::Ntpv4]);
	let aead_record = AeadAlgorithmRecord::from(vec![KnownAeadAlgorithm::AeadAesSivCmac256]);
	let end_record = EndOfMessageRecord;

	let clientrec = &mut serialize(next_protocol_record);
	clientrec.append(&mut serialize(aead_record));
	clientrec.append(&mut serialize(end_record));
	tls_stream.write(clientrec).unwrap();
	tls_stream.flush().unwrap();
	let keys = gen_key(tls_stream.sess).unwrap();

	let mut state = ReceivedNtsKeRecordState {
		finished: false,
		next_protocols: Vec::new(),
		aead_scheme: Vec::new(),
		cookies: Vec::new(),
		next_server: None,
		next_port: None,
	};

	while !state.finished {
		let mut header: [u8; HEADER_SIZE] = [0; HEADER_SIZE];

		// We should use `read_exact` here because we always need to read 4 bytes to get the
		// header.
		if let Err(error) = tls_stream.read_exact(&mut header[..]) {
			debug!("tls stream read exact error:{:?}", error);
		}

		// Retrieve a body length from the 3rd and 4th bytes of the header.
		let body_length = u16::from_be_bytes([header[2], header[3]]);
		let mut body = vec![0; body_length as usize];

		// `read_exact` the length of the body.
		if let Err(error) = tls_stream.read_exact(body.as_mut_slice()) {
			debug!("tls stream read exact error:{:?}", error);
		}

		// Reconstruct the whole record byte array to let the `records` module deserialize it.
		let mut record_bytes = Vec::from(&header[..]);
		record_bytes.append(&mut body);

		// `deserialize` has an invariant that the slice needs to be long enough to make it a
		// valid record, which in this case our slice is exactly as long as specified in the
		// length field.
		match deserialize(Party::Client, record_bytes.as_slice()) {
			Ok(record) => {
				let status = process_record(record, &mut state);
				match status {
					Ok(_) => {},
					Err(err) => {
						debug!("{:?}", err);
					},
				}
			},
			Err(DeserializeError::UnknownNotCriticalRecord) => {
				// If it's not critical, just ignore the error.
				debug!("unknown record type");
			},
			Err(DeserializeError::UnknownCriticalRecord) => {
				// TODO: This should propertly handled by sending an Error record.
				debug!("error: unknown critical record");
			},
			Err(DeserializeError::Parsing(error)) => {
				// TODO: This shouldn't be wrapped as a trait object.
				debug!("error: {}", error);
			},
		}
	}
	debug!("saw the end of the response");
	match sock.shutdown(Shutdown::Write) {
		Ok(_) => {},
		Err(err) => {
			debug!("stream shut down error:{:?}", err);
		},
	};

	let aead_scheme =
		if state.aead_scheme.is_empty() { DEFAULT_SCHEME } else { state.aead_scheme[0] };

	let state = NtsKeResult {
		aead_scheme,
		cookies: state.cookies,
		next_protocols: state.next_protocols,
		next_server: state.next_server.unwrap_or(NTS_HOSTNAME.to_string()),
		next_port: state.next_port.unwrap_or(DEFAULT_NTP_PORT),
		keys,
		use_ipv4: Some(true),
	};
	Ok(state)
}

/// Run the NTS client with the given data from key exchange
pub fn run_nts_ntp_client(state: NtsKeResult) -> Result<NtpResult, Box<dyn Error>> {
	let mut ip_addrs = (state.next_server.as_str(), state.next_port).to_socket_addrs()?;
	let addr;
	let socket;
	if let Some(use_ipv4) = state.use_ipv4 {
		if use_ipv4 {
			// mandated to use ipv4
			addr = ip_addrs.find(|&x| x.is_ipv4());
			if addr == None {
				return Err(Box::new(NoIpv4AddrFound))
			}
			socket = UdpSocket::bind("0.0.0.0:0");
		} else {
			// mandated to use ipv6
			addr = ip_addrs.find(|&x| x.is_ipv6());
			if addr == None {
				return Err(Box::new(NoIpv6AddrFound))
			}
			socket = UdpSocket::bind("[::]:0");
		}
	} else {
		// sniff whichever one is supported
		addr = ip_addrs.next();
		// check if this address is ipv4 or ipv6
		if addr.unwrap().is_ipv6() {
			socket = UdpSocket::bind("[::]:0");
		} else {
			socket = UdpSocket::bind("0.0.0.0:0");
		}
	}
	let socket = socket.expect("Cannot create an udp socket!");
	socket.set_read_timeout(Some(TIMEOUT))?;
	socket.set_write_timeout(Some(TIMEOUT))?;
	let mut send_aead = Aes128SivAead::new(GenericArray::from_slice(&state.keys.c2s));
	let mut recv_aead = Aes128SivAead::new(GenericArray::from_slice(&state.keys.s2c));
	let header = NtpPacketHeader {
		leap_indicator: LeapState::NoLeap,
		version: 4,
		mode: Client,
		stratum: 0,
		poll: 0,
		precision: 0x20,
		root_delay: 0,
		root_dispersion: 0,
		reference_id: 0,
		reference_timestamp: 0xdeadbeef,
		origin_timestamp: 0,
		receive_timestamp: 0,
		transmit_timestamp: 0,
	};
	let mut unique_id: Vec<u8> = vec![0; 32];
	rand::thread_rng().fill(&mut unique_id[..]);
	let exts = vec![
		NtpExtension { ext_type: UniqueIdentifier, contents: unique_id.clone() },
		NtpExtension { ext_type: NTSCookie, contents: state.cookies[0].clone() },
	];
	let packet = NtsPacket { header, auth_exts: exts, auth_enc_exts: vec![] };
	socket.connect(addr.unwrap())?;
	let wire_packet = &serialize_nts_packet::<Aes128SivAead>(packet, &mut send_aead);
	let t1 = system_to_ntpfloat(SystemTime::now());
	socket.send(wire_packet)?;
	debug!("transmitting packet");
	let mut buff = [0; BUFF_SIZE];
	let (size, _origin) = socket.recv_from(&mut buff)?;
	let t4 = system_to_ntpfloat(SystemTime::now());
	debug!("received packet");
	let received = parse_nts_packet::<Aes128SivAead>(&buff[0..size], &mut recv_aead);
	match received {
		Err(x) => Err(Box::new(x)),
		Ok(packet) => {
			// check if server response contains the same UniqueIdentifier as client request
			let resp_unique_id = packet.auth_exts[0].clone().contents;
			if resp_unique_id != unique_id {
				return Err(Box::new(InvalidUid))
			}

			Ok(NtpResult {
				stratum: packet.header.stratum,
				time_diff: ((timestamp_to_float(packet.header.receive_timestamp) - t1)
					+ (timestamp_to_float(packet.header.transmit_timestamp) - t4))
					/ 2.0,
			})
		},
	}
}
