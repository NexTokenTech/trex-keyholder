use log::*;
use sgx_types::*;
use sgx_urts::SgxEnclave;
/// keep this api free from chain-specific types!
use std::io::{Read, Write};
use std::{fs::File, path::PathBuf};
use tkp_settings::files::{ENCLAVE_FILE, ENCLAVE_TOKEN};

/// init enclave
pub fn enclave_init() -> SgxResult<SgxEnclave> {
	const LEN: usize = 1024;
	let mut launch_token = [0; LEN];
	let mut launch_token_updated = 0;

	// Step 1: try to retrieve the launch token saved by last transaction
	//         if there is no token, then create a new one.
	//
	// try to get the token saved in $HOME */
	let mut home_dir = PathBuf::new();
	let use_token = match dirs::home_dir() {
		Some(path) => {
			info!("[+] Home dir is {}", path.display());
			home_dir = path;
			true
		},
		None => {
			error!("[-] Cannot get home dir");
			false
		},
	};
	let token_file = home_dir.join(ENCLAVE_TOKEN);
	if use_token {
		match File::open(&token_file) {
			Err(_) => {
				info!(
					"[-] Token file {} not found! Will create one.",
					token_file.as_path().to_str().unwrap()
				);
			},
			Ok(mut f) => {
				info!("[+] Open token file success! ");
				match f.read(&mut launch_token) {
					Ok(LEN) => {
						info!("[+] Token file valid!");
					},
					_ => info!("[+] Token file invalid, will create new token file"),
				}
			},
		}
	}

	// Step 2: call sgx_create_enclave to initialize an enclave instance
	// Debug Support: 1 = debug mode, 0 = not debug mode
	#[cfg(not(feature = "production"))]
	let debug = 1;
	#[cfg(feature = "production")]
	let debug = 0;

	let mut misc_attr =
		sgx_misc_attribute_t { secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 }, misc_select: 0 };
	let enclave = SgxEnclave::create(
		ENCLAVE_FILE,
		debug,
		&mut launch_token,
		&mut launch_token_updated,
		&mut misc_attr,
	);

	// Step 3: save the launch token if it is updated
	if use_token && launch_token_updated != 0 {
		// reopen the file with write capability
		match File::create(&token_file) {
			Ok(mut f) => match f.write_all(&launch_token) {
				Ok(()) => info!("[+] Saved updated launch token!"),
				Err(_) => error!("[-] Failed to save updated launch token!"),
			},
			Err(_) => {
				warn!("[-] Failed to save updated enclave token, but doesn't matter");
			},
		}
	}
	enclave
}
