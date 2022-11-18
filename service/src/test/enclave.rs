use log::info;
use sgx_types::sgx_status_t;
use crate::enclave::api::{enclave_init, get_shielding_pubkey};
use crate::enclave::ffi;

#[test]
fn shielding_key_decryption(){
    let enclave = match enclave_init() {
        Ok(r) => {
            info!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            info!("[-] Init Enclave Failed {}!", x.as_str());
            return
        },
    };
    println!("shielding pub key");
    let rsa_pubkey = get_shielding_pubkey(&enclave);
    let plaintext: Vec<u8> =
        "test encrypt text and decrypt cipher".to_string().into_bytes();
    let mut ciphertext: Vec<u8> = Vec::new();
    rsa_pubkey.encrypt_buffer(&plaintext, &mut ciphertext).expect("Encrypt Error");

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut res: u8 = 1;
    unsafe {
        ffi::test_decrypt(
            enclave.geteid(),
            &mut retval,
            plaintext.as_ptr(),
            plaintext.len() as u32,
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            &mut res,
        );
    };
    assert_eq!(res, 0, "Decrypted message does not match original!");
    assert_eq!(retval, sgx_status_t::SGX_SUCCESS, "SGX ECall is not successful!")
}