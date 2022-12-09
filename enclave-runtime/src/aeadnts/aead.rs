// use crate::{
//     generic_array::{typenum::U16, ArrayLength, GenericArray},
//     Error,
// };
// use aes::{Aes128, Aes256};
// use aes_siv::siv::{Siv, IV_SIZE};
// use cmac::Cmac;
// use core::ops::Add;
// use crypto_mac::Mac;
// use ctr::Ctr128;
// use stream_cipher::{NewStreamCipher, SyncStreamCipher};
//
// #[cfg(feature = "alloc")]
// use alloc::vec::Vec;
//
// #[cfg(feature = "pmac")]
// use pmac_crate::Pmac;
//
// /// AES-SIV tags (which have a dual role as the synthetic IV)
// pub type Tag = GenericArray<u8, U16>;
//
// /// An Authenticated Encryption with Associated Data (AEAD) algorithm.
// pub trait Aead {
//     /// Size of a key associated with this AEAD algorithm
//     type KeySize: ArrayLength<u8>;
//
//     /// Size of a MAC tag
//     type TagSize: ArrayLength<u8>;
//
//     /// Create a new AEAD instance
//     ///
//     /// Panics if the key is the wrong length
//     fn new(key: &[u8]) -> Self;
//
//     /// Encrypt the given plaintext in-place, replacing it with the SIV tag and
//     /// ciphertext. Requires a buffer with 16-bytes additional space.
//     ///
//     /// To encrypt data, it is recommended to use this API instead of the lower-level `Siv` API.
//     ///
//     /// # Usage
//     ///
//     /// It's important to note that only the *end* of the buffer will be
//     /// treated as the input plaintext:
//     ///
//     /// ```rust
//     /// let buffer = [0u8; 21];
//     /// let plaintext = &buffer[..buffer.len() - 16];
//     /// ```
//     ///
//     /// In this case, only the *last* 5 bytes are treated as the plaintext,
//     /// since `21 - 16 = 5` (the AES block size is 16-bytes).
//     ///
//     /// The buffer must include an additional 16-bytes of space in which to
//     /// write the SIV tag (at the beginning of the buffer).
//     /// Failure to account for this will leave you with plaintext messages that
//     /// are missing their first 16-bytes!
//     ///
//     /// # Panics
//     ///
//     /// Panics if `plaintext.len()` is less than `M::OutputSize`.
//     /// Panics if `nonce.len()` is greater than `MAX_ASSOCIATED_DATA`.
//     /// Panics if `associated_data.len()` is greater than `MAX_ASSOCIATED_DATA`.
//     fn encrypt_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]);
//
//     /// Decrypt the given ciphertext in-place, authenticating it against the
//     /// synthetic IV included in the message.
//     ///
//     /// To decrypt data, it is recommended to use this API instead of the lower-level `Siv` API.
//     ///
//     /// Returns a slice containing a decrypted message on success.
//     fn decrypt_in_place<'a>(
//         &mut self,
//         nonce: &[u8],
//         associated_data: &[u8],
//         buffer: &'a mut [u8],
//     ) -> Result<&'a [u8], Error>;
//
//     /// Encrypt the given plaintext, allocating and returning a Vec<u8> for the ciphertext
//     #[cfg(feature = "alloc")]
//     fn encrypt(&mut self, nonce: &[u8], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
//         let mut buffer = vec![0; IV_SIZE + plaintext.len()];
//         buffer[IV_SIZE..].copy_from_slice(plaintext);
//         self.encrypt_in_place(nonce, associated_data, &mut buffer);
//         buffer
//     }
//
//     /// Decrypt the given ciphertext, allocating and returning a Vec<u8> for the plaintext
//     #[cfg(feature = "alloc")]
//     fn decrypt(
//         &mut self,
//         nonce: &[u8],
//         associated_data: &[u8],
//         ciphertext: &[u8],
//     ) -> Result<Vec<u8>, Error> {
//         let mut buffer = Vec::from(ciphertext);
//         self.decrypt_in_place(nonce, associated_data, &mut buffer)?;
//         buffer.drain(..IV_SIZE);
//         Ok(buffer)
//     }
// }
//
// /// The `SivAead` type wraps the more powerful `Siv` interface in a more
// /// commonly used Authenticated Encryption with Associated Data (AEAD) API,
// /// which accepts a key, nonce, and associated data when encrypting/decrypting.
// pub struct SivAead<C, M>
//     where
//         C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
//         M: Mac<OutputSize = U16>,
// {
//     siv: Siv<C, M>,
// }
//
// //
// // AES-CMAC-SIV
// //
//
// /// SIV AEAD modes based on CMAC
// pub type CmacSivAead<BlockCipher> = SivAead<Ctr128<BlockCipher>, Cmac<BlockCipher>>;
//
// /// AES-CMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
// pub type Aes128SivAead = CmacSivAead<Aes128>;
//
// /// AES-CMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
// pub type Aes256SivAead = CmacSivAead<Aes256>;
//
// //
// // AES-PMAC-SIV
// //
//
// /// SIV AEAD modes based on PMAC
// #[cfg(feature = "pmac")]
// pub type PmacSivAead<BlockCipher> = SivAead<Ctr128<BlockCipher>, Pmac<BlockCipher>>;
//
// /// AES-PMAC-SIV in AEAD mode with 256-bit key size (128-bit security)
// #[cfg(feature = "pmac")]
// pub type Aes128PmacSivAead = PmacSivAead<Aes128>;
//
// /// AES-PMAC-SIV in AEAD mode with 512-bit key size (256-bit security)
// #[cfg(feature = "pmac")]
// pub type Aes256PmacSivAead = PmacSivAead<Aes256>;
//
// impl<C, M> Aead for SivAead<C, M>
//     where
//         C: NewStreamCipher<NonceSize = U16> + SyncStreamCipher,
//         M: Mac<OutputSize = U16>,
//         C::KeySize: Add,
//         <C::KeySize as Add>::Output: ArrayLength<u8>,
// {
//     type KeySize = <C as NewStreamCipher>::KeySize;
//     type TagSize = U16;
//
//     fn new(key: &[u8]) -> Self {
//         Self {
//             siv: Siv::new(GenericArray::clone_from_slice(key)),
//         }
//     }
//
//     fn encrypt_in_place(&mut self, nonce: &[u8], associated_data: &[u8], buffer: &mut [u8]) {
//         assert!(buffer.len() >= IV_SIZE, "no space for IV in buffer");
//         let tag = self
//             .siv
//             .encrypt_in_place_detached(&[associated_data, nonce], &mut buffer[IV_SIZE..])
//             .expect("encryption failure!");
//
//         buffer[..IV_SIZE].copy_from_slice(&tag);
//     }
//
//     fn decrypt_in_place<'a>(
//         &mut self,
//         nonce: &[u8],
//         associated_data: &[u8],
//         buffer: &'a mut [u8],
//     ) -> Result<&'a [u8], Error> {
//         if buffer.len() < IV_SIZE {
//             return Err(Error);
//         }
//
//         let tag = Tag::clone_from_slice(&buffer[..IV_SIZE]);
//         self.siv.decrypt_in_place_detached(
//             &[associated_data, nonce],
//             &mut buffer[IV_SIZE..],
//             &tag,
//         )?;
//         Ok(&buffer[IV_SIZE..])
//     }
// }