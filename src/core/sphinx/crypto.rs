// Copyright 2022 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Sphinx crypto primitives

use aes::{
	cipher::{generic_array::GenericArray, NewCipher, StreamCipher as AesStreamCipher},
	Aes128Ctr,
};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type LionessCipher = lioness::LionessDefault;

/// the key size of the MAC in bytes
pub const MAC_KEY_SIZE: usize = 32;

/// the output size of the MAC in bytes.
pub const MAC_SIZE: usize = 16;

/// the key size of the stream cipher in bytes.
pub const STREAM_KEY_SIZE: usize = 16;

/// the IV size of the stream cipher in bytes.
pub const STREAM_IV_SIZE: usize = 16;

/// the key size of the SPRP in bytes.
pub const SPRP_KEY_SIZE: usize = lioness::RAW_KEY_SIZE;

pub const KEY_SIZE: usize = 32;

/// the size of the DH group element in bytes.
pub const GROUP_ELEMENT_SIZE: usize = KEY_SIZE;

const KDF_OUTPUT_SIZE: usize =
	MAC_KEY_SIZE + STREAM_KEY_SIZE + STREAM_IV_SIZE + SPRP_KEY_SIZE + KEY_SIZE;

const KDF_INFO_STR: &str = "paritytech-kdf-v0-hkdf-sha256";

/// stream cipher for sphinx crypto usage
pub struct StreamCipher {
	cipher: Aes128Ctr,
}

impl StreamCipher {
	/// create a new StreamCipher struct
	pub fn new(raw_key: &[u8; STREAM_KEY_SIZE], raw_iv: &[u8; STREAM_IV_SIZE]) -> StreamCipher {
		let key = GenericArray::from_slice(&raw_key[..]);
		let iv = GenericArray::from_slice(raw_iv);
		StreamCipher { cipher: Aes128Ctr::new(&key, &iv) }
	}

	/// given a key return a cipher stream of length n
	pub fn generate(&mut self, n: usize) -> Vec<u8> {
		let mut output = vec![0u8; n];
		self.cipher.apply_keystream(&mut output);
		output
	}

	pub fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
		dst.copy_from_slice(src);
		self.cipher.apply_keystream(dst);
	}
}

/// PacketKeys are the per-hop Sphinx Packet Keys, derived from the blinded
/// DH key exchange.
pub struct PacketKeys {
	pub header_mac: [u8; MAC_KEY_SIZE],
	pub header_encryption: [u8; STREAM_KEY_SIZE],
	pub header_encryption_iv: [u8; STREAM_IV_SIZE],
	pub payload_encryption: [u8; SPRP_KEY_SIZE],
	pub blinding_factor: [u8; KEY_SIZE],
}

/// kdf takes the input key material and returns the Sphinx Packet keys.
pub fn kdf(input: &[u8; KEY_SIZE]) -> PacketKeys {
	let output = hkdf_expand(input, String::from(KDF_INFO_STR).into_bytes().as_slice());
	let (a1, a2, a3, a4, a5) = array_refs![
		&output,
		MAC_KEY_SIZE,
		STREAM_KEY_SIZE,
		STREAM_IV_SIZE,
		SPRP_KEY_SIZE,
		KEY_SIZE
	];
	PacketKeys {
		header_mac: *a1,
		header_encryption: *a2,
		header_encryption_iv: *a3,
		payload_encryption: *a4,
		blinding_factor: *a5,
	}
}

pub fn hkdf_expand(prk: &[u8], info: &[u8]) -> [u8; KDF_OUTPUT_SIZE] {
	let mut output = [0u8; KDF_OUTPUT_SIZE];
	let hk = Hkdf::<Sha256>::from_prk(prk).unwrap();
	hk.expand(info, &mut output).unwrap();
	output
}

/// hmac returns the hmac of all the data slices using a given key
pub fn hmac_list(key: &[u8; MAC_KEY_SIZE], data: &[&[u8]]) -> [u8; MAC_SIZE] {
	type HmacSha256 = Hmac<Sha256>;
	let mut mac = HmacSha256::new_from_slice(key).unwrap();
	for d in data {
		mac.update(d);
	}
	let mut output = [0u8; MAC_SIZE];
	output.copy_from_slice(&mac.finalize().into_bytes()[..MAC_SIZE]);
	output
}

/// returns the plaintext of the message msg, decrypted via the
/// Sphinx SPRP with a given key.
pub fn sprp_decrypt(key: &[u8; SPRP_KEY_SIZE], mut msg: Vec<u8>) -> Result<Vec<u8>, ()> {
	let cipher = LionessCipher::new_raw(key);
	cipher.decrypt(&mut msg).map_err(|_| ())?;
	Ok(msg)
}

/// returns the ciphertext of the message msg, encrypted via the
/// Sphinx SPRP with a given key.
pub fn sprp_encrypt(key: &[u8; SPRP_KEY_SIZE], mut msg: Vec<u8>) -> Result<Vec<u8>, ()> {
	let cipher = LionessCipher::new_raw(key);
	cipher.encrypt(&mut msg).map_err(|_| ())?;
	Ok(msg)
}
