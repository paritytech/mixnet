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

//! Key exchange, secret derivation, MAC computation, and encryption.

use super::{
	delay::{DelaySeed, DELAY_SEED_SIZE},
	packet::{Actions, KxPublic, Mac, Payload, MAX_HOPS},
};
use arrayref::array_refs;
use arrayvec::ArrayVec;
use blake2::{
	digest::{
		consts::{U16, U32, U64},
		generic_array::{sequence::Concat, GenericArray},
		FixedOutput, Mac as DigestMac,
	},
	Blake2bMac,
};
use c2_chacha::{
	stream_cipher::{NewStreamCipher, SyncStreamCipher},
	ChaCha20,
};
use curve25519_dalek::{
	constants::ED25519_BASEPOINT_TABLE, montgomery::MontgomeryPoint, scalar::Scalar,
	traits::IsIdentity,
};
use lioness::LionessDefault;
use rand::{CryptoRng, Rng};

const KX_BLINDING_FACTOR_PERSONAL: &[u8; 16] = b"sphinx-blind-fac";
const SMALL_DERIVED_SECRETS_PERSONAL: &[u8; 16] = b"sphinx-small-d-s";
const PAYLOAD_ENCRYPTION_KEY_PERSONAL: &[u8; 16] = b"sphinx-pl-en-key";

/// Size in bytes of a [`SharedSecret`].
pub const SHARED_SECRET_SIZE: usize = 32;
/// Either produced by key exchange or shared in a SURB.
pub type SharedSecret = [u8; SHARED_SECRET_SIZE];

////////////////////////////////////////////////////////////////////////////////
// Key exchange
////////////////////////////////////////////////////////////////////////////////

/// Apply X25519 bit clamping to the given raw bytes to produce a scalar for use with Curve25519.
pub fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar {
	scalar[0] &= 248;
	scalar[31] &= 127;
	scalar[31] |= 64;
	Scalar::from_bits(scalar)
}

/// Generate a key-exchange secret key.
pub fn gen_kx_secret(rng: &mut (impl Rng + CryptoRng)) -> Scalar {
	let mut secret = [0; 32];
	rng.fill_bytes(&mut secret);
	clamp_scalar(secret)
}

/// Derive the public key corresponding to a secret key.
pub fn derive_kx_public(kx_secret: &Scalar) -> KxPublic {
	(ED25519_BASEPOINT_TABLE * kx_secret).to_montgomery().to_bytes()
}

fn derive_kx_blinding_factor(kx_public: &KxPublic, kx_shared_secret: &SharedSecret) -> Scalar {
	let kx_public: &GenericArray<_, _> = kx_public.into();
	let key = kx_public.concat((*kx_shared_secret).into());
	let h = Blake2bMac::<U32>::new_with_salt_and_personal(&key, b"", KX_BLINDING_FACTOR_PERSONAL)
		.expect("Key, salt, and personalisation sizes are fixed and small enough");
	clamp_scalar(h.finalize().into_bytes().into())
}

/// Apply the blinding factor to `kx_secret`.
fn blind_kx_secret(kx_secret: &mut Scalar, kx_public: &KxPublic, kx_shared_secret: &SharedSecret) {
	*kx_secret *= derive_kx_blinding_factor(kx_public, kx_shared_secret);
}

/// Apply the blinding factor to `kx_public`.
pub fn blind_kx_public(kx_public: &KxPublic, kx_shared_secret: &SharedSecret) -> KxPublic {
	(MontgomeryPoint(*kx_public) * derive_kx_blinding_factor(kx_public, kx_shared_secret))
		.to_bytes()
}

pub fn derive_kx_shared_secret(kx_public: &KxPublic, kx_secret: &Scalar) -> SharedSecret {
	(MontgomeryPoint(*kx_public) * kx_secret).to_bytes()
}

pub fn kx_shared_secret_is_identity(kx_shared_secret: &SharedSecret) -> bool {
	MontgomeryPoint(*kx_shared_secret).is_identity()
}

/// Generate a public key to go in a packet and the corresponding shared secrets for each hop.
pub fn gen_kx_public_and_shared_secrets(
	kx_public: &mut KxPublic,
	kx_shared_secrets: &mut ArrayVec<SharedSecret, MAX_HOPS>,
	rng: &mut (impl Rng + CryptoRng),
	their_kx_publics: &[KxPublic],
) {
	let mut kx_secret = gen_kx_secret(rng);
	*kx_public = derive_kx_public(&kx_secret);
	let mut kx_public = *kx_public;

	for (i, their_kx_public) in their_kx_publics.iter().enumerate() {
		if i != 0 {
			if i != 1 {
				// An alternative would be to use blind_kx_public, but this is much cheaper
				kx_public = derive_kx_public(&kx_secret);
			}
			blind_kx_secret(
				&mut kx_secret,
				&kx_public,
				kx_shared_secrets.last().expect(
					"On at least second iteration of loop, shared secret pushed every iteration",
				),
			);
		}
		kx_shared_secrets.push(derive_kx_shared_secret(their_kx_public, &kx_secret));
	}
}

////////////////////////////////////////////////////////////////////////////////
// Additional secret derivation
////////////////////////////////////////////////////////////////////////////////

fn derive_secret(derived: &mut [u8], shared_secret: &SharedSecret, personal: &[u8; 16]) {
	for (i, chunk) in derived.chunks_mut(64).enumerate() {
		// This is the construction libsodium uses for crypto_kdf_derive_from_key; see
		// https://doc.libsodium.org/key_derivation/
		let h = Blake2bMac::<U64>::new_with_salt_and_personal(
			shared_secret,
			&i.to_le_bytes(),
			personal,
		)
		.expect("Key, salt, and personalisation sizes are fixed and small enough");
		h.finalize_into(GenericArray::from_mut_slice(chunk));
	}
}

const MAC_KEY_SIZE: usize = 16;
pub type MacKey = [u8; MAC_KEY_SIZE];
const ACTIONS_ENCRYPTION_KEY_SIZE: usize = 32;
pub type ActionsEncryptionKey = [u8; ACTIONS_ENCRYPTION_KEY_SIZE];
const SMALL_DERIVED_SECRETS_SIZE: usize =
	MAC_KEY_SIZE + ACTIONS_ENCRYPTION_KEY_SIZE + DELAY_SEED_SIZE;

pub struct SmallDerivedSecrets([u8; SMALL_DERIVED_SECRETS_SIZE]);

impl SmallDerivedSecrets {
	pub fn new(shared_secret: &SharedSecret) -> Self {
		let mut derived = [0; SMALL_DERIVED_SECRETS_SIZE];
		derive_secret(&mut derived, shared_secret, SMALL_DERIVED_SECRETS_PERSONAL);
		Self(derived)
	}

	fn split(&self) -> (&MacKey, &ActionsEncryptionKey, &DelaySeed) {
		array_refs![&self.0, MAC_KEY_SIZE, ACTIONS_ENCRYPTION_KEY_SIZE, DELAY_SEED_SIZE]
	}

	pub fn mac_key(&self) -> &MacKey {
		self.split().0
	}

	pub fn actions_encryption_key(&self) -> &ActionsEncryptionKey {
		self.split().1
	}

	pub fn delay_seed(&self) -> &DelaySeed {
		self.split().2
	}
}

pub const PAYLOAD_ENCRYPTION_KEY_SIZE: usize = 192;
pub type PayloadEncryptionKey = [u8; PAYLOAD_ENCRYPTION_KEY_SIZE];

pub fn derive_payload_encryption_key(shared_secret: &SharedSecret) -> PayloadEncryptionKey {
	let mut derived = [0; PAYLOAD_ENCRYPTION_KEY_SIZE];
	derive_secret(&mut derived, shared_secret, PAYLOAD_ENCRYPTION_KEY_PERSONAL);
	derived
}

////////////////////////////////////////////////////////////////////////////////
// MAC computation
////////////////////////////////////////////////////////////////////////////////

pub fn compute_mac(actions: &[u8], pad: &[u8], key: &MacKey) -> Mac {
	let mut h = Blake2bMac::<U16>::new_from_slice(key).expect("Key size is fixed and small enough");
	h.update(actions);
	h.update(pad);
	h.finalize().into_bytes().into()
}

pub fn mac_ok(mac: &Mac, actions: &Actions, key: &MacKey) -> bool {
	let mut h = Blake2bMac::<U16>::new_from_slice(key).expect("Key size is fixed and small enough");
	h.update(actions);
	h.verify(mac.into()).is_ok()
}

////////////////////////////////////////////////////////////////////////////////
// Actions encryption
////////////////////////////////////////////////////////////////////////////////

pub fn apply_actions_encryption_keystream(data: &mut [u8], key: &ActionsEncryptionKey) {
	// Key is only used once, so fine for nonce to be 0
	let mut c = ChaCha20::new(key.into(), &[0; 8].into());
	c.apply_keystream(data);
}

pub fn apply_keystream(data: &mut [u8], keystream: &[u8]) {
	for (d, k) in data.iter_mut().zip(keystream) {
		*d ^= *k;
	}
}

////////////////////////////////////////////////////////////////////////////////
// Payload encryption
////////////////////////////////////////////////////////////////////////////////

pub fn encrypt_payload(payload: &mut Payload, key: &PayloadEncryptionKey) {
	let l = LionessDefault::new_raw(key);
	l.encrypt(payload).expect("Payload size is fixed and large enough");
}

pub fn decrypt_payload(payload: &mut Payload, key: &PayloadEncryptionKey) {
	let l = LionessDefault::new_raw(key);
	l.decrypt(payload).expect("Payload size is fixed and large enough");
}
