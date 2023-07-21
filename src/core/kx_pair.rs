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

//! Mixnet key-exchange key pair.

use super::sphinx::{
	clamp_scalar, derive_kx_public, derive_kx_shared_secret, gen_kx_secret, KxPublic, SharedSecret,
};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

pub struct KxPair {
	/// Boxed to avoid leaving copies of the secret key around in memory if `KxPair` is moved.
	secret: Box<Zeroizing<Scalar>>,
	public: KxPublic,
}

impl KxPair {
	pub fn gen(rng: &mut (impl Rng + CryptoRng)) -> Self {
		gen_kx_secret(rng).into()
	}

	pub fn public(&self) -> &KxPublic {
		&self.public
	}

	pub fn exchange(&self, their_public: &KxPublic) -> SharedSecret {
		derive_kx_shared_secret(their_public, self.secret.as_ref())
	}
}

impl From<Scalar> for KxPair {
	fn from(secret: Scalar) -> Self {
		// We box the secret to avoid leaving copies of it in memory when the KxPair is moved. Note
		// that we will likely leave some copies on the stack here; I'm not aware of any good way
		// of avoiding this.
		let secret = Box::new(Zeroizing::new(secret));
		let public = derive_kx_public(secret.as_ref());
		Self { secret, public }
	}
}

impl From<[u8; 32]> for KxPair {
	fn from(secret: [u8; 32]) -> Self {
		clamp_scalar(secret).into()
	}
}
