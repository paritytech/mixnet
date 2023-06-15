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

//! Keystore for Sphinx key-exchange keys.
//!
//! A store is split into two parts: [`KxPublicStore`] and [`KxStore`]. [`KxPublicStore`] provides
//! access to the public keys and is intended to be shared among multiple threads. [`KxStore`]
//! provides access to the secret keys via a key-exchange function and is intended to be used by a
//! single thread.

use super::{
	sessions::SessionIndex,
	sphinx::{
		clamp_scalar, derive_kx_public, derive_kx_shared_secret, gen_kx_secret, KxPublic,
		SharedSecret,
	},
};
use curve25519_dalek::scalar::Scalar;
use parking_lot::Mutex;
use rand::rngs::OsRng;
use std::sync::Arc;
use zeroize::Zeroizing;

struct SessionPublic {
	index: SessionIndex,
	public: KxPublic,
}

struct SessionSecret {
	index: SessionIndex,
	/// Boxed to avoid leaving copies of the secret key around in memory if `SessionSecret` is
	/// moved.
	secret: Box<Zeroizing<Scalar>>,
}

struct KxPublicStoreInner {
	discarded_sessions_before: SessionIndex,
	/// Session public keys.
	session_publics: Vec<SessionPublic>,
	/// Session secret keys not yet added to the main store.
	pending_session_secrets: Vec<SessionSecret>,
}

impl KxPublicStoreInner {
	fn insert(&mut self, index: SessionIndex, secret: Box<Zeroizing<Scalar>>) -> KxPublic {
		let public = derive_kx_public(secret.as_ref());
		self.session_publics.push(SessionPublic { index, public });
		self.pending_session_secrets.push(SessionSecret { index, secret });
		public
	}
}

/// Provides access to public keys. Intended to be shared among multiple threads.
pub struct KxPublicStore(Mutex<KxPublicStoreInner>);

impl KxPublicStore {
	/// Create a new `KxPublicStore`. For testing purposes, the secret key for session 0 can be
	/// explicitly provided; usually it is randomly generated.
	pub fn new(session_0_secret: Option<&[u8; 32]>) -> Self {
		let mut inner = KxPublicStoreInner {
			discarded_sessions_before: 0,
			session_publics: Vec::new(),
			pending_session_secrets: Vec::new(),
		};
		if let Some(secret) = session_0_secret {
			inner.insert(0, Box::new(Zeroizing::new(clamp_scalar(*secret))));
		}
		Self(Mutex::new(inner))
	}

	/// Returns the public key for the specified session, or [`None`] if the key pair was discarded
	/// due to age.
	pub fn public_for_session(&self, index: SessionIndex) -> Option<KxPublic> {
		let mut inner = self.0.lock();

		if index < inner.discarded_sessions_before {
			return None
		}

		for s in &inner.session_publics {
			if s.index == index {
				return Some(s.public)
			}
		}

		// We box the secret to avoid leaving copies of it in memory when the SessionSecret is
		// moved. Note that we will likely leave some copies on the stack here; I'm not aware of
		// any good way of avoiding this.
		Some(inner.insert(index, Box::new(Zeroizing::new(gen_kx_secret(&mut OsRng)))))
	}

	fn discard_sessions_before(&self, index: SessionIndex) {
		let mut inner = self.0.lock();
		if index > inner.discarded_sessions_before {
			inner.discarded_sessions_before = index;
			inner.session_publics.retain(|s| s.index >= index);
			inner.pending_session_secrets.retain(|p| p.index >= index);
		}
	}

	fn take_pending_session_secrets(&self) -> Vec<SessionSecret> {
		let mut inner = self.0.lock();
		std::mem::take(&mut inner.pending_session_secrets)
	}
}

pub struct KxStore {
	discarded_sessions_before: SessionIndex,
	public: Arc<KxPublicStore>,
	session_secrets: Vec<SessionSecret>,
}

impl KxStore {
	pub fn new(public: Arc<KxPublicStore>) -> Self {
		Self { discarded_sessions_before: 0, public, session_secrets: Vec::new() }
	}

	pub fn public(&self) -> &Arc<KxPublicStore> {
		&self.public
	}

	/// Forget the keys for sessions before (but not including) `index`.
	pub fn discard_sessions_before(&mut self, index: SessionIndex) {
		if index > self.discarded_sessions_before {
			self.discarded_sessions_before = index;
			self.public.discard_sessions_before(index);
			self.session_secrets.retain(|s| s.index >= index);
		}
	}

	/// Make secrets created for [`public_for_session`](KxPublicStore::public_for_session) queries
	/// available to [`session_exchange`](Self::session_exchange).
	pub fn add_pending_session_secrets(&mut self) {
		self.session_secrets.extend(self.public.take_pending_session_secrets());
	}

	/// Perform key exchange using the secret key for the specified session.
	pub fn session_exchange(
		&mut self,
		index: SessionIndex,
		their_public: &KxPublic,
	) -> Option<SharedSecret> {
		self.session_secrets
			.iter()
			.find(|s| s.index == index)
			.map(|s| derive_kx_shared_secret(their_public, s.secret.as_ref()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn basic_operation() {
		let their_secret = gen_kx_secret(&mut rand::thread_rng());
		let their_public = derive_kx_public(&their_secret);

		let mut store = KxStore::new(Arc::new(KxPublicStore::new(None)));

		for session_index in 0..2 {
			let our_public = store.public().public_for_session(session_index).unwrap();
			let shared_secret = derive_kx_shared_secret(&our_public, &their_secret);
			store.add_pending_session_secrets();
			assert_eq!(
				shared_secret,
				store.session_exchange(session_index, &their_public).unwrap()
			);
		}

		assert!(store.session_exchange(3, &their_public).is_none());
	}

	#[test]
	fn session_discarding() {
		let mut store = KxStore::new(Arc::new(KxPublicStore::new(None)));
		let public_0 = store.public().public_for_session(0).unwrap();
		assert_eq!(store.public().public_for_session(0), Some(public_0));
		store.discard_sessions_before(1);
		assert_eq!(store.public().public_for_session(0), None);
	}
}
