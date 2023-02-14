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
//! A store is split into two parts: `KxPublicStore` and `KxStore`. `KxPublicStore` provides access
//! to the public keys and is intended to be shared among multiple threads. `KxStore` provides
//! access to the secret keys via a key-exchange function and is intended to be used by a single
//! thread.

use super::{
	sessions::SessionIndex,
	sphinx::{KxPublic, KxSharedSecret},
};
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey, StaticSecret};

struct SessionPublic {
	index: SessionIndex,
	public: KxPublic,
}

struct SessionSecret {
	index: SessionIndex,
	/// Boxed to avoid leaving copies of the secret key around in memory if `SessionSecret` is
	/// moved.
	secret: Box<StaticSecret>,
}

struct KxPublicStoreInner {
	discarded_sessions_before: SessionIndex,
	/// Session public keys.
	session_publics: Vec<SessionPublic>,
	/// Session secret keys not yet added to the main store.
	pending_session_secrets: Vec<SessionSecret>,
}

pub struct KxPublicStore(Mutex<KxPublicStoreInner>);

impl KxPublicStore {
	pub fn new() -> Self {
		Self(Mutex::new(KxPublicStoreInner {
			discarded_sessions_before: 0,
			session_publics: Vec::new(),
			pending_session_secrets: Vec::new(),
		}))
	}

	/// Returns `None` if the key pair was discarded due to age.
	pub fn public_for_session(&self, index: SessionIndex) -> Option<KxPublic> {
		let mut inner = self.0.lock().unwrap();

		if index < inner.discarded_sessions_before {
			return None
		}

		for s in &inner.session_publics {
			if s.index == index {
				return Some(s.public)
			}
		}

		// We box the secret to avoid leaving copies of it in memory when the `SessionSecret` is
		// moved. Note that we will likely leave some copies on the stack here; I'm not aware of
		// any good way of avoiding this.
		let secret = Box::new(StaticSecret::new(OsRng));
		let public: PublicKey = secret.as_ref().into();
		let public = public.to_bytes();
		inner.session_publics.push(SessionPublic { index, public });
		inner.pending_session_secrets.push(SessionSecret { index, secret });
		Some(public)
	}

	fn discard_sessions_before(&self, index: SessionIndex) {
		let mut inner = self.0.lock().unwrap();
		if index > inner.discarded_sessions_before {
			inner.discarded_sessions_before = index;
			inner.session_publics.retain(|s| s.index >= index);
			inner.pending_session_secrets.retain(|p| p.index >= index);
		}
	}

	fn take_pending_session_secrets(&self) -> Vec<SessionSecret> {
		let mut inner = self.0.lock().unwrap();
		std::mem::take(&mut inner.pending_session_secrets)
	}
}

impl Default for KxPublicStore {
	fn default() -> Self {
		Self::new()
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

	/// Make secrets created for `public_for_session` queries available to `session_exchange`.
	pub fn add_pending_session_secrets(&mut self) {
		self.session_secrets.extend(self.public.take_pending_session_secrets());
	}

	/// Perform key exchange using the secret key for the specified session.
	pub fn session_exchange(
		&mut self,
		index: SessionIndex,
		their_public: &KxPublic,
	) -> Option<KxSharedSecret> {
		self.session_secrets
			.iter()
			.find(|s| s.index == index)
			.map(|s| s.secret.diffie_hellman(&(*their_public).into()).to_bytes())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn basic_operation() {
		let their_secret = StaticSecret::new(rand::thread_rng());
		let their_public: PublicKey = (&their_secret).into();
		let their_public = their_public.to_bytes();

		let mut store = KxStore::new(Arc::new(KxPublicStore::new()));

		for session_index in 0..2 {
			let our_public = store.public().public_for_session(session_index).unwrap();
			let shared_secret = their_secret.diffie_hellman(&our_public.into()).to_bytes();
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
		let mut store = KxStore::new(Arc::new(KxPublicStore::new()));
		let public_0 = store.public().public_for_session(0).unwrap();
		assert_eq!(store.public().public_for_session(0), Some(public_0));
		store.discard_sessions_before(1);
		assert_eq!(store.public().public_for_session(0), None);
	}
}
