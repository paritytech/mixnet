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

//! Keystore for SURB payload encryption keys.

use super::{
	fragment::MessageId,
	sphinx::{SurbId, SurbPayloadEncryptionKeys, SURB_ID_SIZE},
};
use hashlink::{linked_hash_map, LinkedHashMap};
use log::debug;
use rand::{CryptoRng, Rng};

struct Value {
	keys: SurbPayloadEncryptionKeys,
	message_id: MessageId,
}

pub struct Entry<'a>(linked_hash_map::OccupiedEntry<'a, SurbId, Value>);

impl<'a> Entry<'a> {
	pub fn keys(&self) -> &SurbPayloadEncryptionKeys {
		&self.0.get().keys
	}

	pub fn message_id(&self) -> &MessageId {
		&self.0.get().message_id
	}

	pub fn remove(self) {
		self.0.remove();
	}
}

pub struct SurbKeystore {
	/// Maximum number of SURBs to keep keys for.
	capacity: usize,
	/// In creation order: oldest SURBs at the front, newest SURBs at the back.
	surbs: LinkedHashMap<SurbId, Value>,
}

impl SurbKeystore {
	pub fn new(capacity: usize) -> Self {
		debug_assert_ne!(capacity, 0);
		Self { capacity, surbs: LinkedHashMap::with_capacity(capacity) }
	}

	/// Create an entry for a new SURB. Returns the randomly generated ID and a mutable reference
	/// to the keys, which should be filled in by the caller.
	pub fn insert(
		&mut self,
		rng: &mut (impl Rng + CryptoRng),
		message_id: &MessageId,
		log_target: &str,
	) -> (SurbId, &mut SurbPayloadEncryptionKeys) {
		// Discard the oldest SURB if we're already at capacity
		debug_assert!(self.surbs.len() <= self.capacity);
		if self.surbs.len() == self.capacity {
			debug!(target: log_target, "Too many entries in SURB keystore; evicting oldest");
			self.surbs.pop_front();
		}

		let mut id = [0; SURB_ID_SIZE];
		rng.fill_bytes(&mut id);
		match self.surbs.entry(id) {
			linked_hash_map::Entry::Occupied(_) => panic!(
				"Randomly generated SURB ID matches an existing SURB ID; something wrong with RNG?"
			),
			linked_hash_map::Entry::Vacant(entry) => {
				let value = entry.insert(Value {
					keys: SurbPayloadEncryptionKeys::new(),
					message_id: *message_id,
				});
				(id, &mut value.keys)
			},
		}
	}

	/// Returns the entry for a SURB, or [`None`] if the ID is not recognised.
	pub fn entry(&mut self, id: &SurbId) -> Option<Entry> {
		match self.surbs.entry(*id) {
			linked_hash_map::Entry::Occupied(entry) => Some(Entry(entry)),
			linked_hash_map::Entry::Vacant(_) => None,
		}
	}
}
