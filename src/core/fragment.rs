// Copyright 2022 Parity Technologies (UK) Ltd.
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

//! Mix message fragment management.
//!
//! Size is bounded to `MAX_MESSAGE_SIZE`.
//!
//! In case the content allow reply, the surb must
//! fit in the first fragment and is presence
//! is only announced in this fragement.

use super::{Error, MixnetCollection};
use crate::{core::sphinx::SphinxConstants, MessageType};
use rand::Rng;
use static_assertions::const_assert;
use std::{
	collections::{hash_map::Entry, HashMap},
	time::Instant,
};

type MessageHash = [u8; 32];

/// Target fragment size. Includes the header and the payload.
pub const FRAGMENT_PACKET_SIZE: usize = 2048;
const FRAGMENT_HEADER_SIZE: usize = 4 + 32;
const FRAGMENT_FIRST_CHUNK_HEADER_SIZE: usize = FRAGMENT_HEADER_SIZE + 32 + 4;
// TODO test it somehow const_assert!(SURBS_REPLY_SIZE < FRAGMENT_PACKET_SIZE - FRAGMENT_FIRST_CHUNK_HEADER_SIZE);
const FRAGMENT_PAYLOAD_SIZE: usize = FRAGMENT_PACKET_SIZE - FRAGMENT_HEADER_SIZE;
const MAX_MESSAGE_SIZE: usize = 256 * 1024;

const FRAGMENT_EXPIRATION_MS: u64 = 10000;

const COVER_TAG: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

// `hash` is using tag as iv to avoid collision.
// Avoiding collision is not needed in all case.
// In the case we do not need to count the number
// of time an identical message was received, it
// would not be needed.
fn hash(iv: &[u8], data: &[u8]) -> MessageHash {
	let mut r = MessageHash::default();
	r.copy_from_slice(blake2_rfc::blake2b::blake2b(32, iv, data).as_bytes());
	r
}

/// Fragment.
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Fragment {
	buf: Vec<u8>,
	index: u32,
	with_surb: bool,
}

impl Fragment {
	/// Create a single fragment filled with random data.
	pub fn create_cover_fragment(rng: &mut impl Rng) -> Fragment {
		let mut buf = vec![0; FRAGMENT_PACKET_SIZE];
		buf[0..4].copy_from_slice(&COVER_TAG[..]);
		rng.fill_bytes(&mut buf[4..]);
		Fragment { buf, index: 0, with_surb: false }
	}

	pub fn create<S: SphinxConstants>(
		index: u32,
		hash: MessageHash,
		iv: &[u8],
		message_len: u32,
		chunk: &[u8],
		with_surb: bool,
	) -> Fragment {
		let mut buf = Vec::with_capacity(FRAGMENT_PACKET_SIZE);
		buf.extend_from_slice(&index.to_be_bytes());
		buf.extend_from_slice(&hash);
		if index == 0 {
			buf.extend_from_slice(iv);
			buf.extend_from_slice(&message_len.to_be_bytes());
		}

		// chunk size must match (need to be padded).
		buf.extend_from_slice(chunk);

		debug_assert!(if with_surb && index == 0 {
			buf.len() == FRAGMENT_PACKET_SIZE - S::SURBS_REPLY_SIZE
		} else {
			buf.len() == FRAGMENT_PACKET_SIZE
		});

		Fragment { buf, index, with_surb }
	}

	fn hash(&self) -> MessageHash {
		let mut hash: MessageHash = Default::default();
		hash.copy_from_slice(&self.buf[4..36]);
		hash
	}

	pub fn from_message<S: SphinxConstants>(fragment: Vec<u8>, kind: &MessageType) -> Result<Option<Self>, Error> {
		let with_surb = kind.with_surb();
		if !with_surb && fragment.len() != FRAGMENT_PACKET_SIZE {
			return Err(Error::BadFragment)
		}
		if fragment[..4] == COVER_TAG {
			return Ok(None)
		}

		let mut index: [u8; 4] = Default::default();
		index.copy_from_slice(&fragment[..4]);
		let index = u32::from_be_bytes(index);

		if with_surb {
			if fragment.len() != FRAGMENT_PACKET_SIZE - S::SURBS_REPLY_SIZE {
				return Err(Error::BadFragment)
			}
			if index != 0 {
				return Err(Error::BadFragment)
			}
		}

		Ok(Some(Fragment { buf: fragment, index, with_surb }))
	}

	pub fn iv(&self) -> Option<Box<[u8; 32]>> {
		if self.index == 0 {
			let mut iv = [0u8; 32];
			iv.copy_from_slice(&self.buf[36..68]);
			Some(Box::new(iv))
		} else {
			None
		}
	}

	pub fn message_len(&self) -> Option<u32> {
		if self.index == 0 {
			let mut len: [u8; 4] = Default::default();
			len.copy_from_slice(&self.buf[68..72]);
			Some(u32::from_be_bytes(len))
		} else {
			None
		}
	}

	pub fn data(&self) -> &[u8] {
		let offset =
			if self.index == 0 { FRAGMENT_FIRST_CHUNK_HEADER_SIZE } else { FRAGMENT_HEADER_SIZE };
		&self.buf[offset..]
	}

	pub fn into_vec(self) -> Vec<u8> {
		self.buf
	}
}

struct IncompleteMessage {
	target_len: Option<u32>,
	target_iv: Option<Box<[u8; 32]>>,
	target_hash: MessageHash,
	fragments: HashMap<u32, Fragment>,
	kind: MessageType,
}

impl IncompleteMessage {
	fn current_len<S: SphinxConstants>(&self) -> usize {
		let surb_len = if self.kind.with_surb() { S::SURBS_REPLY_SIZE } else { 0 };
		(self.fragments.len() * FRAGMENT_PAYLOAD_SIZE) - surb_len
	}

	fn is_complete(&self) -> bool {
		self.target_len
			.map(|target_len| self.current_len() >= target_len as usize)
			.unwrap_or(false)
	}

	fn num_fragments(&self) -> usize {
		self.fragments.len()
	}

	fn total_expected_fragments<S: SphinxConstants>(&self) -> Option<usize> {
		self.target_len.map(|target_len| {
			let surb_len = if self.kind.with_surb() { S::SURBS_REPLY_SIZE } else { 0 };
			(target_len as usize + surb_len) / FRAGMENT_PAYLOAD_SIZE + 1
		})
	}

	fn reconstruct(mut self) -> Result<(Vec<u8>, MessageType), Error> {
		let mut index = 0;
		let target_len = if let Some(len) = self.target_len {
			len as usize
		} else {
			return Err(Error::BadFragment)
		};
		let mut result = Vec::with_capacity(target_len);
		while result.len() < target_len {
			let fragment = match self.fragments.remove(&index) {
				Some(fragment) => fragment,
				None => return Err(Error::BadFragment),
			};
			result.extend_from_slice(fragment.data());
			index += 1;
		}
		if result.len() < target_len {
			return Err(Error::BadFragment)
		}
		// check padding
		if !result[target_len..].iter().all(|c| c == &0) {
			return Err(Error::BadFragment)
		}
		result.resize(target_len, 0u8);

		if let Some(iv) = self.target_iv {
			let hash = hash(&iv[..], &result);
			if hash == self.target_hash {
				return Ok((result, self.kind))
			}
		}
		Err(Error::BadFragment)
	}
}

/// Manages partial message fragments.
pub struct MessageCollection(MixnetCollection<MessageHash, IncompleteMessage>);

impl MessageCollection {
	pub fn new() -> Self {
		MessageCollection(MixnetCollection::new(FRAGMENT_EXPIRATION_MS))
	}

	/// Insert a new new message fragment in the collection. If the fragment completes some message,
	/// full message is returned.
	pub fn insert_fragment(
		&mut self,
		fragment: Vec<u8>,
		kind: MessageType,
	) -> Result<Option<(Vec<u8>, MessageType)>, Error> {
		let fragment = if let Some(fragment) = Fragment::from_message(fragment, &kind)? {
			fragment
		} else {
			// Discard cover message
			return Ok(None)
		};

		let expires_ix = self.0.next_inserted_entry();
		match self.0.entry(fragment.hash()) {
			Entry::Occupied(mut e) => {
				let with_surb = fragment.with_surb;
				let index = fragment.index;
				if index == 0 {
					e.get_mut().0.target_len = fragment.message_len();
					e.get_mut().0.target_iv = fragment.iv();
				}
				e.get_mut().0.fragments.insert(index, fragment);
				if with_surb {
					e.get_mut().0.kind = kind;
				}
				log::trace!(target: "mixnet", "Inserted additional fragment {} ({}/{:?})", index, e.get().0.num_fragments(), e.get().0.total_expected_fragments());
				if e.get().0.is_complete() {
					log::trace!(target: "mixnet", "Fragment complete");
					let e = e.remove();
					let e = self.0.removed_entry(e);
					return Ok(Some(e.reconstruct()?))
				}
			},
			Entry::Vacant(e) => {
				let index = fragment.index;
				let mut message = IncompleteMessage {
					target_hash: fragment.hash(),
					target_len: fragment.message_len(),
					target_iv: fragment.iv(),
					fragments: Default::default(),
					kind,
				};
				let hash = fragment.hash();
				message.fragments.insert(index, fragment);
				log::trace!(target: "mixnet", "Inserted new fragment {} ({}/{:?})", index, 1, message.total_expected_fragments());
				if message.is_complete() {
					log::trace!(target: "mixnet", "Fragment complete");
					return Ok(Some(message.reconstruct()?))
				}
				e.insert((message, expires_ix));
				self.0.inserted_entry(hash, Instant::now());
			},
		}
		Ok(None)
	}

	/// Perform periodic maintenance. Messages that sit in the collection for too long are expunged.
	pub fn cleanup(&mut self, now: Instant) {
		let removed = self.0.cleanup(now);
		if removed > 0 {
			log::trace!(target: "mixnet", "Fragment cleanup. Removed {} fragments", removed)
		}
	}
}

/// Utility function to split message body into equal-sized chunks. Each chunk contains a header
/// that allows for message reconstruction.
pub fn create_fragments<S: SphinxConstants>(
	rng: &mut impl Rng,
	mut message: Vec<u8>,
	with_surb: bool,
) -> Result<Vec<Fragment>, Error> {
	let surb_len = if with_surb { S::SURBS_REPLY_SIZE } else { 0 };
	let additional_first_header = FRAGMENT_FIRST_CHUNK_HEADER_SIZE - FRAGMENT_HEADER_SIZE;
	if message.len() > MAX_MESSAGE_SIZE {
		return Err(Error::MessageTooLarge)
	}
	let len_no_header = message.len() + surb_len + additional_first_header;
	let mut iv = [0u8; 32];
	rng.fill_bytes(&mut iv);
	let hash = hash(&iv[..], &message);
	let message_len = message.len();
	let pad =
		(FRAGMENT_PAYLOAD_SIZE - len_no_header % FRAGMENT_PAYLOAD_SIZE) % FRAGMENT_PAYLOAD_SIZE;
	message.resize(message.len() + pad, 0);
	let nb_chunks = (message.len() + surb_len + additional_first_header) / FRAGMENT_PAYLOAD_SIZE;
	debug_assert!(
		(message.len() + surb_len + additional_first_header) % FRAGMENT_PAYLOAD_SIZE == 0
	);
	let mut offset = 0;
	let mut fragments = Vec::with_capacity(nb_chunks);
	for n in 0..nb_chunks {
		let additional_header = if n == 0 { additional_first_header } else { 0 };
		let fragment_len = if with_surb && n == 0 {
			FRAGMENT_PAYLOAD_SIZE - S::SURBS_REPLY_SIZE - additional_header
		} else {
			FRAGMENT_PAYLOAD_SIZE - additional_header
		};
		let chunk = &message[offset..offset + fragment_len];
		offset += fragment_len;
		let fragment =
			Fragment::create(n as u32, hash, iv.as_slice(), message_len as u32, chunk, with_surb);
		fragments.push(fragment);
	}
	Ok(fragments)
}

#[cfg(test)]
mod test {
	use super::*;
	use rand::{prelude::SliceRandom, RngCore};

	#[test]
	fn create_and_insert_small() {
		let peer_public_key =
			x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0u8; 32]));
		let recipient = Box::new(([0u8; 32], peer_public_key)); // unused in test

		let mut rng = rand::thread_rng();
		let mut fragments = MessageCollection::new();

		let small_fragment = create_fragments(&mut rng, vec![42], false).unwrap();
		assert_eq!(small_fragment.len(), 1);
		let small_fragment = small_fragment[0].clone().into_vec();
		assert_eq!(small_fragment.len(), FRAGMENT_PACKET_SIZE);

		assert_eq!(
			fragments
				.insert_fragment(
					small_fragment,
					MessageType::FromSurbs(Some(vec![1]), recipient.clone())
				)
				.unwrap(),
			Some((vec![42], MessageType::FromSurbs(Some(vec![1]), recipient)))
		);

		let mut large = Vec::new();
		large.resize(60000, 0u8);
		rng.fill_bytes(&mut large);
		let mut large_fragments = create_fragments(&mut rng, large.clone(), false).unwrap();
		assert_eq!(large_fragments.len(), 30);

		large_fragments.shuffle(&mut rng);
		for fragment in large_fragments.iter().skip(1) {
			assert_eq!(
				fragments
					.insert_fragment(fragment.clone().into_vec(), MessageType::StandAlone)
					.unwrap(),
				None
			);
		}
		assert_eq!(
			fragments
				.insert_fragment(large_fragments[0].clone().into_vec(), MessageType::StandAlone)
				.unwrap(),
			Some((large, MessageType::StandAlone))
		);

		let mut too_large = Vec::new();
		too_large.resize(MAX_MESSAGE_SIZE + 1, 0u8);
		assert_eq!((create_fragments(&mut rng, too_large, false)), Err(Error::MessageTooLarge));
	}

	#[test]
	fn insert_invalid() {
		let mut fragments = MessageCollection::new();
		assert_eq!(
			fragments.insert_fragment(vec![], MessageType::StandAlone),
			Err(Error::BadFragment)
		);
		assert_eq!(
			fragments.insert_fragment(vec![42], MessageType::StandAlone),
			Err(Error::BadFragment)
		);
		let empty_packet = [0u8; FRAGMENT_PACKET_SIZE].to_vec();
		assert_eq!(
			fragments.insert_fragment(empty_packet, MessageType::StandAlone),
			Err(Error::BadFragment)
		);
	}

	#[test]
	fn cleanup() {
		let mut rng = rand::thread_rng();
		let mut fragments = MessageCollection::new();
		fragments.0.expiration = std::time::Duration::from_millis(0);
		let mut message = Vec::new();
		message.resize(FRAGMENT_PACKET_SIZE * 2, 0u8);
		let message_fragments = create_fragments(&mut rng, message, false).unwrap();
		assert_eq!(
			fragments
				.insert_fragment(message_fragments[0].clone().into_vec(), MessageType::StandAlone)
				.unwrap(),
			None
		);
		assert_eq!(1, fragments.0.messages.len());
		fragments.cleanup(Instant::now());
		assert_eq!(0, fragments.0.messages.len());
	}
}
