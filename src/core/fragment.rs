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
//! In case the content allow reply, the surbs must
//! fit in the first fragment and is presence
//! is only announced in this fragement.

use super::{Error, MixnetCollection};
use crate::{core::sphinx::SURBS_REPLY_SIZE, MessageType};
use rand::Rng;
use std::{
	collections::{hash_map::Entry, HashMap},
	time::Instant,
};

struct FragmentHeaderFirstChunk<'a>(&'a mut [u8]);
struct FragmentHeader<'a>(&'a mut [u8]);

type MessageHash = [u8; 32];

/// Target fragment size. Includes the header and the payload.
pub const FRAGMENT_PACKET_SIZE: usize = 2048;
const FRAGMENT_HEADER_SIZE: usize = 4 + 32;
const FRAGMENT_FIRST_CHUNK_HEADER_SIZE: usize = FRAGMENT_HEADER_SIZE + 32 + 4;
const FRAGMENT_PAYLOAD_SIZE: usize = FRAGMENT_PACKET_SIZE - FRAGMENT_HEADER_SIZE;
const FRAGMENT_FIRST_CHUNK_PAYLOAD_SIZE: usize =
	FRAGMENT_PACKET_SIZE - FRAGMENT_FIRST_CHUNK_HEADER_SIZE;
const MAX_MESSAGE_SIZE: usize = 256 * 1024;

const FRAGMENT_EXPIRATION_MS: u64 = 10000;

// TODO remove this tag, make cover a command in header and don't open payload?
const COVER_TAG: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

// hash is using tag as iv to avoid collision.
fn hash(iv: &[u8], data: &[u8]) -> MessageHash {
	let mut r = MessageHash::default();
	r.copy_from_slice(blake2_rfc::blake2b::blake2b(32, iv, data).as_bytes());
	r
}

impl<'a> FragmentHeader<'a> {
	fn new(slice: &'a mut [u8]) -> Self {
		assert!(slice.len() >= FRAGMENT_HEADER_SIZE);
		FragmentHeader(slice)
	}

	fn set_index(&mut self, index: u32) {
		self.0[..4].copy_from_slice(&index.to_be_bytes())
	}

	fn index(&self) -> u32 {
		let mut index: [u8; 4] = Default::default();
		index.copy_from_slice(&self.0[..4]);
		u32::from_be_bytes(index)
	}

	fn set_cover(&mut self) {
		self.0[..4].copy_from_slice(&COVER_TAG)
	}

	fn is_cover(&self) -> bool {
		&self.0[..4] == &COVER_TAG
	}

	fn set_hash(&mut self, hash: MessageHash) {
		self.0[4..36].copy_from_slice(&hash)
	}

	fn hash(&self) -> MessageHash {
		let mut hash: MessageHash = Default::default();
		hash.copy_from_slice(&self.0[4..36]);
		hash
	}
}

impl<'a> FragmentHeaderFirstChunk<'a> {
	fn new(slice: &'a mut [u8]) -> Self {
		assert!(slice.len() >= FRAGMENT_FIRST_CHUNK_HEADER_SIZE);
		FragmentHeaderFirstChunk(slice)
	}

	fn set_iv(&mut self, iv: [u8; 32]) {
		self.0[36..68].copy_from_slice(&iv)
	}

	fn iv(&self) -> [u8; 32] {
		let mut iv = [0u8; 32];
		iv.copy_from_slice(&self.0[36..68]);
		iv
	}

	fn set_message_len(&mut self, len: u32) {
		self.0[68..72].copy_from_slice(&len.to_be_bytes())
	}

	fn message_len(&self) -> u32 {
		let mut len: [u8; 4] = Default::default();
		len.copy_from_slice(&self.0[68..72]);
		u32::from_be_bytes(len)
	}
}

struct IncompleteMessage {
	target_len: Option<u32>,
	target_iv: [u8; 32],
	target_hash: MessageHash,
	fragments: HashMap<u32, Vec<u8>>,
	kind: MessageType,
}

impl IncompleteMessage {
	fn current_len(&self) -> usize {
		let surbs_len = if self.kind.with_surbs() { SURBS_REPLY_SIZE } else { 0 };
		(self.fragments.len() * FRAGMENT_PAYLOAD_SIZE) - surbs_len
	}

	fn is_complete(&self) -> bool {
		self.target_len
			.map(|target_len| self.current_len() >= target_len as usize)
			.unwrap_or(false)
	}

	fn num_fragments(&self) -> usize {
		self.fragments.len()
	}

	fn total_expected_fragments(&self) -> Option<usize> {
		self.target_len.map(|target_len| {
			let surbs_len = if self.kind.with_surbs() { SURBS_REPLY_SIZE } else { 0 };
			(target_len as usize + surbs_len) / FRAGMENT_PAYLOAD_SIZE + 1
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
			if index == 0 {
				result.extend_from_slice(&fragment[FRAGMENT_FIRST_CHUNK_HEADER_SIZE..]);
			} else {
				result.extend_from_slice(&fragment[FRAGMENT_HEADER_SIZE..]);
			}
			index += 1;
		}
		result.resize(target_len, 0u8); // TODO warn or error if resize needed
		let hash = hash(&self.target_iv[..], &result);
		if hash != self.target_hash {
			return Err(Error::BadFragment)
		}
		Ok((result, self.kind))
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
		mut fragment: Vec<u8>,
		kind: MessageType,
	) -> Result<Option<(Vec<u8>, MessageType)>, Error> {
		let surbs_len = if kind.with_surbs() { SURBS_REPLY_SIZE } else { 0 };
		if fragment.len() + surbs_len != FRAGMENT_PACKET_SIZE {
			return Err(Error::BadFragment)
		}
		let (hash, index) = {
			let header = FragmentHeader::new(&mut fragment);
			if header.is_cover() {
				// Discard cover message
				return Ok(None)
			}
			(header.hash(), header.index())
		};

		let expires_ix = self.0.next_inserted_entry();
		match self.0.entry(hash.clone()) {
			Entry::Occupied(mut e) => {
				if index == 0 {
					let header = FragmentHeaderFirstChunk(&mut fragment);
					e.get_mut().0.target_len = Some(header.message_len());
					e.get_mut().0.target_iv = header.iv();
				}
				e.get_mut().0.fragments.insert(index, fragment);
				if kind.with_surbs() {
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
				let (target_len, target_iv) = if index == 0 {
					let header = FragmentHeaderFirstChunk(&mut fragment);
					(Some(header.message_len()), header.iv())
				} else {
					(None, [0u8; 32])
				};
				let mut message = IncompleteMessage {
					target_hash: hash,
					target_len,
					target_iv,
					fragments: Default::default(),
					kind,
				};
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
pub fn create_fragments(
	rng: &mut impl Rng,
	mut message: Vec<u8>,
	with_surbs: bool,
) -> Result<Vec<Vec<u8>>, Error> {
	assert!(SURBS_REPLY_SIZE < FRAGMENT_FIRST_CHUNK_PAYLOAD_SIZE); // TODO const assert?
	let surbs_len = if with_surbs { SURBS_REPLY_SIZE } else { 0 };
	let additional_first_header = FRAGMENT_FIRST_CHUNK_HEADER_SIZE - FRAGMENT_HEADER_SIZE;
	if message.len() > MAX_MESSAGE_SIZE {
		return Err(Error::MessageTooLarge)
	}
	let len_no_header = message.len() + surbs_len + additional_first_header;
	let mut iv = [0u8; 32];
	rng.fill_bytes(&mut iv);
	let hash = hash(&iv[..], &message);
	let message_len = message.len();
	let pad =
		(FRAGMENT_PAYLOAD_SIZE - len_no_header % FRAGMENT_PAYLOAD_SIZE) % FRAGMENT_PAYLOAD_SIZE;
	message.resize(message.len() + pad, 0);
	let nb_chunks = (message.len() + surbs_len + additional_first_header) / FRAGMENT_PAYLOAD_SIZE;
	debug_assert!(
		(message.len() + surbs_len + additional_first_header) % FRAGMENT_PAYLOAD_SIZE == 0
	);
	let mut offset = 0;
	let mut fragments = Vec::with_capacity(nb_chunks);
	for n in 0..nb_chunks {
		let additional_header = if n == 0 { additional_first_header } else { 0 };
		let fragment_len = if with_surbs && n == 0 {
			FRAGMENT_PAYLOAD_SIZE - SURBS_REPLY_SIZE - additional_header
		} else {
			FRAGMENT_PAYLOAD_SIZE - additional_header
		};
		let chunk = &message[offset..offset + fragment_len];
		offset += fragment_len;
		let mut fragment = Vec::with_capacity(FRAGMENT_PACKET_SIZE);
		fragment.resize(FRAGMENT_HEADER_SIZE, 0u8);
		let mut header = FragmentHeader::new(&mut fragment);
		header.set_hash(hash);
		header.set_index(n as u32);
		if n == 0 {
			fragment.resize(FRAGMENT_FIRST_CHUNK_HEADER_SIZE, 0u8);
			let mut header = FragmentHeaderFirstChunk::new(&mut fragment);
			header.set_message_len(message_len as u32);
			header.set_iv(iv);
		}
		fragment.extend_from_slice(chunk);
		fragments.push(fragment);
	}
	Ok(fragments)
}

/// Create a single fragment filled with random data.
pub fn create_cover_fragment(rng: &mut impl Rng) -> Vec<u8> {
	let mut message = Vec::with_capacity(FRAGMENT_PACKET_SIZE);
	message.resize(FRAGMENT_PACKET_SIZE, 0u8);
	let mut header = FragmentHeader::new(&mut message);
	let mut hash = MessageHash::default();
	rng.fill_bytes(&mut hash);
	header.set_hash(hash);
	header.set_cover();
	message
}

#[cfg(test)]
mod test {
	use super::*;
	use rand::{prelude::SliceRandom, RngCore};

	#[test]
	fn create_and_insert_small() {
		let mut rng = rand::thread_rng();
		let mut fragments = MessageCollection::new();

		let mut small_fragment = create_fragments(&mut rng, vec![42], false).unwrap();
		assert_eq!(small_fragment.len(), 1);
		let small_fragment = std::mem::take(&mut small_fragment[0]);
		assert_eq!(small_fragment.len(), FRAGMENT_PACKET_SIZE);

		assert_eq!(
			fragments.insert_fragment(small_fragment, MessageType::FromSurbs).unwrap(),
			Some((vec![42], MessageType::FromSurbs))
		);

		let mut large = Vec::new();
		large.resize(60000, 0u8);
		rng.fill_bytes(&mut large);
		let mut large_fragments = create_fragments(&mut rng, large.clone(), false).unwrap();
		assert_eq!(large_fragments.len(), 30);

		large_fragments.shuffle(&mut rng);
		for fragment in large_fragments.iter().skip(1) {
			assert_eq!(fragments.insert_fragment(fragment.clone(), MessageType::StandAlone).unwrap(), None);
		}
		assert_eq!(
			fragments.insert_fragment(large_fragments[0].clone(), MessageType::StandAlone).unwrap(),
			Some((large, MessageType::StandAlone))
		);

		let mut too_large = Vec::new();
		too_large.resize(MAX_MESSAGE_SIZE + 1, 0u8);
		assert_eq!((create_fragments(&mut rng, too_large, false)), Err(Error::MessageTooLarge));
	}

	#[test]
	fn insert_invalid() {
		let mut fragments = MessageCollection::new();
		assert_eq!(fragments.insert_fragment(vec![], MessageType::StandAlone), Err(Error::BadFragment));
		assert_eq!(fragments.insert_fragment(vec![42], MessageType::StandAlone), Err(Error::BadFragment));
		let empty_packet = [0u8; FRAGMENT_PACKET_SIZE].to_vec();
		assert_eq!(fragments.insert_fragment(empty_packet, MessageType::StandAlone), Err(Error::BadFragment));
	}

	#[test]
	fn create_cover() {
		let mut rng = rand::thread_rng();
		let fragment = create_cover_fragment(&mut rng);
		assert_eq!(fragment.len(), FRAGMENT_PACKET_SIZE);
	}

	#[test]
	fn cleanup() {
		let mut rng = rand::thread_rng();
		let mut fragments = MessageCollection::new();
		fragments.0.expiration = std::time::Duration::from_millis(0);
		let mut message = Vec::new();
		message.resize(FRAGMENT_PACKET_SIZE * 2, 0u8);
		let message_fragments = create_fragments(&mut rng, message, false).unwrap();
		assert_eq!(fragments.insert_fragment(message_fragments[0].clone(), MessageType::StandAlone).unwrap(), None);
		assert_eq!(1, fragments.0.messages.len());
		fragments.cleanup(Instant::now());
		assert_eq!(0, fragments.0.messages.len());
	}
}
