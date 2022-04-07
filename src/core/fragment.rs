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

//! Mix message fragment management.
//!
//! Size is bounded to `MAX_MESSAGE_SIZE`.
//!
//! In case the content allow reply, the surbs must
//! fit in the first fragment and is presence
//! is only announced in this fragement.

use super::Error;
use crate::core::sphinx::{SurbsEncoded, SURBS_REPLY_SIZE};
use instant::Duration;
use rand::Rng;
use std::{
	collections::{hash_map::Entry, HashMap},
	time::Instant,
};

struct FragmentHeader<'a>(&'a mut [u8]);

type MessageHash = [u8; 32];

/// Target fragment size. Includes the header and the payload.
pub const FRAGMENT_PACKET_SIZE: usize = 2048;
const FRAGMENT_HEADER_SIZE: usize = 32 + 4 + 4;
const FRAGMENT_PAYLOAD_SIZE: usize = FRAGMENT_PACKET_SIZE - FRAGMENT_HEADER_SIZE;
const MAX_MESSAGE_SIZE: usize = 256 * 1024;
/// Surbs presence is higher byte of be encoding of the number of fragment.
/// Can only conflict if the effective message size is less than a byte.
const MASK_SURBS_U8: u8 = 1 << 7;

const FRAGMENT_EXPIRATION_MS: u64 = 10000;

const COVER_TAG: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

fn hash(data: &[u8]) -> MessageHash {
	let mut r = MessageHash::default();
	r.copy_from_slice(blake2_rfc::blake2b::blake2b(32, &[], data).as_bytes());
	r
}

impl<'a> FragmentHeader<'a> {
	fn new(slice: &'a mut [u8]) -> Self {
		assert!(slice.len() >= FRAGMENT_HEADER_SIZE);
		FragmentHeader(slice)
	}

	fn set_hash(&mut self, hash: MessageHash) {
		self.0[0..32].copy_from_slice(&hash)
	}

	fn set_message_len(&mut self, len: u32) {
		self.0[32..36].copy_from_slice(&len.to_be_bytes())
	}

	fn set_has_surbs(&mut self, has_surbs: bool) {
		if has_surbs {
			self.0[36] |= MASK_SURBS_U8;
		} else {
			self.0[36] &= !MASK_SURBS_U8;
		}
	}

	fn set_index(&mut self, index: u32) {
		let mut index = index.to_be_bytes();
		if self.has_surbs() {
			index[0] |= MASK_SURBS_U8;
		}
		self.0[36..40].copy_from_slice(&index)
	}

	fn set_cover(&mut self) {
		self.0[36..40].copy_from_slice(&COVER_TAG)
	}

	fn hash(&self) -> MessageHash {
		let mut hash: MessageHash = Default::default();
		hash.copy_from_slice(&self.0[0..32]);
		hash
	}

	fn message_len(&self) -> u32 {
		let mut len: [u8; 4] = Default::default();
		len.copy_from_slice(&self.0[32..36]);
		u32::from_be_bytes(len)
	}

	fn index(&self) -> u32 {
		let mut index: [u8; 4] = Default::default();
		index.copy_from_slice(&self.0[36..40]);
		index[0] &= !MASK_SURBS_U8;
		u32::from_be_bytes(index)
	}

	fn has_surbs(&self) -> bool {
		(self.0[36] & MASK_SURBS_U8) > 0
	}

	fn is_cover(&self) -> bool {
		&self.0[36..40] == &COVER_TAG
	}
}

struct IncompleteMessage {
	target_len: u32,
	target_hash: MessageHash,
	fragments: HashMap<u32, Vec<u8>>,
	surbs: Option<SurbsEncoded>,
	expires: Instant,
}

impl IncompleteMessage {
	fn current_len(&self) -> usize {
		let surbs_len = if self.surbs.is_some() { SURBS_REPLY_SIZE } else { 0 };
		(self.fragments.len() * FRAGMENT_PAYLOAD_SIZE) - surbs_len
	}

	fn is_complete(&self) -> bool {
		self.current_len() >= self.target_len as usize
	}

	fn num_fragments(&self) -> usize {
		self.fragments.len()
	}

	fn total_expected_fragments(&self) -> usize {
		// Not that when surbs is attached there may be a error of one unit due to additional
		// space used by surbs.
		self.target_len as usize / FRAGMENT_PAYLOAD_SIZE + 1
	}

	fn reconstruct(mut self) -> Result<(Vec<u8>, Option<SurbsEncoded>), Error> {
		let mut index = 0;
		let mut result = Vec::with_capacity(self.target_len as usize);
		while result.len() < self.target_len as usize {
			let fragment = match self.fragments.remove(&index) {
				Some(fragment) => fragment,
				None => return Err(Error::BadFragment),
			};
			result.extend_from_slice(&fragment[FRAGMENT_HEADER_SIZE..]);
			index += 1;
		}
		result.resize(self.target_len as usize, 0u8);
		let hash = hash(&result);
		if hash != self.target_hash {
			return Err(Error::BadFragment)
		}
		Ok((result, self.surbs))
	}
}

/// Manages partial message fragments.
pub struct MessageCollection {
	messages: HashMap<MessageHash, IncompleteMessage>,
	expiration: Duration,
}

impl MessageCollection {
	pub fn new() -> Self {
		Self {
			messages: Default::default(),
			expiration: Duration::from_millis(FRAGMENT_EXPIRATION_MS),
		}
	}

	/// Insert a new new message fragment in the collection. If the fragment completes some message,
	/// full message is returned.
	pub fn insert_fragment(
		&mut self,
		mut fragment: Vec<u8>,
		surbs: Option<SurbsEncoded>,
	) -> Result<Option<(Vec<u8>, Option<SurbsEncoded>)>, Error> {
		let surbs_len = if surbs.is_some() { SURBS_REPLY_SIZE } else { 0 };
		if fragment.len() + surbs_len != FRAGMENT_PACKET_SIZE {
			return Err(Error::BadFragment)
		}
		let (hash, len, index) = {
			let header = FragmentHeader::new(&mut fragment);
			if header.is_cover() {
				// Discard cover message
				return Ok(None)
			}
			(header.hash(), header.message_len(), header.index())
		};

		// TODO storing by hash is wrong: when two message with same content KO!!
		match self.messages.entry(hash.clone()) {
			Entry::Occupied(mut e) => {
				e.get_mut().fragments.insert(index, fragment);
				if surbs.is_some() {
					e.get_mut().surbs = surbs;
				}
				log::trace!(target: "mixnet", "Inserted additional fragment {} ({}/{})", index, e.get().num_fragments(), e.get().total_expected_fragments());
				if e.get().is_complete() {
					log::trace!(target: "mixnet", "Fragment complete");
					return Ok(Some(e.remove().reconstruct()?))
				}
			},
			Entry::Vacant(e) => {
				let mut message = IncompleteMessage {
					target_hash: hash,
					target_len: len,
					fragments: Default::default(),
					surbs,
					expires: Instant::now() + self.expiration,
				};
				message.fragments.insert(index, fragment);
				log::trace!(target: "mixnet", "Inserted new fragment {} ({}/{})", index, 1, message.total_expected_fragments());
				if message.is_complete() {
					log::trace!(target: "mixnet", "Fragment complete");
					return Ok(Some(message.reconstruct()?))
				}
				e.insert(message);
			},
		}
		Ok(None)
	}

	/// Perform periodic maintenance. Messages that sit in the collection for too long are expunged.
	pub fn cleanup(&mut self) {
		let now = Instant::now();
		let count = self.messages.len();
		self.messages.retain(|_, m| m.expires > now);
		let removed = count - self.messages.len();
		if removed > 0 {
			log::trace!(target: "mixnet", "Fragment cleanup. Removed {} fragments", removed)
		}
	}
}

/// Utility function to split message body into equal-sized chunks. Each chunk contains a header
/// that allows for message reconstruction.
pub fn create_fragments(mut message: Vec<u8>, with_surbs: bool) -> Result<Vec<Vec<u8>>, Error> {
	assert!(SURBS_REPLY_SIZE < FRAGMENT_PAYLOAD_SIZE); // TODO const assert?
	let surbs_len = if with_surbs { SURBS_REPLY_SIZE } else { 0 };
	let len = message.len() + surbs_len;
	if len > MAX_MESSAGE_SIZE {
		return Err(Error::MessageTooLarge)
	}
	let pad = FRAGMENT_PAYLOAD_SIZE;
	let hash = hash(&message);
	let message_len = message.len();
	message.resize(message_len + (pad - len % pad) % pad, 0);
	let nb_chunks = (message.len() + surbs_len) / FRAGMENT_PAYLOAD_SIZE;
	debug_assert!((message.len() + surbs_len) % FRAGMENT_PAYLOAD_SIZE == 0);
	// TODO message.resize(len + (pad - (len % pad)), 0);
	let mut offset = 0;
	let mut fragments = Vec::with_capacity(nb_chunks);
	for n in 0..nb_chunks {
		let fragment_len = if with_surbs && n == 0 {
			FRAGMENT_PAYLOAD_SIZE - SURBS_REPLY_SIZE
		} else {
			FRAGMENT_PAYLOAD_SIZE
		};
		let chunk = &message[offset..offset + fragment_len];
		offset += fragment_len;
		let mut fragment = Vec::with_capacity(fragment_len);
		fragment.resize(FRAGMENT_HEADER_SIZE, 0u8);
		let mut header = FragmentHeader::new(&mut fragment);
		header.set_hash(hash);
		header.set_message_len(message_len as u32);
		header.set_has_surbs(with_surbs);
		header.set_index(n as u32);
		fragment.extend_from_slice(chunk);
		fragments.push(fragment);
	}
	Ok(fragments)
}

/// Create a single fragment filled with random data.
pub fn create_cover_fragment<R: Rng>(rng: &mut R) -> Vec<u8> {
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

		let mut small_fragment = create_fragments(vec![42], false).unwrap();
		assert_eq!(small_fragment.len(), 1);
		let small_fragment = std::mem::take(&mut small_fragment[0]);
		assert_eq!(small_fragment.len(), FRAGMENT_PACKET_SIZE);

		assert_eq!(
			fragments.insert_fragment(small_fragment, None).unwrap(),
			Some((vec![42], None))
		);

		let mut large = Vec::new();
		large.resize(60000, 0u8);
		rng.fill_bytes(&mut large);
		let mut large_fragments = create_fragments(large.clone(), false).unwrap();
		assert_eq!(large_fragments.len(), 30);

		large_fragments.shuffle(&mut rng);
		for fragment in large_fragments.iter().skip(1) {
			assert_eq!(fragments.insert_fragment(fragment.clone(), None).unwrap(), None);
		}
		assert_eq!(
			fragments.insert_fragment(large_fragments[0].clone(), None).unwrap(),
			Some((large, None))
		);

		let mut too_large = Vec::new();
		too_large.resize(MAX_MESSAGE_SIZE + 1, 0u8);
		assert_eq!((create_fragments(too_large, false)), Err(Error::MessageTooLarge));
	}

	#[test]
	fn insert_invalid() {
		let mut fragments = MessageCollection::new();
		assert_eq!(fragments.insert_fragment(vec![], None), Err(Error::BadFragment));
		assert_eq!(fragments.insert_fragment(vec![42], None), Err(Error::BadFragment));
		let empty_packet = [0u8; FRAGMENT_PACKET_SIZE].to_vec();
		assert_eq!(fragments.insert_fragment(empty_packet, None), Err(Error::BadFragment));
	}

	#[test]
	fn create_cover() {
		let mut rng = rand::thread_rng();
		let fragment = create_cover_fragment(&mut rng);
		assert_eq!(fragment.len(), FRAGMENT_PACKET_SIZE);
	}

	#[test]
	fn cleanup() {
		let mut fragments = MessageCollection::new();
		fragments.expiration = Duration::from_millis(0);
		let mut message = Vec::new();
		message.resize(FRAGMENT_PACKET_SIZE * 2, 0u8);
		let message_fragments = create_fragments(message, false).unwrap();
		assert_eq!(fragments.insert_fragment(message_fragments[0].clone(), None).unwrap(), None);
		assert_eq!(1, fragments.messages.len());
		fragments.cleanup();
		assert_eq!(0, fragments.messages.len());
	}
}
