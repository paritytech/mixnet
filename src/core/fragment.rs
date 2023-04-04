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

//! Mixnet message fragment handling.

use super::{
	scattered::Scattered,
	sphinx::{Surb, PAYLOAD_DATA_SIZE, SURB_SIZE},
};
use arrayref::{array_mut_ref, array_refs, mut_array_refs};
use hashlink::{linked_hash_map::Entry, LinkedHashMap};
use log::{error, log, warn, Level};
use std::cmp::{max, min};

/// Size in bytes of a [`MessageId`].
pub const MESSAGE_ID_SIZE: usize = 16;
/// Message identifier. Should be randomly generated. Attached to fragments to enable reassembly.
/// May also be used to identify replies.
pub type MessageId = [u8; MESSAGE_ID_SIZE];
const FRAGMENT_INDEX_SIZE: usize = 2;
type FragmentIndex = u16;
const FRAGMENT_DATA_SIZE_SIZE: usize = 2;
type FragmentDataSize = u16;
const FRAGMENT_NUM_SURBS_SIZE: usize = 1;
type FragmentNumSurbs = u8;
const FRAGMENT_HEADER_SIZE: usize = MESSAGE_ID_SIZE +
	FRAGMENT_INDEX_SIZE + // Last fragment index (number of fragments - 1)
	FRAGMENT_INDEX_SIZE + // Index of this fragment
	FRAGMENT_DATA_SIZE_SIZE + // Number of data bytes in this fragment
	FRAGMENT_NUM_SURBS_SIZE; // Number of SURBs in this fragment

pub const FRAGMENT_SIZE: usize = PAYLOAD_DATA_SIZE;
pub type Fragment = [u8; FRAGMENT_SIZE];
const FRAGMENT_PAYLOAD_SIZE: usize = FRAGMENT_SIZE - FRAGMENT_HEADER_SIZE;
type FragmentPayload = [u8; FRAGMENT_PAYLOAD_SIZE];
const MAX_SURBS_PER_FRAGMENT: usize = FRAGMENT_PAYLOAD_SIZE / SURB_SIZE;

#[allow(clippy::type_complexity)]
fn split_fragment(
	fragment: &Fragment,
) -> (
	&MessageId,
	&[u8; FRAGMENT_INDEX_SIZE],
	&[u8; FRAGMENT_INDEX_SIZE],
	&[u8; FRAGMENT_DATA_SIZE_SIZE],
	&[u8; FRAGMENT_NUM_SURBS_SIZE],
	&FragmentPayload,
) {
	array_refs![
		fragment,
		MESSAGE_ID_SIZE,
		FRAGMENT_INDEX_SIZE,
		FRAGMENT_INDEX_SIZE,
		FRAGMENT_DATA_SIZE_SIZE,
		FRAGMENT_NUM_SURBS_SIZE,
		FRAGMENT_PAYLOAD_SIZE
	]
}

fn message_id(fragment: &Fragment) -> &MessageId {
	split_fragment(fragment).0
}

fn num_fragments(fragment: &Fragment) -> usize {
	(FragmentIndex::from_le_bytes(*split_fragment(fragment).1) as usize) + 1
}

fn fragment_index(fragment: &Fragment) -> usize {
	FragmentIndex::from_le_bytes(*split_fragment(fragment).2) as usize
}

fn fragment_data_size(fragment: &Fragment) -> usize {
	FragmentDataSize::from_le_bytes(*split_fragment(fragment).3) as usize
}

fn fragment_num_surbs(fragment: &Fragment) -> usize {
	FragmentNumSurbs::from_le_bytes(*split_fragment(fragment).4) as usize
}

fn fragment_payload(fragment: &Fragment) -> &FragmentPayload {
	split_fragment(fragment).5
}

#[derive(Debug, thiserror::Error)]
enum CheckFragmentErr {
	#[error("Out-of-range index ({index}, max {max})")]
	Index { index: usize, max: usize },
	#[error("Bad payload size ({size}, max {max})")]
	PayloadSize { size: usize, max: usize },
}

fn check_fragment(fragment: &Fragment) -> Result<(), CheckFragmentErr> {
	if fragment_index(fragment) >= num_fragments(fragment) {
		return Err(CheckFragmentErr::Index {
			index: fragment_index(fragment),
			max: num_fragments(fragment) - 1,
		})
	}

	let data_size = fragment_data_size(fragment);
	let num_surbs = fragment_num_surbs(fragment);
	let payload_size = data_size + (num_surbs * SURB_SIZE);
	if payload_size > FRAGMENT_PAYLOAD_SIZE {
		return Err(CheckFragmentErr::PayloadSize { size: payload_size, max: FRAGMENT_PAYLOAD_SIZE })
	}

	Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct GenericMessage {
	pub id: MessageId,
	pub data: Vec<u8>,
	pub surbs: Vec<Surb>,
}

impl GenericMessage {
	/// Construct a message from a list of fragments. The fragments must all be valid (checked by
	/// [`check_fragment`]) and in the correct order.
	fn from_fragments<'a>(fragments: impl Iterator<Item = &'a Fragment> + Clone) -> Self {
		let id = *message_id(fragments.clone().next().expect("At least one fragment"));

		let mut data = Vec::with_capacity(fragments.clone().map(fragment_data_size).sum());
		let mut surbs = Vec::with_capacity(fragments.clone().map(fragment_num_surbs).sum());
		for fragment in fragments {
			debug_assert!(check_fragment(fragment).is_ok());
			let payload = fragment_payload(fragment);
			data.extend_from_slice(&payload[..fragment_data_size(fragment)]);
			surbs.extend(
				payload
					// TODO Use array_rchunks if/when this is stabilised
					.rchunks_exact(SURB_SIZE)
					.map(|surb| {
						TryInto::<&Surb>::try_into(surb)
							.expect("All slices returned by rchunks_exact have length SURB_SIZE")
					})
					.take(fragment_num_surbs(fragment)),
			);
		}

		Self { id, data, surbs }
	}
}

#[derive(Debug, thiserror::Error)]
enum IncompleteMessageInsertErr {
	#[error("Inconsistent number of fragments for message ({0} vs {1})")]
	InconsistentNumFragments(usize, usize),
	#[error("Already have this fragment")]
	AlreadyHave,
}

struct IncompleteMessage {
	fragments: Vec<Option<Box<Fragment>>>,
	/// Count of [`Some`] in `fragments`.
	num_received_fragments: usize,
}

impl IncompleteMessage {
	fn new(num_fragments: usize) -> Self {
		Self { fragments: vec![None; num_fragments], num_received_fragments: 0 }
	}

	/// Attempt to insert `fragment`, which must be a valid fragment (checked by
	/// [`check_fragment`]). Success implies
	/// [`num_received_fragments`](Self::num_received_fragments) was incremented.
	fn insert(&mut self, fragment: &Fragment) -> Result<(), IncompleteMessageInsertErr> {
		debug_assert!(check_fragment(fragment).is_ok());

		if num_fragments(fragment) != self.fragments.len() {
			return Err(IncompleteMessageInsertErr::InconsistentNumFragments(
				num_fragments(fragment),
				self.fragments.len(),
			))
		}

		let slot = &mut self.fragments[fragment_index(fragment)];
		if slot.is_some() {
			return Err(IncompleteMessageInsertErr::AlreadyHave)
		}

		*slot = Some((*fragment).into());
		self.num_received_fragments += 1;
		debug_assert!(self.num_received_fragments <= self.fragments.len());
		Ok(())
	}

	/// Returns [`None`] if we don't have all the fragments yet. Otherwise, returns an iterator
	/// over the completed list of fragments.
	fn complete_fragments(&self) -> Option<impl Iterator<Item = &Fragment> + Clone> {
		(self.num_received_fragments == self.fragments.len()).then(|| {
			self.fragments
				.iter()
				.map(|fragment| fragment.as_ref().expect("All fragments received").as_ref())
		})
	}
}

pub struct FragmentAssembler {
	/// Incomplete messages, in LRU order: least recently used at the front, most recently at the
	/// back. All messages have at least one received fragment.
	incomplete_messages: LinkedHashMap<MessageId, IncompleteMessage>,
	/// Total number of received fragments across all messages in `incomplete_messages`.
	num_incomplete_fragments: usize,

	/// Maximum number of incomplete messages to keep in `incomplete_messages`.
	max_incomplete_messages: usize,
	/// Maximum number of received fragments to keep across all messages in `incomplete_messages`.
	max_incomplete_fragments: usize,
	/// Maximum number of fragments per message. Fragments of messages with more than this many
	/// fragments are dropped on receipt.
	max_fragments_per_message: usize,
}

impl FragmentAssembler {
	pub fn new(
		max_incomplete_messages: usize,
		max_incomplete_fragments: usize,
		max_fragments_per_message: usize,
	) -> Self {
		Self {
			incomplete_messages: LinkedHashMap::with_capacity(
				// Plus one because we only evict _after_ going over the limit
				max_incomplete_messages.saturating_add(1),
			),
			num_incomplete_fragments: 0,
			max_incomplete_messages,
			max_incomplete_fragments,
			max_fragments_per_message,
		}
	}

	fn need_eviction(&self) -> bool {
		(self.incomplete_messages.len() > self.max_incomplete_messages) ||
			(self.num_incomplete_fragments > self.max_incomplete_fragments)
	}

	/// Evict a message if we're over the messages or fragments limit. This should be called after
	/// each fragment insertion.
	fn maybe_evict(&mut self, log_target: &str) {
		if self.need_eviction() {
			warn!(target: log_target, "Too many incomplete messages; evicting LRU");
			let incomplete_message = self
				.incomplete_messages
				.pop_front()
				.expect("Over messages or fragments limit, there must be at least one message")
				.1;
			debug_assert!(
				self.num_incomplete_fragments >= incomplete_message.num_received_fragments
			);
			self.num_incomplete_fragments -= incomplete_message.num_received_fragments;
			// Called after each fragment insertion, so could only have been one message or
			// fragment over the limit. Each message has at least one received fragment, so having
			// popped a message we should now be within both limits.
			debug_assert!(!self.need_eviction());
		}
	}

	/// Attempt to insert `fragment`. If this completes a message, the completed message is
	/// returned.
	pub fn insert(&mut self, fragment: &Fragment, log_target: &str) -> Option<GenericMessage> {
		if let Err(err) = check_fragment(fragment) {
			error!(target: log_target, "Received bad fragment: {err}");
			return None
		}
		let num_fragments = num_fragments(fragment);
		if num_fragments > self.max_fragments_per_message {
			return None
		}
		if num_fragments == 1 {
			return Some(GenericMessage::from_fragments(std::iter::once(fragment)))
		}
		match self.incomplete_messages.entry(*message_id(fragment)) {
			Entry::Occupied(mut entry) => {
				let incomplete_message = entry.get_mut();
				if let Err(err) = incomplete_message.insert(fragment) {
					let level = match err {
						IncompleteMessageInsertErr::AlreadyHave => Level::Trace,
						_ => Level::Error,
					};
					log!(target: log_target, level, "Fragment insert failed: {err}");
					return None
				}
				self.num_incomplete_fragments += 1;
				let message =
					incomplete_message.complete_fragments().map(GenericMessage::from_fragments);
				if message.is_some() {
					self.num_incomplete_fragments -= entry.remove().num_received_fragments;
				} else {
					entry.to_back();
					self.maybe_evict(log_target);
				}
				message
			},
			Entry::Vacant(entry) => {
				let mut incomplete_message = IncompleteMessage::new(num_fragments);
				// Insert of first fragment cannot fail
				assert!(incomplete_message.insert(fragment).is_ok());
				entry.insert(incomplete_message);
				self.num_incomplete_fragments += 1;
				self.maybe_evict(log_target);
				None
			},
		}
	}
}

pub struct FragmentBlueprint<'a> {
	message_id: MessageId,
	last_index: FragmentIndex,
	index: FragmentIndex,
	data: Scattered<'a, u8>,
	num_surbs: FragmentNumSurbs,
}

impl<'a> FragmentBlueprint<'a> {
	pub fn write_except_surbs(&self, fragment: &mut Fragment) {
		let (message_id, last_index, index, data_size, num_surbs, payload) = mut_array_refs![
			fragment,
			MESSAGE_ID_SIZE,
			FRAGMENT_INDEX_SIZE,
			FRAGMENT_INDEX_SIZE,
			FRAGMENT_DATA_SIZE_SIZE,
			FRAGMENT_NUM_SURBS_SIZE,
			FRAGMENT_PAYLOAD_SIZE
		];

		// Write header
		*message_id = self.message_id;
		*last_index = self.last_index.to_le_bytes();
		*index = self.index.to_le_bytes();
		*data_size = (self.data.len() as FragmentDataSize).to_le_bytes();
		*num_surbs = self.num_surbs.to_le_bytes();

		// Write payload
		self.data.copy_to_slice(&mut payload[..self.data.len()]);
	}

	pub fn surbs<'fragment>(
		&self,
		fragment: &'fragment mut Fragment,
	) -> impl Iterator<Item = &'fragment mut Surb> {
		array_mut_ref![fragment, FRAGMENT_HEADER_SIZE, FRAGMENT_PAYLOAD_SIZE]
			// TODO Use array_rchunks_mut if/when this is stabilised
			.rchunks_exact_mut(SURB_SIZE)
			.map(|surb| {
				TryInto::<&mut Surb>::try_into(surb)
					.expect("All slices returned by rchunks_exact_mut have length SURB_SIZE")
			})
			.take(self.num_surbs as usize)
	}
}

// TODO Use usize::div_ceil when this is stabilised
fn div_ceil(x: usize, y: usize) -> usize {
	if x == 0 {
		0
	} else {
		((x - 1) / y) + 1
	}
}

/// Generate fragment blueprints containing the provided message ID and data and the specified
/// number of SURBs. Returns [`None`] if more fragments would be required than are possible to
/// encode. Note that the actual number of fragments supported by the receiver is likely to be
/// significantly less than this.
pub fn fragment_blueprints<'a>(
	message_id: &MessageId,
	mut data: Scattered<'a, u8>,
	mut num_surbs: usize,
) -> Option<impl ExactSizeIterator<Item = FragmentBlueprint<'a>>> {
	let message_id = *message_id;

	// Figure out how many fragments we need
	let num_fragments_for_surbs = div_ceil(num_surbs, MAX_SURBS_PER_FRAGMENT);
	let surb_fragments_unused_size = num_fragments_for_surbs.saturating_mul(FRAGMENT_PAYLOAD_SIZE) -
		num_surbs.saturating_mul(SURB_SIZE);
	let remaining_data_size = data.len().saturating_sub(surb_fragments_unused_size);
	let num_fragments_for_remaining_data = div_ceil(remaining_data_size, FRAGMENT_PAYLOAD_SIZE);
	let num_fragments =
		max(num_fragments_for_surbs.saturating_add(num_fragments_for_remaining_data), 1);

	let last_index = num_fragments - 1;
	(last_index <= (FragmentIndex::MAX as usize)).then(|| {
		(0..num_fragments).map(move |index| {
			let fragment_num_surbs = min(num_surbs, MAX_SURBS_PER_FRAGMENT);
			num_surbs -= fragment_num_surbs;
			let fragment_unused_size = FRAGMENT_PAYLOAD_SIZE - (fragment_num_surbs * SURB_SIZE);
			let fragment_data_size = min(data.len(), fragment_unused_size);
			let (fragment_data, remaining_data) = data.split_at(fragment_data_size);
			data = remaining_data;
			FragmentBlueprint {
				message_id,
				last_index: last_index as FragmentIndex,
				index: index as FragmentIndex,
				data: fragment_data,
				num_surbs: fragment_num_surbs as FragmentNumSurbs,
			}
		})
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use itertools::Itertools;
	use rand::{prelude::SliceRandom, Rng, RngCore};

	const LOG_TARGET: &str = "mixnet";

	#[test]
	fn create_and_insert_small() {
		let mut rng = rand::thread_rng();

		let id = rng.gen();
		let mut blueprints = fragment_blueprints(&id, [42].as_slice().into(), 1).unwrap();
		assert_eq!(blueprints.len(), 1);
		let blueprint = blueprints.next().unwrap();

		let mut fragment = [0; FRAGMENT_SIZE];
		blueprint.write_except_surbs(&mut fragment);
		let mut dummy_surb = [0; SURB_SIZE];
		rng.fill_bytes(&mut dummy_surb);
		{
			let mut surbs = blueprint.surbs(&mut fragment);
			*surbs.next().unwrap() = dummy_surb;
			assert!(surbs.next().is_none());
		}

		let mut fa = FragmentAssembler::new(1, usize::MAX, usize::MAX);
		assert_eq!(
			fa.insert(&fragment, LOG_TARGET),
			Some(GenericMessage { id, data: vec![42], surbs: vec![dummy_surb] })
		);
	}

	fn no_surb_fragments(message_id: &MessageId, data: &[u8]) -> Vec<Fragment> {
		fragment_blueprints(message_id, data.into(), 0)
			.unwrap()
			.map(|blueprint| {
				let mut fragment = [0; FRAGMENT_SIZE];
				blueprint.write_except_surbs(&mut fragment);
				fragment
			})
			.collect()
	}

	fn insert_fragments<'a>(
		fa: &mut FragmentAssembler,
		mut fragments: impl Iterator<Item = &'a Fragment>,
	) -> Option<GenericMessage> {
		let message = fragments.find_map(|fragment| fa.insert(fragment, LOG_TARGET));
		assert!(fragments.next().is_none());
		message
	}

	#[test]
	fn create_and_insert_large() {
		let mut rng = rand::thread_rng();

		let id = rng.gen();
		let mut data = vec![0; 60000];
		rng.fill_bytes(&mut data);
		let mut fragments = no_surb_fragments(&id, &data);
		assert_eq!(fragments.len(), 30);
		fragments.shuffle(&mut rng);

		let mut fa = FragmentAssembler::new(1, usize::MAX, usize::MAX);
		assert_eq!(
			insert_fragments(&mut fa, fragments.iter()),
			Some(GenericMessage { id, data, surbs: Vec::new() })
		);
	}

	#[test]
	fn create_too_large() {
		let too_large = vec![0; (((FragmentIndex::MAX as usize) + 1) * FRAGMENT_PAYLOAD_SIZE) + 1];
		assert!(
			fragment_blueprints(&[0; MESSAGE_ID_SIZE], too_large.as_slice().into(), 0).is_none()
		);
	}

	#[test]
	fn message_limit_eviction() {
		let mut rng = rand::thread_rng();

		let first_id = rng.gen();
		let mut first_data = vec![0; 3000];
		rng.fill_bytes(&mut first_data);
		let first_fragments = no_surb_fragments(&first_id, &first_data);

		let second_id = rng.gen();
		let mut second_data = vec![0; 3000];
		rng.fill_bytes(&mut second_data);
		let second_fragments = no_surb_fragments(&second_id, &second_data);

		let mut fa = FragmentAssembler::new(1, usize::MAX, usize::MAX);

		// One message at a time should work
		assert_eq!(
			insert_fragments(&mut fa, first_fragments.iter()),
			Some(GenericMessage { id: first_id, data: first_data, surbs: Vec::new() })
		);
		assert_eq!(
			insert_fragments(&mut fa, second_fragments.iter()),
			Some(GenericMessage { id: second_id, data: second_data, surbs: Vec::new() })
		);

		// Alternating fragments should not work due to eviction
		assert_eq!(
			insert_fragments(&mut fa, first_fragments.iter().interleave(&second_fragments)),
			None
		);
	}

	#[test]
	fn fragment_limit_eviction() {
		let mut rng = rand::thread_rng();

		let first_id = rng.gen();
		let mut first_data = vec![0; 5000];
		rng.fill_bytes(&mut first_data);
		let first_fragments = no_surb_fragments(&first_id, &first_data);

		let second_id = rng.gen();
		let mut second_data = vec![0; 5000];
		rng.fill_bytes(&mut second_data);
		let second_fragments = no_surb_fragments(&second_id, &second_data);

		// With a one-fragment limit it should not be possible to reconstruct either message
		let mut fa = FragmentAssembler::new(2, 1, usize::MAX);
		assert_eq!(insert_fragments(&mut fa, first_fragments.iter()), None);
		assert_eq!(insert_fragments(&mut fa, second_fragments.iter()), None);

		let mut fa = FragmentAssembler::new(2, 2, usize::MAX);

		// With a two-fragment limit it should be possible to reconstruct them individually
		assert_eq!(
			insert_fragments(&mut fa, first_fragments.iter()),
			Some(GenericMessage { id: first_id, data: first_data, surbs: Vec::new() })
		);
		assert_eq!(
			insert_fragments(&mut fa, second_fragments.iter()),
			Some(GenericMessage { id: second_id, data: second_data, surbs: Vec::new() })
		);

		// But not when interleaved
		assert_eq!(
			insert_fragments(&mut fa, first_fragments.iter().interleave(&second_fragments)),
			None
		);
	}
}
