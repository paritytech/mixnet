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

//! Mixnet packet queues.

use super::sphinx::{Packet, PeerId};
use std::{
	cmp::Ordering,
	collections::{BinaryHeap, VecDeque},
	time::Instant,
};

/// A packet plus the ID of the peer it should be sent to.
pub struct AddressedPacket {
	/// Where the packet should be sent.
	pub peer_id: PeerId,
	/// The packet contents.
	pub packet: Box<Packet>,
}

pub struct ForwardPacket {
	/// When the packet should be sent.
	pub deadline: Instant,
	/// The packet and destination.
	pub packet: AddressedPacket,
}

impl PartialEq for ForwardPacket {
	fn eq(&self, other: &Self) -> bool {
		self.deadline == other.deadline
	}
}

impl Eq for ForwardPacket {}

impl PartialOrd for ForwardPacket {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for ForwardPacket {
	fn cmp(&self, other: &Self) -> Ordering {
		// Packets with the earliest deadline considered greatest
		self.deadline.cmp(&other.deadline).reverse()
	}
}

pub struct ForwardPacketQueue {
	/// Maximum number of packets in the queue. This should match the capacity of `queue`, but we
	/// don't rely on that.
	capacity: usize,
	queue: BinaryHeap<ForwardPacket>,
}

impl ForwardPacketQueue {
	pub fn new(capacity: usize) -> Self {
		Self { capacity, queue: BinaryHeap::with_capacity(capacity) }
	}

	pub fn next_deadline(&self) -> Option<Instant> {
		self.queue.peek().map(|packet| packet.deadline)
	}

	pub fn remaining_capacity(&self) -> usize {
		self.capacity.saturating_sub(self.queue.len())
	}

	/// Insert a packet into the queue. Returns true iff the deadline of the item at the head of
	/// the queue changed. Should only be called if there is space in the queue (see
	/// [`remaining_capacity`](Self::remaining_capacity)).
	pub fn insert(&mut self, packet: ForwardPacket) -> bool {
		debug_assert!(self.queue.len() < self.capacity);
		let prev_deadline = self.next_deadline();
		self.queue.push(packet);
		self.next_deadline() != prev_deadline
	}

	pub fn pop(&mut self) -> Option<ForwardPacket> {
		self.queue.pop()
	}
}

pub struct AuthoredPacketQueue {
	/// Maximum number of packets in the queue. This should match the capacity of `queue`, but we
	/// don't rely on that.
	capacity: usize,
	queue: VecDeque<AddressedPacket>,
}

impl AuthoredPacketQueue {
	pub fn new(capacity: usize) -> Self {
		Self { capacity, queue: VecDeque::with_capacity(capacity) }
	}

	pub fn len(&self) -> usize {
		self.queue.len()
	}

	pub fn capacity(&self) -> usize {
		self.capacity
	}

	pub fn remaining_capacity(&self) -> usize {
		self.capacity.saturating_sub(self.queue.len())
	}

	/// Push a packet onto the queue. Should only be called if there is space in the queue (see
	/// [`remaining_capacity`](Self::remaining_capacity)).
	pub fn push(&mut self, packet: AddressedPacket) {
		debug_assert!(self.queue.len() < self.capacity);
		self.queue.push_back(packet);
	}

	pub fn pop(&mut self) -> Option<AddressedPacket> {
		self.queue.pop_front()
	}
}
