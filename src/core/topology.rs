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

//! Mixnet topology interface.

use crate::{
	core::{MixPeerAddress, MixPublicKey},
	MixPeerId,
};
use rand::{
	prelude::{IteratorRandom, SliceRandom},
	CryptoRng, Rng,
};

const NUM_GATEWAYS: usize = 5;

/// Contains network information. Current implementation assumes that each node
/// in the set is connected to every other node.
#[derive(Default)]
pub struct SessionTopology {
	nodes: Vec<(MixPeerId, MixPublicKey, Vec<MixPeerAddress>)>,
}

impl SessionTopology {
	pub fn new(nodes: Vec<(MixPeerId, MixPublicKey, Vec<MixPeerAddress>)>) -> Self {
		Self { nodes }
	}

	pub fn random_recipient<R: Rng + CryptoRng + ?Sized>(&self, rng: &mut R) -> Option<MixPeerId> {
		self.nodes.iter().choose(rng).map(|(id, _, _)| id.clone())
	}

	/// If the node isn't part of the topology this returns a set of gateway addresses to connect
	/// to.
	pub fn gateways<R: Rng + CryptoRng + ?Sized>(&self, rng: &mut R) -> Vec<MixPeerAddress> {
		self.nodes
			.as_slice()
			.choose_multiple(rng, NUM_GATEWAYS)
			.map(|(_, _, addrs)| addrs.clone())
			.flatten()
			.collect()
	}

	pub fn random_path_to<R: Rng + CryptoRng + ?Sized>(
		&self,
		rng: &mut R,
		start: &MixPeerId,
		recipient: &MixPeerId,
		num_hops: usize,
	) -> Option<Vec<(MixPeerId, MixPublicKey)>> {
		let (_, start_pk, _) = self.nodes.iter().find(|(id, _, _)| id == start)?;
		let (_, last_pk, _) = self.nodes.iter().find(|(id, _, _)| id == recipient)?;

		let mut result = vec![];
		let mut prev = *start;
		let mut next = *start;
		let mut next_pk = *start_pk;
		for i in 0..num_hops - 1 {
			while next == prev || (i == num_hops - 2 && next == *recipient) {
				(next, next_pk, _) = *self.nodes.as_slice().choose(rng)?;
			}
			result.push((next, next_pk));
			prev = next;
		}
		result.push((recipient.clone(), last_pk.clone()));
		Some(result)
	}
}
