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

use crate::{core::MixPublicKey, MixPeerId, core::MixPeerAddress};
use rand::{prelude::{SliceRandom, IteratorRandom}, CryptoRng, Rng};

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

	pub fn gateways<R: Rng + CryptoRng + ?Sized>(&self, rng: &mut R) -> Vec<MixPeerAddress> {
		self.nodes
			.as_slice()
			.choose_multiple(rng, 5)
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
		let (_, first_pk, _) = self.nodes.iter().find(|(id, _, _)| id == start)?;
		let (_, last_pk, _) = self.nodes.iter().find(|(id, _, _)| id == start)?;

		let mut result = vec![(start.clone(), first_pk.clone())];
		let mut next = start.clone();
		let mut next_pk = first_pk.clone();
		for _ in 0 .. num_hops - 1 {
			while result.last().unwrap().0 == next {
				(next, next_pk, _)= *self.nodes.as_slice().choose(rng)?;
			}
			result.push((next, next_pk));
		}
		result.push((recipient.clone(), last_pk.clone()));
		Some(result)
	}
}
