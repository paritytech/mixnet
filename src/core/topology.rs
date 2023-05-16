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

//! Mixnet topology. A new [`Topology`] is created for every session.

use super::sphinx::{
	KxPublic, MixnodeIndex, PeerId, RawMixnodeIndex, Target, MAX_HOPS, MAX_MIXNODE_INDEX,
};
use arrayvec::ArrayVec;
use either::Either;
use multiaddr::Multiaddr;
use rand::{seq::SliceRandom, CryptoRng, Rng};
use std::{
	cmp::{max, min},
	fmt,
};

/// Key-exchange public key, peer ID, and external addresses for a mixnode.
#[derive(Clone)]
pub struct Mixnode {
	/// Key-exchange public key for the mixnode.
	pub kx_public: KxPublic,
	/// Peer ID for the mixnode.
	pub peer_id: PeerId,
	/// External addresses for the mixnode.
	pub external_addresses: Vec<Multiaddr>,
}

enum LocalNode {
	/// The local node is a mixnode, with the specified index.
	Mixnode(MixnodeIndex),
	/// The local node is not a mixnode. It should attempt to connect to the specified gateway
	/// mixnodes.
	NonMixnode(Vec<MixnodeIndex>),
}

/// Topology error.
#[derive(Debug, thiserror::Error)]
pub enum TopologyErr {
	/// An out-of-range mixnode index was encountered.
	#[error("Bad mixnode index ({0})")]
	BadMixnodeIndex(MixnodeIndex),
	/// There aren't enough mixnodes.
	#[error("Too few mixnodes; this should have been caught earlier")]
	TooFewMixnodes,
	/// The local node has not managed to connect to any gateway mixnodes.
	#[error("The local node has not managed to connect to any gateway mixnodes")]
	NoConnectedGatewayMixnodes,
}

pub struct Topology {
	mixnodes: Vec<Mixnode>,
	local_kx_public: KxPublic,
	local_node: LocalNode,
}

impl Topology {
	/// `mixnodes` must be no longer than [`MAX_MIXNODE_INDEX + 1`](MAX_MIXNODE_INDEX).
	pub fn new(
		rng: &mut impl Rng,
		mixnodes: Vec<Mixnode>,
		local_kx_public: &KxPublic,
		num_gateway_mixnodes: u32,
	) -> Self {
		debug_assert!(mixnodes.len() <= (MAX_MIXNODE_INDEX + 1) as usize);

		// Determine if the local node is a mixnode. It is possible for another node to publish our
		// key-exchange public key as theirs, possibly resulting in a bogus index here. This isn't
		// particularly harmful so we don't bother doing anything about it:
		//
		// - It might result in us thinking we're in the mixnode set when we're really not. Note
		//   that this situation can only occur if we were trying to register anyway; if we weren't,
		//   we wouldn't have even generated our key-exchange keys before session registration
		//   ended.
		// - We might attempt to connect to ourselves or include ourselves as a hop in packets we
		//   send. While this is usually avoided, it isn't a big deal.
		let local_node = mixnodes
			.iter()
			.position(|mixnode| &mixnode.kx_public == local_kx_public)
			.map_or_else(
				|| {
					// Local node is not a mixnode. Pick some gateway mixnodes to connect to.
					LocalNode::NonMixnode(
						rand::seq::index::sample(
							rng,
							mixnodes.len(),
							min(num_gateway_mixnodes as usize, mixnodes.len()),
						)
						.iter()
						.map(|index| {
							index
								.try_into()
								.expect("Topology::new() contract limits size of mixnode set")
						})
						.collect(),
					)
				},
				|index| {
					// Local node is a mixnode
					LocalNode::Mixnode(
						index
							.try_into()
							.expect("Topology::new() contract limits size of mixnode set"),
					)
				},
			);

		Self { mixnodes, local_kx_public: *local_kx_public, local_node }
	}

	pub fn is_mixnode(&self) -> bool {
		matches!(self.local_node, LocalNode::Mixnode(_))
	}

	pub fn reserved_peer_addresses(&self) -> impl Iterator<Item = &Multiaddr> {
		let indices = match &self.local_node {
			LocalNode::Mixnode(local_index) => Either::Left({
				// Connect to all other mixnodes (ie exclude the local node)
				let num = self.mixnodes.len() as RawMixnodeIndex;
				(0..local_index.get()).chain((local_index.get() + 1)..num)
			}),
			LocalNode::NonMixnode(gateway_indices) =>
				Either::Right(gateway_indices.iter().map(|index| index.get())),
		};
		indices.flat_map(|index| self.mixnodes[index as usize].external_addresses.iter())
	}

	pub fn mixnode_index_to_peer_id(&self, index: MixnodeIndex) -> Result<PeerId, TopologyErr> {
		self.mixnodes
			.get(index.get() as usize)
			.map(|mixnode| mixnode.peer_id)
			.ok_or(TopologyErr::BadMixnodeIndex(index))
	}

	pub fn target_to_peer_id(&self, target: &Target) -> Result<PeerId, TopologyErr> {
		match target {
			Target::MixnodeIndex(index) => self.mixnode_index_to_peer_id(*index),
			Target::PeerId(peer_id) => Ok(*peer_id),
		}
	}
}

impl fmt::Display for Topology {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		match &self.local_node {
			LocalNode::Mixnode(local_index) => write!(fmt, "Local node is mixnode {local_index}"),
			LocalNode::NonMixnode(gateway_indices) => {
				write!(fmt, "Local node is not a mixnode; gateway mixnodes are ")?;
				for (i, gateway_index) in gateway_indices.iter().enumerate() {
					if i == 0 {
						gateway_index.fmt(fmt)?;
					} else {
						write!(fmt, ", {gateway_index}")?;
					}
				}
				Ok(())
			},
		}
	}
}

/// A trait for querying the peer ID and connectivity of the local node.
pub trait NetworkStatus {
	/// Returns the peer ID of the local node.
	fn local_peer_id(&self) -> PeerId;
	/// Returns true iff the local node is currently connected to the specified peer.
	fn is_connected(&self, peer_id: &PeerId) -> bool;
}

const MAX_CONNECTED_GATEWAY_INDICES: usize = 5;

pub enum RouteKind {
	/// Route begins at the local node and ends at the specified mixnode.
	ToMixnode(MixnodeIndex),
	/// Route begins at the specified mixnode and ends at the local node.
	FromMixnode(MixnodeIndex),
	/// Route begins and ends at the local node.
	Loop,
}

struct UsedIndices(ArrayVec<MixnodeIndex, { MAX_HOPS + 1 }>);

impl UsedIndices {
	fn new() -> Self {
		Self(ArrayVec::new())
	}

	fn insert(&mut self, index: MixnodeIndex) {
		match self.0.iter().position(|used_index| *used_index >= index) {
			Some(i) =>
				if self.0[i] != index {
					self.0.insert(i, index);
				},
			None => self.0.push(index),
		}
	}

	fn iter(&self) -> impl ExactSizeIterator<Item = MixnodeIndex> + '_ {
		self.0.iter().copied()
	}

	fn as_option(&self) -> Option<MixnodeIndex> {
		debug_assert!(self.0.len() <= 1);
		self.0.first().copied()
	}
}

pub struct RouteGenerator<'topology> {
	topology: &'topology Topology,
	local_peer_id: PeerId,
	/// Always empty if the local node is a mixnode. Otherwise, the subset of the gateway mixnodes
	/// from the topology that are currently connected.
	connected_gateway_indices: ArrayVec<MixnodeIndex, MAX_CONNECTED_GATEWAY_INDICES>,
}

impl<'topology> RouteGenerator<'topology> {
	pub fn new(topology: &'topology Topology, ns: &dyn NetworkStatus) -> Self {
		let connected_gateway_indices = match &topology.local_node {
			LocalNode::Mixnode(_) => ArrayVec::new(),
			// If we're not a mixnode, we should have attempted to connect to a number of "gateway"
			// mixnodes. As we compete with other nodes for slots we might not have managed to
			// connect to all of them. Check which ones we managed to connect to.
			LocalNode::NonMixnode(gateway_indices) => gateway_indices
				.iter()
				.copied()
				.filter(|gateway_index| {
					let mixnode = &topology.mixnodes[gateway_index.get() as usize];
					ns.is_connected(&mixnode.peer_id)
				})
				.take(MAX_CONNECTED_GATEWAY_INDICES)
				.collect(),
		};

		Self { topology, local_peer_id: ns.local_peer_id(), connected_gateway_indices }
	}

	pub fn topology(&self) -> &'topology Topology {
		self.topology
	}

	/// Choose a random mixnode and return its index. Exclude mixnodes with indices in
	/// `exclude_indices` from consideration. `exclude_indices` must be sorted and must not contain
	/// duplicate or invalid indices.
	fn choose_mixnode_index(
		&self,
		rng: &mut (impl Rng + CryptoRng),
		exclude_indices: impl ExactSizeIterator<Item = MixnodeIndex>,
	) -> Result<MixnodeIndex, TopologyErr> {
		let num_allowed =
			self.topology
				.mixnodes
				.len()
				.checked_sub(exclude_indices.len())
				.expect("No duplicate or invalid indices in exclude_indices") as RawMixnodeIndex;
		if num_allowed == 0 {
			return Err(TopologyErr::TooFewMixnodes)
		}

		let mut chosen = rng.gen_range(0, num_allowed);
		for exclude_index in exclude_indices {
			if chosen >= exclude_index.get() {
				chosen += 1;
			}
		}
		// At most exclude_indices.len() added in loop, and chosen was less than
		// self.topology.mixnodes.len() - exclude_indices.len() before the loop
		debug_assert!((chosen as usize) < self.topology.mixnodes.len());

		Ok(chosen.try_into().expect("Topology::new() contract limits size of mixnode set"))
	}

	/// Choose a random mixnode to send a message to and return its index.
	pub fn choose_destination_index(
		&self,
		rng: &mut (impl Rng + CryptoRng),
	) -> Result<MixnodeIndex, TopologyErr> {
		let exclude_index = match self.topology.local_node {
			// If we're a mixnode, don't send to ourselves
			LocalNode::Mixnode(local_index) => Some(local_index),
			// If we're not a mixnode, and we are only connected to one gateway mixnode, don't send
			// to it; it must be the first hop, and we don't want to visit any node more than once
			LocalNode::NonMixnode(_) => match self.connected_gateway_indices.as_slice() {
				[gateway_index] => Some(*gateway_index),
				_ => None,
			},
		};
		self.choose_mixnode_index(rng, exclude_index.iter().copied())
	}

	fn choose_connected_gateway_index(
		&self,
		rng: &mut (impl Rng + CryptoRng),
		try_exclude_index: Option<MixnodeIndex>,
	) -> Result<MixnodeIndex, TopologyErr> {
		try_exclude_index
			.and_then(|try_exclude_index| {
				if !self.connected_gateway_indices.iter().any(|index| *index == try_exclude_index) {
					// Mixnode to exclude is not a connected gateway
					return None
				}
				let (&first, rest) = self.connected_gateway_indices.split_first()?;
				let Some(&chosen) = rest.choose(rng) else {
					// Only one connected gateway; must use regardless of try_exclude_index
					return Some(first)
				};
				// try_exclude_index is either first or in rest. If we chose it from rest, replace
				// it with first.
				Some(if chosen == try_exclude_index { first } else { chosen })
			})
			.or_else(|| self.connected_gateway_indices.choose(rng).copied())
			.ok_or(TopologyErr::NoConnectedGatewayMixnodes)
	}

	/// Generate a route through the mixnet. Returns the mixnode index of the first hop. The route
	/// may contain more hops than `num_hops` if this is necessary.
	pub fn gen_route(
		&self,
		targets: &mut ArrayVec<Target, { MAX_HOPS - 1 }>,
		their_kx_publics: &mut ArrayVec<KxPublic, MAX_HOPS>,
		rng: &mut (impl Rng + CryptoRng),
		kind: RouteKind,
		num_hops: usize,
	) -> Result<MixnodeIndex, TopologyErr> {
		// Mixnode indices we've used already. We avoid using any mixnode more than once.
		let mut used_indices = UsedIndices::new();

		let (from_local, to_local) = match kind {
			RouteKind::ToMixnode(index) => {
				used_indices.insert(index);
				(true, false)
			},
			RouteKind::FromMixnode(index) => {
				used_indices.insert(index);
				(false, true)
			},
			RouteKind::Loop => (true, true),
		};

		// If we're a mixnode, make sure we don't include ourselves in the route
		debug_assert!(from_local || to_local);
		if let LocalNode::Mixnode(index) = self.topology.local_node {
			used_indices.insert(index);
		}

		// If we're not a mixnode, and the packet is to be sent by us, the first hop needs to be to
		// a connected gateway mixnode
		let special_first_index = match self.topology.local_node {
			LocalNode::NonMixnode(_) if from_local => {
				let index = self.choose_connected_gateway_index(rng, used_indices.as_option())?;
				used_indices.insert(index);
				Some(index)
			},
			_ => None,
		};

		// If we're not a mixnode, and the packet is to be received by us, the last hop needs to be
		// from a connected gateway mixnode
		let special_penultimate_index = match self.topology.local_node {
			LocalNode::NonMixnode(_) if to_local => {
				let index = self.choose_connected_gateway_index(rng, used_indices.as_option())?;
				used_indices.insert(index);
				Some(index)
			},
			_ => None,
		};

		let min_hops = [
			// Special first hop
			special_first_index.is_some(),
			// Intermediate hop required if special first and penultimate hops to same mixnode
			// (this can only happen with RouteKind::Loop)
			special_first_index.is_some() && (special_first_index == special_penultimate_index),
			// Special penultimate hop
			special_penultimate_index.is_some(),
			// Last hop
			true,
		]
		.iter()
		.map(|need_hop| *need_hop as usize)
		.sum();
		let num_hops = max(num_hops, min_hops);

		let mut first_index = None;
		for i in 0..num_hops {
			// Figure out the hop target. This is either a mixnode index (Some) or the local node
			// (None).
			let mut index = match (i, num_hops - i, special_first_index, special_penultimate_index)
			{
				// Special first hop
				(0, _, Some(index), _) => Some(index),
				// Special penultimate hop
				(_, 2, _, Some(index)) => Some(index),
				// Last hop
				(_, 1, _, _) => match kind {
					RouteKind::ToMixnode(index) => Some(index),
					RouteKind::FromMixnode(_) => None,
					RouteKind::Loop => None,
				},
				// Intermediate hop
				_ => {
					let index = self.choose_mixnode_index(rng, used_indices.iter())?;
					used_indices.insert(index);
					Some(index)
				},
			};

			// Push the key-exchange public key for the target
			their_kx_publics.push(match index {
				Some(index) => self.topology.mixnodes[index.get() as usize].kx_public,
				None => self.topology.local_kx_public,
			});

			// Push the target
			if index.is_none() {
				// Target is the local node. If the local node is a mixnode, use its index.
				if let LocalNode::Mixnode(local_index) = self.topology.local_node {
					index = Some(local_index);
				}
			}
			if i == 0 {
				// First hop should always be to a mixnode
				debug_assert!(index.is_some());
				first_index = index;
			} else {
				targets.push(match index {
					Some(index) => Target::MixnodeIndex(index),
					None => Target::PeerId(self.local_peer_id),
				});
			}
		}

		Ok(first_index.expect("At least one hop"))
	}
}
