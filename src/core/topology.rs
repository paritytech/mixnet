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

use crate::{core::NetworkPeerId, Error, MixPeerId, MixPublicKey, SendOptions};
use rand::Rng;

/// Provide network topology information to the mixnet.
pub trait Topology: Sized + Send + 'static {
	/// Select a random recipient for the message to be delivered. This is
	/// called when the user sends the message with no recipient specified.
	/// E.g. this can select a random validator that can accept the blockchain
	/// transaction into the block.
	/// Return `None` if no such selection is possible.
	fn random_recipient(
		&self,
		local_id: &MixPeerId,
		send_options: &SendOptions,
	) -> Option<(MixPeerId, MixPublicKey)>;

	/// For a given peer return a list of peers it is supposed to be connected to.
	/// Return `None` if peer is not routing.
	fn neighbors(&self, id: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>>;

	/// Check if a peer is in topology, do not need to be connected.
	fn is_routing(&self, id: &MixPeerId) -> bool {
		self.neighbors(id).is_some()
	}

	/// first hop nodes that may currently allow external node connection.
	fn first_hop_nodes_external(
		&self,
		_from: &MixPeerId,
		_to: &MixPeerId,
	) -> Vec<(MixPeerId, MixPublicKey)>;

	/// Check if a peer is in topology, do not need to be connected.
	fn is_first_node(&self, _id: &MixPeerId) -> bool;

	/// If external is allowed, it returns a ratio of
	/// routing node bandwidth to use.
	fn allowed_external(&self, _id: &MixPeerId) -> Option<(usize, usize)> {
		None
	}

	/// Check node links.
	fn routing_to(&self, from: &MixPeerId, to: &MixPeerId) -> bool;

	/// Random message path.
	/// Warning number of hops is indicative and for some topology
	/// could be higher (eg if `start` or `recipient` are not routing
	/// a hop should be added).
	///
	/// Default implementation is taking random of all possible path.
	fn random_path(
		&mut self,
		start_node: (&MixPeerId, Option<&MixPublicKey>),
		recipient_node: (&MixPeerId, Option<&MixPublicKey>),
		count: usize,
		num_hops: usize,
		max_hops: usize,
		last_query_if_surb: Option<&Vec<(MixPeerId, MixPublicKey)>>,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
		if num_hops > max_hops {
			return Err(Error::TooManyHops)
		}
		let mut rng = rand::thread_rng();
		let mut add_start = None;
		let mut add_end = None;
		let start = if self.is_first_node(start_node.0) {
			*start_node.0
		} else {
			let firsts = self.first_hop_nodes_external(start_node.0, recipient_node.0);
			if firsts.is_empty() {
				return Err(Error::NoPath(Some(*recipient_node.0)))
			}
			let n: usize = rng.gen_range(0..firsts.len());
			add_start = Some(firsts[n]);
			firsts[n].0
		};
		let recipient = if self.is_routing(recipient_node.0) {
			*recipient_node.0
		} else if let Some(query) = last_query_if_surb {
			// reuse a node that was recently connected.
			if let Some(rec) = query.get(0) {
				add_end = Some(recipient_node);
				rec.0
			} else {
				return Err(Error::NoPath(Some(*recipient_node.0)))
			}
		} else {
			return Err(Error::NoPath(Some(*recipient_node.0)))
		};
		// Generate all possible paths and select one at random
		let mut partial = Vec::new();
		let mut paths = Vec::new();
		gen_paths(self, &mut partial, &mut paths, &start, &recipient, num_hops);

		if paths.is_empty() {
			return Err(Error::NoPath(Some(recipient)))
		}

		let mut result = Vec::new();
		while result.len() < count {
			// TODO path pool could be persisted, but at this point this implementation
			// is not really targetted.
			let n: usize = rng.gen_range(0..paths.len());
			let mut path = paths[n].clone();
			if let Some((peer, key)) = add_start {
				path.insert(0, (peer, key));
			}
			if let Some((peer, key)) = add_end {
				if let Some(key) = key {
					path.push((*peer, *key));
				} else {
					return Err(Error::NoPath(Some(*recipient_node.0)))
				}
			}
			result.push(path);
		}
		log::trace!(target: "mixnet", "Random path {:?}", result);
		Ok(result)
	}

	/// On connection successful handshake.
	fn connected(&mut self, id: MixPeerId, public_key: MixPublicKey);

	/// On disconnect.
	fn disconnect(&mut self, id: &MixPeerId);

	fn handshake_size(&self) -> usize;

	fn check_handshake(
		&mut self,
		payload: &[u8],
		from: &NetworkPeerId,
	) -> Option<(MixPeerId, MixPublicKey)>;

	/// On handshake, can extract peer id and publickey.
	///
	/// Return None if peer is filtered by network id.
	fn handshake(&mut self, with: &NetworkPeerId, public_key: &MixPublicKey) -> Option<Vec<u8>>;

	/// Utils that should be call when using `check_handshake`.
	fn accept_peer(&self, local_id: &MixPeerId, peer_id: &MixPeerId) -> bool {
		self.routing_to(local_id, peer_id) ||
			self.routing_to(peer_id, local_id) ||
			self.allowed_external(peer_id).is_some()
	}
}

fn gen_paths<T: Topology>(
	topology: &T,
	partial: &mut Vec<(MixPeerId, MixPublicKey)>,
	paths: &mut Vec<Vec<(MixPeerId, MixPublicKey)>>,
	last: &MixPeerId,
	target: &MixPeerId,
	num_hops: usize,
) {
	let neighbors = topology.neighbors(last).unwrap_or_default();
	for (id, key) in neighbors {
		if partial.len() < num_hops - 1 {
			partial.push((id, key));
			gen_paths(topology, partial, paths, &id, target, num_hops);
			partial.pop();
		}

		if partial.len() == num_hops - 1 {
			// About to complete path. Only select paths that end up at target.
			if &id != target {
				continue
			}
			partial.push((id, key));
			paths.push(partial.clone());
			partial.pop();
		}
	}
}

/// No topology try direct connection.
pub struct NoTopology {
	pub connected_peers: std::collections::HashMap<MixPeerId, MixPublicKey>,
}

impl Topology for NoTopology {
	fn random_recipient(
		&self,
		from: &MixPeerId,
		_: &SendOptions,
	) -> Option<(MixPeerId, MixPublicKey)> {
		use rand::prelude::IteratorRandom;
		let mut rng = rand::thread_rng();
		// Select a random connected peer
		self.connected_peers
			.iter()
			.filter(|(k, _v)| k != &from)
			.choose(&mut rng)
			.map(|(k, v)| (*k, *v))
	}

	fn allowed_external(&self, _id: &MixPeerId) -> Option<(usize, usize)> {
		Some((1, 1))
	}

	fn random_path(
		&mut self,
		_start: (&MixPeerId, Option<&MixPublicKey>),
		recipient: (&MixPeerId, Option<&MixPublicKey>),
		count: usize,
		_num_hops: usize,
		_max_hops: usize,
		_last_query_if_surb: Option<&Vec<(MixPeerId, MixPublicKey)>>,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
		log::warn!(target: "mixnet", "No topology, direct transmission");
		// No topology is defined. Check if direct connection is possible.
		match self.connected_peers.get(recipient.0) {
			Some(key) => Ok(vec![vec![(*recipient.0, *key)]; count]),
			_ => Err(Error::NoPath(Some(*recipient.0))),
		}
	}

	fn neighbors(&self, _id: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>> {
		None
	}

	// first hop that allow external node connection.
	fn first_hop_nodes_external(
		&self,
		_from: &MixPeerId,
		_to: &MixPeerId,
	) -> Vec<(MixPeerId, MixPublicKey)> {
		Vec::new()
	}

	fn is_first_node(&self, _id: &MixPeerId) -> bool {
		true
	}

	fn routing_to(&self, _from: &MixPeerId, _to: &MixPeerId) -> bool {
		true
	}

	fn connected(&mut self, id: MixPeerId, key: MixPublicKey) {
		self.connected_peers.insert(id, key);
	}

	fn disconnect(&mut self, id: &MixPeerId) {
		self.connected_peers.remove(id);
	}

	fn handshake_size(&self) -> usize {
		32
	}

	fn check_handshake(
		&mut self,
		payload: &[u8],
		from: &NetworkPeerId,
	) -> Option<(MixPeerId, MixPublicKey)> {
		let peer_id = crate::core::to_sphinx_id(from).ok()?;
		let mut pk = [0u8; crate::core::PUBLIC_KEY_LEN];
		pk.copy_from_slice(payload);
		let pk = MixPublicKey::from(pk);
		Some((peer_id, pk))
	}

	fn handshake(&mut self, _with: &NetworkPeerId, public_key: &MixPublicKey) -> Option<Vec<u8>> {
		Some(public_key.to_bytes().to_vec())
	}
}
