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

use crate::{Error, MixPeerId, MixPublicKey};
use rand::Rng;

/// Provide network topology information to the mixnet.
pub trait Topology: Sized + Send + 'static {
	/// Select a random recipient for the message to be delivered. This is
	/// called when the user sends the message with no recipient specified.
	/// E.g. this can select a random validator that can accept the blockchain
	/// transaction into the block.
	/// Return `None` if no such selection is possible.
	fn random_recipient(&self) -> Option<MixPeerId>;

	/// For a given peer return a list of peers it is supposed to be connected to.
	/// Return `None` if peer is not routing.
	/// TODO if removing random_path default implementation, this can be removed too.
	/// These are live neighbors.
	fn neighbors(&self, id: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>>;

	/// Allowed neighbors that are not live.
	/// This method is used to try connection periodically.
	fn try_connect_neighbors(&self, _id: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>> {
		None
	}

	/// Nodes that can be first hop.
	fn first_hop_nodes(&self, _id: &MixPeerId) -> Vec<(MixPeerId, MixPublicKey)>;

	fn is_first_node(&self, _id: &MixPeerId) -> bool;

	/// If node is possibly a first hop, it can allow
	/// external request.
	fn allow_external(&self, _id: &MixPeerId) -> bool {
		false
	}

	fn publish_known_routes(&self) -> Vec<u8> {
		unimplemented!("TODO should only be use for putting route in handshake");
		// use external management otherwhise.
		// TODO would be custom handshake and limited in size? (or number of packet??)
	}

	fn import_known_routes(&mut self, _encoded_routes: Vec<u8>) {
		unimplemented!("TODO should only be use for putting route in handshake");
		// use external management otherwhise.
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
		&self,
		start: &MixPeerId,
		recipient: &MixPeerId,
		count: usize,
		num_hops: usize,
		max_hops: usize,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
		if num_hops > max_hops {
			return Err(Error::TooManyHops)
		}
		// Generate all possible paths and select one at random
		let mut partial = Vec::new();
		let mut paths = Vec::new();
		gen_paths(self, &mut partial, &mut paths, start, recipient, num_hops);

		if paths.is_empty() {
			return Err(Error::NoPath(Some(*recipient)))
		}

		let mut rng = rand::thread_rng();
		let mut result = Vec::new();
		while result.len() < count {
			// TODO path pool could be persisted, but at this point this implementation
			// is not really targetted.
			let n: usize = rng.gen_range(0..paths.len());
			result.push(paths[n].clone());
		}
		log::trace!(target: "mixnet", "Random path {:?}", result);
		Ok(result)
	}

	/// Random message cover path.
	///
	/// Default implementation is a single hop that is only fine
	/// for topology with all node with same role.
	/// TODO remove this default.
	fn random_cover_path(&self, local_id: &MixPeerId) -> Vec<(MixPeerId, MixPublicKey)> {
		// Select a random connected peer
		let neighbors = self.neighbors(local_id).unwrap_or_default();

		if neighbors.is_empty() {
			return Vec::new()
		}

		let mut rng = rand::thread_rng();
		let n: usize = rng.gen_range(0..neighbors.len());
		vec![neighbors[n].clone()]
	}

	/// On connection successful handshake.
	fn connected(&mut self, id: MixPeerId, public_key: MixPublicKey);

	/// On disconnect.
	fn disconnect(&mut self, id: &MixPeerId);
}

fn gen_paths<T: Topology>(
	topology: &T,
	partial: &mut Vec<(MixPeerId, MixPublicKey)>,
	paths: &mut Vec<Vec<(MixPeerId, MixPublicKey)>>,
	last: &MixPeerId,
	target: &MixPeerId,
	num_hops: usize,
) {
	let neighbors = topology.neighbors(&last).unwrap_or_default();
	for (id, key) in neighbors {
		if partial.len() < num_hops - 1 {
			partial.push((id.clone(), key));
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
	fn random_recipient(&self) -> Option<MixPeerId> {
		use rand::prelude::IteratorRandom;
		let mut rng = rand::thread_rng();
		// Select a random connected peer
		self.connected_peers.keys().choose(&mut rng).cloned()
	}

	fn random_path(
		&self,
		_start: &MixPeerId,
		recipient: &MixPeerId,
		count: usize,
		_num_hops: usize,
		_max_hops: usize,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
		log::warn!(target: "mixnet", "No topology, direct transmission");
		// No topology is defined. Check if direct connection is possible.
		match self.connected_peers.get(&recipient) {
			Some(key) => return Ok(vec![vec![(*recipient, key.clone())]; count]),
			_ => return Err(Error::NoPath(Some(*recipient))),
		}
	}

	fn random_cover_path(&self, _local_id: &MixPeerId) -> Vec<(MixPeerId, MixPublicKey)> {
		let neighbors = self
			.connected_peers
			.iter()
			.map(|(id, key)| (id.clone(), key.clone()))
			.collect::<Vec<_>>();
		if neighbors.is_empty() {
			return Vec::new()
		}

		let mut rng = rand::thread_rng();
		let n: usize = rng.gen_range(0..neighbors.len());
		vec![neighbors[n].clone()]
	}

	fn neighbors(&self, _id: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>> {
		None
	}

	fn first_hop_nodes(&self, _id: &MixPeerId) -> Vec<(MixPeerId, MixPublicKey)> {
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
}
