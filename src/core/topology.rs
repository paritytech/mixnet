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
	/// If topology is not active, we use direct connection.
	const ACTIVE: bool = true;

	/// Content shared in the swarm specific to topology.
	/// TODO this is currently unused: remove? can be of use.
	type ConnectionInfo;

	/// Select a random recipient for the message to be delivered. This is
	/// called when the user sends the message with no recipient specified.
	/// E.g. this can select a random validator that can accept the blockchain
	/// transaction into the block.
	/// Return `None` if no such selection is possible.
	fn random_recipient(&self) -> Option<MixPeerId>;

	/// For a given peer return a list of peers it is supposed to be connected to.
	/// Return `None` if peer is not routing.
	/// TODO when `None` allow sending even if not part of topology but in the mixnet:
	/// external hop for latest (see gen_path function). Then last hop will expose
	/// a new connection, so it need to be an additional hop (if possible).
	///
	/// TODO change to return a iter (avoid costy implementation by api design).
	///
	/// TODO if removing random_path default implementation, this can be removed too.
	fn neighbors(&self, id: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>>;

	/// Indicate if we are currently a node that is routing message.
	fn routing(&self) -> bool;

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
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
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
			// TODO this path pool looks fishy: should persist or it is very costy for nothing
			// actually would make sense to put in topology: in a star where neighbor fn return
			// same thing for every one it is full useless. In layer, maybe we want
			// to favor some nodes in first hop due to later possibles.
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

	/// Append connection infos to a handshake message.
	fn encoded_connection_info(info: &Self::ConnectionInfo) -> Vec<u8>;

	/// Read connection info from a message, return `None` if missing or
	/// extra data remaining.
	fn read_connection_info(encoded: &[u8]) -> Option<Self::ConnectionInfo>;

	/// On connection successful handshake.
	fn connected(
		&mut self,
		id: MixPeerId,
		public_key: MixPublicKey,
		connection_info: Self::ConnectionInfo,
	);

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

/// No specific topology defined, we use all connected peers instead.
pub struct NoTopology;

impl Topology for NoTopology {
	const ACTIVE: bool = false;

	type ConnectionInfo = ();

	fn random_recipient(&self) -> Option<MixPeerId> {
		None
	}
	fn neighbors(&self, _: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>> {
		None
	}
	fn routing(&self) -> bool {
		true
	}
	fn encoded_connection_info(_: &Self::ConnectionInfo) -> Vec<u8> {
		Vec::new()
	}
	fn read_connection_info(encoded: &[u8]) -> Option<Self::ConnectionInfo> {
		(encoded.len() == 0).then(|| ())
	}
	fn connected(&mut self, _: MixPeerId, _: MixPublicKey, _: Self::ConnectionInfo) {}
	fn disconnect(&mut self, _: &MixPeerId) {}
}
