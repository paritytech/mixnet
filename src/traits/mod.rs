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

pub mod hash_table;

use crate::{Error, MixPeerId, MixPublicKey, NetworkPeerId, SendOptions, WindowStats};
use ambassador::delegatable_trait;
use dyn_clone::DynClone;
use futures::{channel::mpsc::SendError, Sink};
use std::task::{Context, Poll};

pub use crate::WorkerCommand;
pub use hash_table::TopologyHashTable;

pub trait ClonableSink: Sink<WorkerCommand, Error = SendError> + DynClone + Unpin + Send {}
impl<T> ClonableSink for T where T: Sink<WorkerCommand, Error = SendError> + DynClone + Unpin + Send {}

/// Provide Configuration of mixnet.
pub trait Configuration: Topology + Handshake + Sized + Send + 'static {
	/// Do we need stats for each windows.
	fn collect_windows_stats(&self) -> bool;

	/// Callback on windows stats.
	fn window_stats(&self, stats: &WindowStats);
}

/// Provide network topology information to the mixnet.
#[delegatable_trait]
pub trait Topology: Sized {
	/// Select a random recipient for the message to be delivered. This is
	/// called when the user sends the message with no recipient specified.
	/// E.g. this can select a random validator that can accept the blockchain
	/// transaction into the block.
	/// Return `None` if no such selection is possible.
	fn random_recipient(
		&mut self,
		local_id: &MixPeerId,
		send_options: &SendOptions,
	) -> Option<(MixPeerId, MixPublicKey)>;

	/// Check if a peer is in topology, do not need to be connected.
	/// TODO rename can_route
	fn is_routing(&self, id: &MixPeerId) -> bool;

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
	fn bandwidth_external(&self, _id: &MixPeerId) -> Option<(usize, usize)>;

	/// Check node links.
	fn routing_to(&self, from: &MixPeerId, to: &MixPeerId) -> bool;

	/// Random message path.
	/// Warning number of hops is indicative and for some topology
	/// could be higher (eg if `start` or `recipient` are not routing
	/// a hop should be added).
	fn random_path(
		&mut self,
		start_node: (&MixPeerId, Option<&MixPublicKey>),
		recipient_node: (&MixPeerId, Option<&MixPublicKey>),
		count: usize,
		num_hops: usize,
		max_hops: usize,
		last_query_if_surb: Option<&Vec<(MixPeerId, MixPublicKey)>>,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error>;

	/// On connection successful handshake.
	fn connected(&mut self, id: MixPeerId, public_key: MixPublicKey);

	/// On disconnect.
	fn disconnected(&mut self, id: &MixPeerId);

	/// Utils that should be call when using `check_handshake`.
	/// TODO remove local_id param
	fn accept_peer(&self, local_id: &MixPeerId, peer_id: &MixPeerId) -> bool;
}

/// Handshake on peer connection.
pub trait Handshake {
	/// Handshake size expected.
	fn handshake_size(&self) -> usize;

	/// Check handshake payload and extract (or return from state)
	/// peer id and public key.
	fn check_handshake(
		&mut self,
		payload: &[u8],
		from: &NetworkPeerId,
	) -> Option<(MixPeerId, MixPublicKey)>;

	/// On handshake, return handshake payload.
	///
	/// Return None if peer is filtered by network id.
	fn handshake(&mut self, with: &NetworkPeerId, public_key: &MixPublicKey) -> Option<Vec<u8>>;
}

/// No topology try direct connection.
pub struct NoTopology {
	pub connected_peers: std::collections::HashMap<MixPeerId, MixPublicKey>,
}

impl Topology for NoTopology {
	fn is_routing(&self, id: &MixPeerId) -> bool {
		self.neighbors(id).is_some()
	}

	fn random_recipient(
		&mut self,
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

	fn bandwidth_external(&self, _id: &MixPeerId) -> Option<(usize, usize)> {
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

	fn disconnected(&mut self, id: &MixPeerId) {
		self.connected_peers.remove(id);
	}

	fn accept_peer(&self, local_id: &MixPeerId, peer_id: &MixPeerId) -> bool {
		self.routing_to(local_id, peer_id) ||
			self.routing_to(peer_id, local_id) ||
			self.bandwidth_external(peer_id).is_some()
	}
}

impl Configuration for NoTopology {
	fn collect_windows_stats(&self) -> bool {
		false
	}

	fn window_stats(&self, _: &WindowStats) {}
}

impl Handshake for NoTopology {
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

/// Primitives needed from a network connection.
pub trait Connection {
	/// Start sending a message. This trait expects to queue a single message
	/// and return the message back if another message is currently being send.
	fn try_queue_send(&mut self, message: Vec<u8>) -> Option<Vec<u8>>;
	/// Send and flush, return true when queued message is written and flushed.
	/// Return false if ignored (no queued message).
	/// Return Error if connection broke.
	fn send_flushed(&mut self, cx: &mut Context) -> Poll<Result<bool, ()>>;
	/// Try receive a packet of a given size.
	/// Maximum supported size is `PACKET_SIZE`, return error otherwise.
	fn try_recv(&mut self, cx: &mut Context, size: usize) -> Poll<Result<Option<Vec<u8>>, ()>>;
}
