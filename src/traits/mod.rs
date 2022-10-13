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

use crate::{Error, MixPublicKey, MixnetId, NetworkId, PeerCount, SendOptions, WindowStats};
use ambassador::delegatable_trait;
use dyn_clone::DynClone;
use futures::{channel::mpsc::SendError, Sink};
use std::{
	collections::{BTreeMap, BTreeSet},
	task::{Context, Poll},
};

pub use crate::WorkerCommand;
pub use hash_table::TopologyHashTable;

pub trait ClonableSink: Sink<WorkerCommand, Error = SendError> + DynClone + Unpin + Send {}
impl<T> ClonableSink for T where T: Sink<WorkerCommand, Error = SendError> + DynClone + Unpin + Send {}

/// Provide Configuration of mixnet.
pub trait Configuration: Topology + Handshake + Sized + Send + 'static {
	/// Do we need stats for each windows.
	fn collect_windows_stats(&self) -> bool;

	/// Callback on windows stats.
	fn window_stats(&self, stats: &WindowStats, connection: &PeerCount);

	/// Callback on connection stats.
	fn peer_stats(&self, stats: &PeerCount);
}

/// Provide network topology information to the mixnet.
#[delegatable_trait]
pub trait Topology: Sized {
	/// Select a random recipient for the message to be delivered. This is
	/// called when the user sends the message with no recipient specified.
	/// E.g. this can select a random validator that can accept the blockchain
	/// transaction into the block.
	/// Return `None` if no such selection is possible.
	/// TODO rem
	fn random_recipient(
		&mut self,
		local_id: &MixnetId,
		send_options: &SendOptions,
	) -> Option<(MixnetId, MixPublicKey)>;

	/// Check if a peer is in topology, do not need to be connected.
	fn can_route(&self, id: &MixnetId) -> bool;

	/// first hop nodes that may currently allow external node connection.
	fn first_hop_nodes_external(
		&self,
		_from: &MixnetId,
		_to: Option<&MixnetId>,
		_num_hop: usize,
	) -> Vec<(MixnetId, MixPublicKey)>;

	/// Check if a peer is in topology, do not need to be connected.
	fn is_first_node(&self, _id: &MixnetId) -> bool;

	/// If external is allowed, it returns a ratio of
	/// routing node bandwidth to use.
	fn bandwidth_external(&self, _id: &MixnetId, peers: &PeerCount) -> Option<(usize, usize)>;

	/// Check node links.
	fn routing_to(&self, from: &MixnetId, to: &MixnetId) -> bool;

	/// Random message path.
	/// Warning number of hops is indicative and for some topology
	/// could be higher (eg if `start` or `recipient` are not routing
	/// a hop should be added).
	///
	/// When recipient is undefined, a random recipient among reachable
	/// routing peers is used.
	///	E.g. this can select a random validator that can accept the blockchain
	/// transaction into the block.
	/// Error when no recipient is reachable.
	fn random_path(
		&mut self,
		start_node: (&MixnetId, Option<&MixPublicKey>),
		recipient_node: Option<(&MixnetId, Option<&MixPublicKey>)>,
		count: usize,
		num_hops: usize,
		max_hops: usize,
		last_query_if_surb: Option<&Vec<(MixnetId, MixPublicKey)>>,
	) -> Result<Vec<Vec<(MixnetId, MixPublicKey)>>, Error>;

	/// On connection successful handshake.
	/// TODO could pass connectionkind to simplify code
	fn connected(&mut self, id: MixnetId, public_key: MixPublicKey);

	/// On disconnect.
	/// TODO could pass connectionkind to simplify code
	fn disconnected(&mut self, id: &MixnetId);

	/// On topology change, might have existing peer changed, return a list of these peers.
	/// Call to this function return the new peers only once and should
	/// be costless when no change occurs.
	fn changed_route(&mut self) -> Option<BTreeSet<MixnetId>>;

	/// On topology change, might have new peer to accept.
	/// Call to this function return the new peers only once and should
	/// be costless when no change occurs.
	/// TODO maybe just rely on should connect too.
	fn try_connect(&mut self) -> Option<BTreeMap<MixnetId, Option<NetworkId>>>;

	/// Return all possible connection ordered by priority and the targetted number of connections
	/// to use.
	fn should_connect_to(&self) -> ShouldConnectTo;

	/// Is peer allowed to connect to our node.
	fn accept_peer(&self, peer_id: &MixnetId, peers: &PeerCount) -> bool;

	/// A new static routing set was globally defined.
	fn handle_new_routing_set(&mut self, set: NewRoutingSet);

	// TODO handle new id and key.
	// TODO handle new distributed routing table
}

// TODO a enum variant with MixPublicKey or opt MixPublicKey.
pub struct ShouldConnectTo<'a> {
	pub peers: &'a [MixnetId],
	pub number: usize,
	pub is_static: bool,
}

impl<'a> ShouldConnectTo<'a> {
	pub fn empty() -> ShouldConnectTo<'static> {
		ShouldConnectTo { peers: &[], number: 0, is_static: true }
	}
}

/// A current routing set of peers.
/// Two variant given other info will be shared.
pub struct NewRoutingSet<'a> {
	pub peers: &'a [(MixnetId, MixPublicKey)],
}

/// Handshake on peer connection.
pub trait Handshake {
	/// Handshake size expected.
	fn handshake_size(&self) -> usize;

	/// Check handshake payload and extract (or return from state)
	/// peer id and public key.
	fn check_handshake(&self, payload: &[u8], from: &NetworkId)
		-> Option<(MixnetId, MixPublicKey)>;

	/// On handshake, return handshake payload.
	///
	/// Return None if peer is filtered by network id.
	fn handshake(&self, with: &NetworkId, public_key: &MixPublicKey) -> Option<Vec<u8>>;
}

/// No topology try direct connection.
pub struct NoTopology {
	pub connected_peers: std::collections::HashMap<MixnetId, MixPublicKey>,
}

impl Topology for NoTopology {
	fn can_route(&self, _id: &MixnetId) -> bool {
		false
	}

	fn random_recipient(
		&mut self,
		_from: &MixnetId,
		_: &SendOptions,
	) -> Option<(MixnetId, MixPublicKey)> {
		unimplemented!("TODO rem")
	}

	fn bandwidth_external(&self, _id: &MixnetId, _: &PeerCount) -> Option<(usize, usize)> {
		Some((1, 1))
	}

	fn random_path(
		&mut self,
		from: (&MixnetId, Option<&MixPublicKey>),
		recipient: Option<(&MixnetId, Option<&MixPublicKey>)>,
		count: usize,
		_num_hops: usize,
		_max_hops: usize,
		_last_query_if_surb: Option<&Vec<(MixnetId, MixPublicKey)>>,
	) -> Result<Vec<Vec<(MixnetId, MixPublicKey)>>, Error> {
		log::warn!(target: "mixnet", "No topology, direct transmission");

		let recipient = recipient.or_else(|| {
			use rand::prelude::IteratorRandom;
			let mut rng = rand::thread_rng();
			// Select a random connected peer
			self.connected_peers
				.iter()
				.filter(|(k, _v)| k != &from.0)
				.choose(&mut rng)
				.map(|(k, v)| (k, Some(v)))
		});
		let recipient = if let Some(recipient) = recipient {
			recipient
		} else {
			return Err(Error::NoPath(None))
		};

		// No topology is defined. Check if direct connection is possible.
		match self.connected_peers.get(recipient.0) {
			Some(key) => Ok(vec![vec![(*recipient.0, *key)]; count]),
			_ => Err(Error::NoPath(Some(*recipient.0))),
		}
	}

	// first hop that allow external node connection.
	fn first_hop_nodes_external(
		&self,
		_from: &MixnetId,
		_to: Option<&MixnetId>,
		_num_hop: usize,
	) -> Vec<(MixnetId, MixPublicKey)> {
		Vec::new()
	}

	fn is_first_node(&self, _id: &MixnetId) -> bool {
		true
	}

	fn routing_to(&self, _from: &MixnetId, _to: &MixnetId) -> bool {
		true
	}

	fn connected(&mut self, id: MixnetId, key: MixPublicKey) {
		self.connected_peers.insert(id, key);
	}

	fn disconnected(&mut self, id: &MixnetId) {
		self.connected_peers.remove(id);
	}

	fn accept_peer(&self, _: &MixnetId, _: &PeerCount) -> bool {
		true
	}

	fn changed_route(&mut self) -> Option<BTreeSet<MixnetId>> {
		None
	}

	fn try_connect(&mut self) -> Option<BTreeMap<MixnetId, Option<NetworkId>>> {
		None
	}

	fn should_connect_to(&self) -> ShouldConnectTo {
		ShouldConnectTo::empty()
	}

	fn handle_new_routing_set(&mut self, _set: NewRoutingSet) {}
}

impl Configuration for NoTopology {
	fn collect_windows_stats(&self) -> bool {
		false
	}

	fn window_stats(&self, _: &WindowStats, _: &PeerCount) {}

	fn peer_stats(&self, _: &PeerCount) {}
}

impl Handshake for NoTopology {
	fn handshake_size(&self) -> usize {
		32
	}

	fn check_handshake(
		&self,
		payload: &[u8],
		from: &NetworkId,
	) -> Option<(MixnetId, MixPublicKey)> {
		let peer_id = crate::core::to_sphinx_id(from).ok()?;
		let mut pk = [0u8; crate::core::PUBLIC_KEY_LEN];
		pk.copy_from_slice(payload);
		let pk = MixPublicKey::from(pk);
		Some((peer_id, pk))
	}

	fn handshake(&self, _with: &NetworkId, public_key: &MixPublicKey) -> Option<Vec<u8>> {
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
