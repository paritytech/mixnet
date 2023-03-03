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

//! The [`MixnetBehaviour`] struct implements the [`NetworkBehaviour`] trait. When used with a
//! [`libp2p_swarm::Swarm`], it will handle the mixnet protocol.

mod handler;
mod maybe_inf_delay;
mod protocol;

use self::{
	handler::{Failure, Handler, Packet},
	maybe_inf_delay::MaybeInfDelay,
};
use super::core::{
	Config, Invalidated, KxPublic, KxPublicStore, Message, MessageId, Mixnet,
	Mixnode as InternalMixnode, MixnodeId, NetworkStatus, PeerId as InternalPeerId, PostErr,
	RelSessionIndex, SessionIndex, SessionStatus, Surb,
};
use futures::FutureExt;
use libp2p_core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{
	IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler, PollParameters,
};
use std::{
	collections::{hash_map::Entry, HashMap, VecDeque},
	sync::Arc,
	task::{Context, Poll},
	time::{Duration, Instant},
};

fn to_internal_peer_id(peer_id: &PeerId) -> Option<InternalPeerId> {
	let hash = peer_id.as_ref();
	let Ok(libp2p_core::multihash::Code::Identity) = libp2p_core::multihash::Code::try_from(hash.code()) else {
		return None
	};
	let public = libp2p_core::identity::PublicKey::from_protobuf_encoding(hash.digest()).ok()?;
	let libp2p_core::identity::PublicKey::Ed25519(public) = public;
	Some(public.encode())
}

fn from_internal_peer_id(internal_peer_id: &InternalPeerId) -> Option<PeerId> {
	let public = libp2p_core::identity::ed25519::PublicKey::decode(internal_peer_id).ok()?;
	let public = libp2p_core::identity::PublicKey::Ed25519(public);
	Some(public.into())
}

type Result = std::result::Result<Packet, Failure>;

#[derive(Clone)]
/// Just like `InternalMixnode` but with a libp2p peer ID instead of a mixnet peer ID.
pub struct Mixnode {
	/// Key-exchange public key for the mixnode.
	pub kx_public: KxPublic,
	/// Peer ID for the mixnode.
	pub peer_id: PeerId,
	/// External addresses for the mixnode.
	pub external_addresses: Vec<Multiaddr>,
}

struct Peers {
	local_id: InternalPeerId,
	connected: HashMap<InternalPeerId, Vec<ConnectionId>>,
}

impl NetworkStatus for Peers {
	fn local_peer_id(&self) -> InternalPeerId {
		self.local_id
	}

	fn is_connected(&self, peer_id: &InternalPeerId) -> bool {
		self.connected.contains_key(peer_id)
	}
}

/// A [`NetworkBehaviour`] that implements the mixnet protocol.
pub struct MixnetBehaviour {
	log_target: &'static str,
	peers: Peers,
	mixnet: Mixnet,
	next_forward_packet_delay: MaybeInfDelay,
	next_authored_packet_delay: MaybeInfDelay,
	events: VecDeque<MixnetEvent>,
}

impl MixnetBehaviour {
	/// Creates a new network behaviour with the given configuration. Returns `None` if the local
	/// peer ID cannot be converted to a mixnet peer ID.
	pub fn new(
		local_peer_id: &PeerId,
		config: Config,
		kx_public_store: Arc<KxPublicStore>,
	) -> Option<Self> {
		let log_target = config.log_target;
		Some(Self {
			log_target,
			peers: Peers {
				local_id: to_internal_peer_id(local_peer_id)?,
				connected: Default::default(),
			},
			mixnet: Mixnet::new(config, kx_public_store),
			next_forward_packet_delay: MaybeInfDelay::new(None),
			next_authored_packet_delay: MaybeInfDelay::new(None),
			events: Default::default(),
		})
	}

	fn handle_invalidated(&mut self) {
		let invalidated = self.mixnet.take_invalidated();
		if invalidated.contains(Invalidated::NEXT_FORWARD_PACKET_DEADLINE) {
			self.next_forward_packet_delay.reset(
				self.mixnet
					.next_forward_packet_deadline()
					.map(|deadline| deadline.saturating_duration_since(Instant::now())),
			);
		}
		if invalidated.contains(Invalidated::NEXT_AUTHORED_PACKET_DEADLINE) {
			self.next_authored_packet_delay.reset(self.mixnet.next_authored_packet_delay());
		}
	}

	/// Sets the current session index and phase. The current and previous mixnodes may need to be
	/// provided after calling this; see `maybe_set_mixnodes`.
	pub fn set_session_status(&mut self, session_status: SessionStatus) {
		self.mixnet.set_session_status(session_status);
		self.handle_invalidated();
	}

	/// Sets the mixnodes for the specified session, if they are needed.
	pub fn maybe_set_mixnodes<F, I, E>(
		&mut self,
		rel_session_index: RelSessionIndex,
		mixnodes: F,
	) -> std::result::Result<(), E>
	where
		F: FnOnce() -> std::result::Result<I, E>,
		I: Iterator<Item = Mixnode>,
	{
		let res = self.mixnet.maybe_set_mixnodes(rel_session_index, || {
			Ok(mixnodes()?
				.map(|mixnode| InternalMixnode {
					kx_public: mixnode.kx_public,
					peer_id: to_internal_peer_id(&mixnode.peer_id).unwrap_or_else(|| {
						log::error!(target: self.log_target,
							"Failed to convert libp2p peer ID {} to mixnet peer ID",
							mixnode.peer_id);
						Default::default()
					}),
					external_addresses: mixnode.external_addresses,
				})
				.collect())
		});
		self.handle_invalidated();
		res
	}

	/// Post a request message. If `destination` is `None`, a destination mixnode is chosen at
	/// random and (on success) the session and mixnode indices are written back to `destination`.
	/// The message is split into fragments and each fragment is sent over a different path to the
	/// destination. Returns the maximum total forwarding delay for any fragment/SURB pair; this
	/// should give a lower bound on the time it takes for a reply to arrive (it is possible for a
	/// reply to arrive sooner if a mixnode misbehaves).
	pub fn post_request(
		&mut self,
		destination: &mut Option<MixnodeId>,
		data: &[u8],
		num_surbs: usize,
	) -> std::result::Result<Duration, PostErr> {
		let res = self.mixnet.post_request(destination, data, num_surbs, &self.peers);
		self.handle_invalidated();
		res
	}

	/// Post a reply message using SURBs. The session index must match the session the SURBs were
	/// generated for. SURBs are removed from `surbs` on use.
	pub fn post_reply(
		&mut self,
		surbs: &mut Vec<Surb>,
		session_index: SessionIndex,
		message_id: &MessageId,
		data: &[u8],
	) -> std::result::Result<(), PostErr> {
		let res = self.mixnet.post_reply(surbs, session_index, message_id, data);
		self.handle_invalidated();
		res
	}
}

/// Event generated by the network behaviour.
#[derive(Debug)]
pub enum MixnetEvent {
	/// A new peer has connected over the mixnet protocol.
	Connected(PeerId),
	/// A peer has disconnected the mixnet protocol.
	Disconnected(PeerId),
	/// A message has reached us.
	Message(Message),
}

impl NetworkBehaviour for MixnetBehaviour {
	type ConnectionHandler = Handler;
	type OutEvent = MixnetEvent;

	fn new_handler(&mut self) -> Self::ConnectionHandler {
		Handler::new(self::handler::Config { log_target: self.log_target, ..Default::default() })
	}

	fn inject_event(&mut self, peer_id: PeerId, _: ConnectionId, event: Result) {
		match event {
			Ok(Packet(packet)) => {
				log::trace!(target: self.log_target, "Incoming packet from {peer_id}");
				let Ok(packet) = packet.as_slice().try_into() else {
					log::error!(target: self.log_target,
						"Dropped incorrectly sized packet ({} bytes) from {peer_id}",
						packet.len());
					return
				};
				if let Some(message) = self.mixnet.handle_packet(packet) {
					self.events.push_front(MixnetEvent::Message(message));
				}
				self.handle_invalidated();
			},
			Err(e) => {
				log::error!(target: self.log_target, "Network error: {e}");
			},
		}
	}

	fn inject_connection_established(
		&mut self,
		peer_id: &PeerId,
		conn_id: &ConnectionId,
		_: &ConnectedPoint,
		_: Option<&Vec<Multiaddr>>,
		_: usize,
	) {
		log::trace!(target: self.log_target, "Connected: {peer_id}, {conn_id:?}");
		let Some(internal_peer_id) = to_internal_peer_id(peer_id) else {
			log::error!(target: self.log_target,
				"Failed to convert libp2p peer ID {peer_id} to mixnet peer ID");
			return
		};
		match self.peers.connected.entry(internal_peer_id) {
			Entry::Occupied(mut entry) => entry.get_mut().push(*conn_id),
			Entry::Vacant(entry) => {
				entry.insert(vec![*conn_id]);
				self.events.push_back(MixnetEvent::Connected(*peer_id));
			},
		}
	}

	fn inject_connection_closed(
		&mut self,
		peer_id: &PeerId,
		conn_id: &ConnectionId,
		_: &ConnectedPoint,
		_: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
		_: usize,
	) {
		log::trace!(target: self.log_target, "Disconnected: {peer_id}, {conn_id:?}");
		let Some(internal_peer_id) = to_internal_peer_id(peer_id) else {
			log::error!(target: self.log_target,
				"Failed to convert libp2p peer ID {peer_id} to mixnet peer ID");
			return
		};
		match self.peers.connected.entry(internal_peer_id) {
			Entry::Occupied(mut entry) => {
				let conn_ids = entry.get_mut();
				let Some(i) = conn_ids.iter().position(|open_conn_id| open_conn_id == conn_id) else {
					log::error!(target: self.log_target,
						"Closed {conn_id:?} not recognised (peer {peer_id})");
					return
				};
				conn_ids.swap_remove(i);
				if conn_ids.is_empty() {
					entry.remove();
					self.events.push_back(MixnetEvent::Disconnected(*peer_id));
				}
			},
			Entry::Vacant(_) =>
				log::error!(target: self.log_target, "Disconnected peer {peer_id} not recognised"),
		}
	}

	fn poll(
		&mut self,
		cx: &mut Context<'_>,
		_: &mut impl PollParameters,
	) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
		if let Some(e) = self.events.pop_back() {
			return Poll::Ready(NetworkBehaviourAction::GenerateEvent(e))
		}

		loop {
			let packet = if self.next_forward_packet_delay.poll_unpin(cx).is_ready() {
				self.mixnet.pop_next_forward_packet()
			} else if self.next_authored_packet_delay.poll_unpin(cx).is_ready() {
				self.mixnet.pop_next_authored_packet(&self.peers)
			} else {
				return Poll::Pending
			};
			self.handle_invalidated();
			let Some(packet) = packet else { continue };

			let Some(peer_id) = from_internal_peer_id(&packet.peer_id) else {
				log::error!(target: self.log_target,
					"Failed to convert mixnet peer ID {:x?} to libp2p peer ID",
					packet.peer_id);
				continue
			};
			let Some(conn_ids) = self.peers.connected.get(&packet.peer_id) else {
				log::warn!(target: self.log_target, "Packet for offline peer {peer_id}");
				continue
			};
			return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
				peer_id,
				handler: NotifyHandler::One(
					*conn_ids
						.first()
						.expect("Peers removed from connected map when last connection ID removed"),
				),
				event: Packet((packet.packet as Box<[_]>).into()),
			})
		}
	}
}
