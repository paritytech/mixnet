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
mod protocol;

use crate::{
	core::{
		to_mix_peer_id, Config, Error, MixEvent, MixPeerAddress, Mixnet, Packet, PublicKeyStore,
		SessionIndex, Surb, PUBLIC_KEY_LEN,
	},
	DecodedMessage, MixPeerId, MixPublicKey, NetworkPeerId, SendOptions, SessionTopology,
};
use futures_timer::Delay;
use handler::{Failure, Handler, Message};
use libp2p_core::{connection::ConnectionId, ConnectedPoint, Multiaddr};
use libp2p_swarm::{
	IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler, PollParameters,
};
use std::{
	collections::{HashMap, VecDeque},
	sync::Arc,
	task::{Context, Poll},
	time::Duration,
};

type Result = std::result::Result<Message, Failure>;

/// Internal information tracked for an established connection.
struct Connection {
	id: ConnectionId,
	_address: Option<Multiaddr>,
	read_timeout: Delay,
}

impl Connection {
	fn new(id: ConnectionId, address: Option<Multiaddr>) -> Self {
		Self { id, _address: address, read_timeout: Delay::new(Duration::new(2, 0)) }
	}
}

/// A [`NetworkBehaviour`] that implements the mixnet protocol.
pub struct MixnetBehaviour {
	connected: HashMap<NetworkPeerId, Connection>,
	handshakes: HashMap<NetworkPeerId, Connection>,
	mixnet: Mixnet,
	events: VecDeque<NetworkEvent>,
	handshake_queue: VecDeque<NetworkPeerId>,
	public_key: MixPublicKey,
}

impl MixnetBehaviour {
	/// Creates a new network behaviour with the given configuration.
	pub fn new(config: Config, keystore: Arc<PublicKeyStore>) -> Self {
		Self {
			public_key: config.public_key.clone(),
			mixnet: Mixnet::new(config, keystore),
			connected: Default::default(),
			handshakes: Default::default(),
			events: Default::default(),
			handshake_queue: Default::default(),
		}
	}

	/// Send a new message to the mix network. The message will be split, chunked and sent over
	/// multiple hops with random delays to the specified recipient.
	pub fn send(
		&mut self,
		to: MixPeerId,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> std::result::Result<(), Error> {
		self.mixnet.register_message(Some(to), message, send_options)
	}

	/// Send a new message to the mix network. The message will be split, chunked and sent over
	/// multiple hops with random delays to a random recipient.
	pub fn send_to_random_recipient(
		&mut self,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> std::result::Result<(), Error> {
		self.mixnet.register_message(None, message, send_options)
	}

	/// Send a reply to a previously received message.
	pub fn send_reply(&mut self, message: Vec<u8>, surb: Surb) -> std::result::Result<(), Error> {
		self.mixnet.register_surb_reply(message, surb)
	}

	/// If the node isn't part of the topology this returns a set of gateway addresses to connect
	/// to.
	pub fn gateways(&self) -> Vec<MixPeerAddress> {
		self.mixnet.gateways()
	}

	/// Set network information for a future session.
	pub fn set_session_topolgy(&mut self, index: SessionIndex, topology: SessionTopology) {
		self.mixnet.set_session_topolgy(index, topology);
	}

	/// Start a previously configured session.
	pub fn start_session(&mut self, index: SessionIndex) {
		self.mixnet.start_session(index);
	}

	fn handshake_message(&self) -> Vec<u8> {
		self.public_key.to_bytes().to_vec()
	}
}

/// Event generated by the network behaviour.
#[derive(Debug)]
pub enum NetworkEvent {
	/// A new peer has connected over the mixnet protocol.
	Connected(NetworkPeerId),
	/// A peer has disconnected the mixnet protocol.
	Disconnected(NetworkPeerId),
	/// A message has reached us.
	Message(DecodedMessage),
	/// Can ignore.
	None,
}

impl NetworkBehaviour for MixnetBehaviour {
	type ConnectionHandler = Handler;
	type OutEvent = NetworkEvent;

	fn new_handler(&mut self) -> Self::ConnectionHandler {
		Handler::new(handler::Config::new())
	}

	fn inject_event(&mut self, peer_id: NetworkPeerId, _: ConnectionId, event: Result) {
		match event {
			Ok(Message(message)) => {
				if let Some(mut connection) = self.handshakes.remove(&peer_id) {
					if message.len() != PUBLIC_KEY_LEN {
						log::trace!(target: "mixnet", "Bad handshake message from {:?}", peer_id);
						// Just drop the connection for now, it should terminate by timeout.
						return
					}
					let mut pk = [0u8; PUBLIC_KEY_LEN];
					pk.copy_from_slice(&message);
					let pub_key = MixPublicKey::from(pk);
					log::trace!(target: "mixnet", "Handshake message from {:?}", peer_id);
					connection.read_timeout.reset(Duration::new(2, 0));
					if let Ok(id) = to_mix_peer_id(&peer_id) {
						self.connected.insert(peer_id, connection);
						self.mixnet.add_connected_peer(id, pub_key);
						self.events.push_back(NetworkEvent::Connected(peer_id));
					}
				} else if let Some(connection) = self.connected.get_mut(&peer_id) {
					log::trace!(target: "mixnet", "Incoming message from {:?}", peer_id);
					connection.read_timeout.reset(Duration::new(2, 0));
					let Ok(id) = to_mix_peer_id(&peer_id) else {
						return
					};
					let message = Packet::from_vec(message);
					let Ok(Some((message, kind))) = self.mixnet.import_message(id, message) else {
						return
					};
					self.events.push_front(NetworkEvent::Message(DecodedMessage {
						peer: id,
						message,
						kind,
					}))
				}
			},
			Err(e) => {
				log::trace!(target: "mixnet", "Network error: {}", e);
			},
		}
	}

	fn inject_connection_established(
		&mut self,
		peer_id: &NetworkPeerId,
		con_id: &ConnectionId,
		endpoint: &ConnectedPoint,
		_: Option<&Vec<Multiaddr>>,
		_: usize,
	) {
		if self.handshakes.contains_key(peer_id) || self.connected.contains_key(peer_id) {
			log::trace!(target: "mixnet", "Duplicate connection: {}", peer_id);
			return
		}
		log::trace!(target: "mixnet", "Connected: {}", peer_id);
		let address = match endpoint {
			ConnectedPoint::Dialer { address, .. } => Some(address.clone()),
			ConnectedPoint::Listener { .. } => None,
		};
		if self.handshakes.insert(*peer_id, Connection::new(*con_id, address)).is_none() {
			self.handshake_queue.push_back(peer_id.clone());
		}
	}

	fn inject_connection_closed(
		&mut self,
		peer_id: &NetworkPeerId,
		_: &ConnectionId,
		_: &ConnectedPoint,
		_: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
		_: usize,
	) {
		log::trace!(target: "mixnet", "Disconnected: {}", peer_id);
		self.handshakes.remove(peer_id);
		self.connected.remove(peer_id);
		let Ok(id) = to_mix_peer_id(peer_id) else {
			return
		};
		self.mixnet.remove_connected_peer(&id);
	}

	fn poll(
		&mut self,
		cx: &mut Context<'_>,
		_: &mut impl PollParameters,
	) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
		if let Some(e) = self.events.pop_back() {
			return Poll::Ready(NetworkBehaviourAction::GenerateEvent(e))
		}

		while let Some(id) = self.handshake_queue.pop_front() {
			if let Some(connection) = self.handshakes.get(&id) {
				return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
					peer_id: id,
					handler: NotifyHandler::One(connection.id),
					event: Message(self.handshake_message()),
				})
			}
		}

		match self.mixnet.poll(cx) {
			Poll::Ready(MixEvent::SendMessage((recipient, data))) => {
				let Ok(id) = crate::core::to_network_peer_id(recipient) else {
					return Poll::Ready(NetworkBehaviourAction::GenerateEvent(NetworkEvent::None))
				};
				if let Some(connection) = self.connected.get(&id) {
					return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
						peer_id: id,
						handler: NotifyHandler::One(connection.id),
						event: Message(data),
					})
				} else {
					log::warn!(target: "mixnet", "Message for offline peer {:?} ({})", recipient, id);
					return Poll::Ready(NetworkBehaviourAction::GenerateEvent(NetworkEvent::None))
				}
			},
			Poll::Pending => Poll::Pending,
		}
	}
}
