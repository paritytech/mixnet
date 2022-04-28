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

//! The [`Mixnet`] struct implements the [`NetworkBehaviour`] trait. When used with a
//! [`libp2p_swarm::Swarm`], it will handle the mixnet protocol.

mod handler;
mod protocol;
mod worker;

use crate::{
	core::{self, Config, MixEvent, SurbsEncoded, PUBLIC_KEY_LEN},
	network::worker::{WorkerIn, WorkerOut},
	MixPublicKey, SendOptions,
};
use futures::{channel::mpsc::SendError, FutureExt, Sink, Stream};
use futures_timer::Delay;
use handler::{Failure, Handler, Message};
use libp2p_core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{
	CloseConnection, IntoProtocolsHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler,
	PollParameters,
};
use std::{
	collections::{HashMap, VecDeque},
	num::Wrapping,
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};
pub use worker::MixnetWorker;

type Result = std::result::Result<Message, Failure>;

pub const WINDOW_BACKPRESSURE: Duration = Duration::from_secs(5);

/// Internal information tracked for an established connection.
struct Connection {
	id: ConnectionId,
	_address: Option<Multiaddr>,
	read_timeout: Delay, /* TODO this is quite unpolled: could poll it in the worker?? actually
	                      * on disconnect connection may stay open -> use keep alive of handler? */
	// number of allowed message
	// in a window of time (can be modified
	// specifically by trait).
	limit_msg: Option<u32>,
	window_count: u32,
	current_window: Wrapping<usize>,
}

impl Connection {
	fn new(id: ConnectionId, address: Option<Multiaddr>, limit_msg: Option<u32>) -> Self {
		Self {
			id,
			_address: address,
			read_timeout: Delay::new(Duration::new(2, 0)),
			limit_msg,
			window_count: 0,
			current_window: Wrapping(0),
		}
	}
}

pub type WorkerStream = Pin<Box<dyn Stream<Item = WorkerOut> + Send>>;
pub type WorkerSink = Pin<Box<dyn Sink<WorkerIn, Error = SendError> + Send>>;
pub type WorkerChannels = (worker::WorkerSink, worker::WorkerStream);

/// A [`NetworkBehaviour`] that implements the mixnet protocol.
pub struct MixnetBehaviour {
	connected: HashMap<PeerId, Connection>,
	handshakes: HashMap<PeerId, Connection>,
	pending_disconnect: VecDeque<(PeerId, ConnectionId)>,
	mixnet_worker_sink: WorkerSink,
	mixnet_worker_stream: WorkerStream,
	events: VecDeque<NetworkEvent>,
	handshake_queue: VecDeque<PeerId>,
	public_key: MixPublicKey,
	default_limit_msg: Option<u32>,
	current_window: Wrapping<usize>,
	window_delay: Delay,
}

impl MixnetBehaviour {
	/// Creates a new network behaviour with the given configuration.
	pub fn new(config: Config, worker_in: WorkerSink, worker_out: WorkerStream) -> Self {
		Self {
			public_key: config.public_key,
			mixnet_worker_sink: worker_in,
			mixnet_worker_stream: worker_out,
			connected: Default::default(),
			handshakes: Default::default(),
			events: Default::default(),
			handshake_queue: Default::default(),
			default_limit_msg: config.limit_per_window,
			current_window: Wrapping(0),
			window_delay: Delay::new(WINDOW_BACKPRESSURE),
			pending_disconnect: Default::default(),
		}
	}

	/// Send a new message to the mix network. The message will be split, chunked and sent over
	/// multiple hops with random delays to the specified recipient.
	/// TODO Errors: in case topology does not allow it (not enough peer, no path...)
	pub fn send(
		&mut self,
		to: PeerId,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> std::result::Result<(), core::Error> {
		// TODO this is incorrect: use as an unbound channel when it is a sink and would
		// need back pressure: find another trait or write it?
		// TODO better error than () to enum
		self.mixnet_worker_sink
			.as_mut()
			.start_send(WorkerIn::RegisterMessage(Some(to), message, send_options))
			.map_err(|_| core::Error::WorkerChannelFull)
	}

	/// Send a new message to the mix network. The message will be split, chunked and sent over
	/// multiple hops with random delays to a random recipient.
	pub fn send_to_random_recipient(
		&mut self,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> std::result::Result<(), core::Error> {
		self.mixnet_worker_sink
			.as_mut()
			.start_send(WorkerIn::RegisterMessage(None, message, send_options))
			.map_err(|_| core::Error::WorkerChannelFull)
	}

	/// Send surbs reply.
	pub fn send_surbs(
		&mut self,
		message: Vec<u8>,
		surbs: SurbsEncoded,
	) -> std::result::Result<(), core::Error> {
		self.mixnet_worker_sink
			.as_mut()
			.start_send(WorkerIn::RegisterSurbs(message, surbs))
			.map_err(|_| core::Error::WorkerChannelFull)
	}

	fn handshake_message(&self) -> Vec<u8> {
		self.public_key.to_bytes().to_vec()
	}
}

/// Event generated by the network behaviour.
/// TODO add info disconnect for bad behavior (can propagate
/// to other system then).
#[derive(Debug)]
pub enum NetworkEvent {
	/// A new peer has connected over the mixnet protocol.
	/// This does not imply the peer will be added to the
	/// topology (can be filtered).
	Connected(PeerId, MixPublicKey),
	/// A peer has disconnected the mixnet protocol.
	Disconnected(PeerId),
	/// A message has reached us.
	Message(DecodedMessage),
}

/// Variant of message received.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MessageType {
	/// Message only.
	StandAlone,
	/// Message with a surbs for reply.
	WithSurbs(SurbsEncoded),
	/// Message from a surbs reply (trusted).
	FromSurbs,
}

impl MessageType {
	/// can the message a surbs reply.
	pub fn with_surbs(&self) -> bool {
		matches!(self, &MessageType::WithSurbs(_))
	}

	/// Extract surbs.
	pub fn surbs(self) -> Option<SurbsEncoded> {
		match self {
			MessageType::WithSurbs(surbs) => Some(surbs),
			_ => None,
		}
	}
}

/// A full mixnet message that has reached its recipient.
#[derive(Debug)]
pub struct DecodedMessage {
	/// The peer ID of the last hop that we have received the message from. This is not the message
	/// origin.
	pub peer: PeerId,
	/// Message data.
	pub message: Vec<u8>,
	/// Message kind.
	pub kind: MessageType,
}

impl NetworkBehaviour for MixnetBehaviour {
	type ProtocolsHandler = Handler;
	type OutEvent = NetworkEvent;

	fn new_handler(&mut self) -> Self::ProtocolsHandler {
		Handler::new(handler::Config::new())
	}

	fn inject_event(&mut self, peer_id: PeerId, con_id: ConnectionId, event: Result) {
		match event {
			Ok(Message(message)) => {
				if let Some(mut connection) = self.handshakes.remove(&peer_id) {
					if message.len() != PUBLIC_KEY_LEN {
						log::trace!(target: "mixnet", "Bad handshake message from {:?}", peer_id);
						// Just drop the connection for now, it should terminate by timeout.
						return
					}
					let mut pk = [0u8; PUBLIC_KEY_LEN];
					pk.copy_from_slice(&message[..PUBLIC_KEY_LEN]);
					let pub_key = MixPublicKey::from(pk);
					log::trace!(target: "mixnet", "Handshake message from {:?}", peer_id);
					connection.read_timeout.reset(Duration::new(2, 0));
					self.connected.insert(peer_id, connection);
					if let Err(e) = self
						.mixnet_worker_sink
						.as_mut()
						.start_send(WorkerIn::AddConnectedPeer(peer_id, pub_key))
					{
						log::error!(target: "mixnet", "Error sending in worker sink {:?}", e);
					}
					self.events.push_back(NetworkEvent::Connected(peer_id, pub_key));
				} else if let Some(connection) = self.connected.get_mut(&peer_id) {
					log::trace!(target: "mixnet", "Incoming message from {:?}", peer_id);

					if self.current_window == connection.current_window {
						connection.window_count += 1;
						if connection
							.limit_msg
							.as_ref()
							.map(|l| &connection.window_count > l)
							.unwrap_or(false)
						{
							log::trace!(target: "mixnet", "Receiving too many messages from {:?}, disconecting.", peer_id);
							self.pending_disconnect.push_front((peer_id, con_id));
							return
						}
					} else {
						connection.current_window = self.current_window;
						connection.window_count = 1;
					}
					connection.read_timeout.reset(Duration::new(2, 0));
					if let Err(e) = self
						.mixnet_worker_sink
						.as_mut()
						.start_send(WorkerIn::ImportMessage(peer_id, message))
					{
						log::error!(target: "mixnet", "Error sending in worker sink {:?}", e);
					}
				}
			},
			Err(e) => {
				log::trace!(target: "mixnet", "Network error: {}", e);
			},
		}
	}

	fn inject_connection_established(
		&mut self,
		peer_id: &PeerId,
		conn: &ConnectionId,
		endpoint: &ConnectedPoint,
		_errors: Option<&Vec<Multiaddr>>,
	) {
		if self.handshakes.contains_key(peer_id) || self.connected.contains_key(peer_id) {
			log::trace!(target: "mixnet", "Duplicate connection: {}", peer_id);
			return
		}
		log::trace!(target: "mixnet", "Connected: {}", peer_id);
		let address = match endpoint {
			ConnectedPoint::Dialer { address } => Some(address.clone()),
			ConnectedPoint::Listener { .. } => None,
		};
		//log::trace!(target: "mixnet", "Connected: {}", peer_id);
		if self
			.handshakes
			.insert(*peer_id, Connection::new(*conn, address, self.default_limit_msg.clone()))
			.is_none()
		{
			self.handshake_queue.push_back(peer_id.clone());
		}
	}

	fn inject_connection_closed(
		&mut self,
		peer_id: &PeerId,
		_conn: &ConnectionId,
		_: &ConnectedPoint,
		_: <Self::ProtocolsHandler as IntoProtocolsHandler>::Handler,
	) {
		self.handshakes.remove(peer_id);
		self.connected.remove(peer_id);
		if let Err(e) = self
			.mixnet_worker_sink
			.as_mut()
			.start_send(WorkerIn::RemoveConnectedPeer(peer_id.clone()))
		{
			log::error!(target: "mixnet", "Error sending in worker sink {:?}", e);
		}
	}

	fn inject_disconnected(&mut self, peer_id: &PeerId) {
		log::trace!(target: "mixnet", "Disconnected: {}", peer_id);
		self.handshakes.remove(peer_id);
		if let Err(e) = self
			.mixnet_worker_sink
			.as_mut()
			.start_send(WorkerIn::RemoveConnectedPeer(peer_id.clone()))
		{
			log::error!(target: "mixnet", "Error sending in worker sink {:?}", e);
		}
		if self.connected.remove(peer_id).is_some() {
			self.events.push_back(NetworkEvent::Disconnected(peer_id.clone()));
		}
	}

	fn poll(
		&mut self,
		cx: &mut Context<'_>,
		_: &mut impl PollParameters,
	) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ProtocolsHandler>> {
		if let Some((peer_id, con_id)) = self.pending_disconnect.pop_back() {
			return Poll::Ready(NetworkBehaviourAction::CloseConnection {
				peer_id,
				connection: CloseConnection::One(con_id),
			})
		}

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

		if let Poll::Ready(_) = self.window_delay.poll_unpin(cx) {
			self.current_window += Wrapping(1);
		}
		match self.mixnet_worker_stream.as_mut().poll_next(cx) {
			Poll::Ready(Some(out)) => match out {
				WorkerOut::Event(MixEvent::SendMessage((recipient, data))) => {
					if let Some(connection) = self.connected.get(&recipient) {
						return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
							peer_id: recipient,
							handler: NotifyHandler::One(connection.id),
							event: Message(data),
						})
					}
				},
				WorkerOut::Event(MixEvent::ChangeLimit(peer_id, limit)) => {
					if let Some(connection) = self.connected.get_mut(&peer_id) {
						connection.limit_msg = limit;
					}
				},
				WorkerOut::Event(MixEvent::Disconnect(peer_id)) => {
					self.connected.remove(&peer_id);
				},
				WorkerOut::ReceivedMessage(peer, message, kind) => self
					.events
					.push_front(NetworkEvent::Message(DecodedMessage { peer, message, kind })),
			},
			Poll::Ready(None) => {
				// TODO shutdown event?
			},
			_ => (),
		}
		Poll::Pending
	}
}
