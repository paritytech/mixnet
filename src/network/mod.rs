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
//! [`libp2p_swarm::Swarm`], it will handle the connection and send established streams
//! to the [`MixnetWorker`].

mod connection;
mod handler;
mod protocol;
mod worker;

pub(crate) use crate::network::worker::Command;
pub use crate::network::worker::{WorkerCommand, WorkerSink as WorkerSink2};
use crate::{core::SurbsPayload, traits::ClonableSink, MixPeerId, MixnetEvent, SendOptions};
use futures::{SinkExt, Stream, StreamExt};
use handler::Handler;
use libp2p_core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{
	CloseConnection, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
	NotifyHandler, PollParameters,
};
use std::{
	collections::{HashMap, VecDeque},
	task::{Context, Poll},
};
pub use worker::MixnetWorker;

pub type StreamFromWorker = Box<dyn Stream<Item = MixnetEvent> + Unpin + Send>;
pub type SinkToWorker = Box<dyn ClonableSink>;
pub type WorkerChannels = (WorkerSink2, worker::WorkerStream);

/// A [`NetworkBehaviour`] that implements the mixnet protocol.
pub struct MixnetBehaviour {
	mixnet_worker_sink: SinkToWorker,
	mixnet_worker_stream: StreamFromWorker,
	// avoid two connections from a single peer.
	connected: HashMap<PeerId, ConnectionId>,
	// connection handler notify queue
	notify_queue: VecDeque<(PeerId, ConnectionId)>,
	// if true when mixnet do not accept a peer we do not
	// cut the swarm connection: can make sense in case it
	// is multiplexed. Then it disconnect depending on ttl
	// or can be disconnected manually.
	keep_connection_alive: bool,
}

impl MixnetBehaviour {
	/// Creates a new network behaviour for a worker.
	pub fn new(
		worker_in: SinkToWorker,
		worker_out: StreamFromWorker,
		keep_connection_alive: bool,
	) -> Self {
		Self {
			mixnet_worker_sink: worker_in,
			mixnet_worker_stream: worker_out,
			notify_queue: Default::default(),
			connected: Default::default(),
			keep_connection_alive,
		}
	}
}

/// Sink allowing to send external mixnet command.
pub struct MixnetCommandSink(pub SinkToWorker);

impl Clone for MixnetCommandSink {
	fn clone(&self) -> Self {
		MixnetCommandSink(dyn_clone::clone_box(&*self.0))
	}
}

impl From<SinkToWorker> for MixnetCommandSink {
	fn from(sink: SinkToWorker) -> Self {
		MixnetCommandSink(sink)
	}
}

impl MixnetCommandSink {
	/// Send a new message to the mix network. The message will be split, chunked and sent over
	/// multiple hops with random delays to the specified recipient.
	///
	/// If no recipient, it is send to a random recipient.
	/// When attaching a surb, it is send using this surbs infos.
	pub fn send(
		&mut self,
		to: Option<MixPeerId>,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> std::result::Result<(), crate::Error> {
		self.0
			.start_send_unpin(Command::RegisterMessage(to, message, send_options).into())
			.map_err(|_| crate::Error::WorkerChannelFull)
	}

	/// Send a surb reply to the mix network.
	pub fn surb(
		&mut self,
		message: Vec<u8>,
		surb: Box<SurbsPayload>,
	) -> std::result::Result<(), crate::Error> {
		self.0
			.start_send_unpin(Command::RegisterSurbs(message, surb).into())
			.map_err(|_| crate::Error::WorkerChannelFull)
	}
}

impl NetworkBehaviour for MixnetBehaviour {
	type ConnectionHandler = Handler;
	type OutEvent = MixnetEvent;

	fn new_handler(&mut self) -> Self::ConnectionHandler {
		Handler::new(
			handler::Config::default(),
			dyn_clone::clone_box(&*self.mixnet_worker_sink),
			self.keep_connection_alive,
		)
	}

	fn inject_event(&mut self, _: PeerId, _: ConnectionId, _: ()) {}

	fn inject_connection_established(
		&mut self,
		peer_id: &PeerId,
		con_id: &ConnectionId,
		_: &ConnectedPoint,
		_: Option<&Vec<Multiaddr>>,
		_: usize,
	) {
		log::trace!(target: "mixnet", "Connected: {}", peer_id);
		if !self.connected.contains_key(peer_id) {
			self.notify_queue.push_back((*peer_id, *con_id));
			self.connected.insert(*peer_id, *con_id);
		}
	}

	fn inject_connection_closed(
		&mut self,
		peer_id: &PeerId,
		con_id: &ConnectionId,
		_: &ConnectedPoint,
		_: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
		_: usize,
	) {
		log::trace!(target: "mixnet", "Disconnected: {}", peer_id);
		if self.connected.get(peer_id).map(|id| id == con_id).unwrap_or(false) {
			self.connected.remove(peer_id);
		}
		if let Err(e) = self
			.mixnet_worker_sink
			.as_mut()
			.start_send_unpin(Command::RemoveConnectedPeer(*peer_id).into())
		{
			log::warn!(target: "mixnet", "Could not send disconnected peer to mixnet {:?}", e);
		}
	}

	fn addresses_of_peer(&mut self, _peer: &PeerId) -> Vec<Multiaddr> {
		// This will only need to be cached if dialing at some point.
		vec![]
	}

	fn poll(
		&mut self,
		cx: &mut Context,
		params: &mut impl PollParameters,
	) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
		if let Some((id, connection)) = self.notify_queue.pop_front() {
			return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
				peer_id: id,
				handler: NotifyHandler::One(connection),
				event: handler::HandlerEvent::NetworkId(id),
			})
		}

		match self.mixnet_worker_stream.poll_next_unpin(cx) {
			Poll::Ready(Some(out)) => match out {
				MixnetEvent::TryConnect(mixnet_id, Some(network_id)) => {
					if let Some(con_id) = self.connected.get(&network_id) {
						return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
							peer_id: network_id,
							handler: NotifyHandler::One(*con_id),
							event: handler::HandlerEvent::TryReConnect,
						})
					}
					Poll::Ready(NetworkBehaviourAction::GenerateEvent(MixnetEvent::TryConnect(
						mixnet_id,
						Some(network_id),
					)))
				},
				MixnetEvent::TryConnect(mixnet_id, None) => Poll::Ready(
					NetworkBehaviourAction::GenerateEvent(MixnetEvent::TryConnect(mixnet_id, None)),
				),
				MixnetEvent::Disconnected(network_id, mixnet_id) =>
					if self.keep_connection_alive {
						Poll::Ready(NetworkBehaviourAction::GenerateEvent(
							MixnetEvent::Disconnected(network_id, mixnet_id),
						))
					} else if let Some(con_id) = self.connected.remove(&network_id) {
						Poll::Ready(NetworkBehaviourAction::CloseConnection {
							peer_id: network_id,
							connection: CloseConnection::One(con_id),
						})
					} else {
						self.poll(cx, params)
					},
				e => Poll::Ready(NetworkBehaviourAction::GenerateEvent(e)),
			},
			Poll::Ready(None) =>
				Poll::Ready(NetworkBehaviourAction::GenerateEvent(MixnetEvent::CloseStream)),
			Poll::Pending => Poll::Pending,
		}
	}
}
