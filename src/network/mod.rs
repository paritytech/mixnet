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

pub(crate) use crate::network::worker::{WorkerSink as WorkerSink2};
use crate::{
	MixnetEvent, MixPeerId,
};
use futures::{channel::oneshot::Sender as OneShotSender, Stream, StreamExt, SinkExt};
use futures::{channel::mpsc::SendError, Sink};
use handler::Handler;
use libp2p_core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId};
use libp2p_swarm::{
	CloseConnection, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
	NotifyHandler, PollParameters, NegotiatedSubstream,
};
use std::{
	collections::{HashMap, VecDeque},
	task::{Context, Poll},
};
use crate::{SendOptions, SurbsPayload, Packet};
use dyn_clone::DynClone;
pub use worker::MixnetWorker;

pub type StreamFromWorker = Box<dyn Stream<Item = MixnetEvent> + Unpin + Send>;
type SinkToWorker = Box<dyn ClonableSink>;
pub struct WorkerChannels(WorkerSink2, worker::WorkerStream);


pub(crate) trait ClonableSink: Sink<WorkerCommand, Error = SendError> + DynClone + Unpin + Send {}
impl<T> ClonableSink for T where T: Sink<WorkerCommand, Error = SendError> + DynClone + Unpin + Send {}

pub(crate) enum WorkerCommand {
	RegisterMessage(Option<MixPeerId>, Vec<u8>, SendOptions),
	RegisterSurbs(Vec<u8>, Box<SurbsPayload>),
	AddPeer(PeerId, Option<NegotiatedSubstream>, NegotiatedSubstream, OneShotSender<()>),
	AddPeerInbound(PeerId, NegotiatedSubstream),
	RemoveConnectedPeer(PeerId),
	ImportExternalMessage(MixPeerId, Packet),
}

/// A [`NetworkBehaviour`] that implements the mixnet protocol.
pub struct MixnetBehaviour {
	// Sink prototype for handler.
	mixnet_worker_sink: SinkToWorker,
	// Commands from worker
	mixnet_worker_stream: StreamFromWorker,
	// avoid two connections from a single peer.
	connected: HashMap<PeerId, ConnectionId>,
	// connection handler notify queue
	notify_queue: VecDeque<(PeerId, ConnectionId)>,
}

/// Sink for external command.
pub struct MixnetCommandSink(SinkToWorker);

impl Clone for MixnetCommandSink {
	fn clone(&self) -> Self {
		MixnetCommandSink(dyn_clone::clone_box(&*self.0))
	}
}

impl MixnetCommandSink {
	pub(crate) fn inner_sink(self) -> SinkToWorker {
		self.0
	}

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
		using_surb: Option<Box<SurbsPayload>>,
	) -> std::result::Result<(), crate::Error> {
		if let Some(surb) = using_surb {
		self.0.start_send_unpin(WorkerCommand::RegisterSurbs(message, surb))
			.map_err(|_| crate::Error::WorkerChannelFull)

		} else {
		self.0.start_send_unpin(WorkerCommand::RegisterMessage(to, message, send_options))
			.map_err(|_| crate::Error::WorkerChannelFull)
		}
	}
}


impl MixnetBehaviour {
	/// Creates a new network behaviour for a worker.
	pub fn new(worker_in: MixnetCommandSink, worker_out: StreamFromWorker) -> Self {
		Self {
			mixnet_worker_sink: worker_in.inner_sink(),
			mixnet_worker_stream: worker_out,
			notify_queue: Default::default(),
			connected: Default::default(),
		}
	}
}

impl NetworkBehaviour for MixnetBehaviour {
	type ConnectionHandler = Handler;
	type OutEvent = MixnetEvent;

	fn new_handler(&mut self) -> Self::ConnectionHandler {
		Handler::new(handler::Config::default(), dyn_clone::clone_box(&*self.mixnet_worker_sink))
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
		if self.connected.get(peer_id) == Some(con_id) {
			self.connected.remove(peer_id);
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
				event: id,
			})
		}

		match self.mixnet_worker_stream.poll_next_unpin(cx) {
			Poll::Ready(Some(out)) => match out {
				MixnetEvent::Disconnected(peer_id) => {
					if let Some(con_id) = self.connected.remove(&peer_id) {
						Poll::Ready(NetworkBehaviourAction::CloseConnection {
							peer_id,
							connection: CloseConnection::One(con_id),
						})
					} else {
						self.poll(cx, params)
					}
				},
				e => Poll::Ready(NetworkBehaviourAction::GenerateEvent(e)),
			},
			Poll::Ready(None) =>
				Poll::Ready(NetworkBehaviourAction::GenerateEvent(MixnetEvent::CloseStream)),
			Poll::Pending => Poll::Pending,
		}
	}
}
