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

//! `NetworkBehaviour` can be to heavy (especially when shared with others), using
//! a worker allows sending the process to a queue instead of runing it directly.

use crate::{
	core::{Config, MixPublicKey, Mixnet, MixnetEvent, SurbsPayload},
	network::connection::Connection,
	traits::Configuration,
	MixnetId, MixnetToBehaviorEvent, NetworkId, SendOptions,
};
use futures::{
	channel::{mpsc::SendError, oneshot::Sender as OneShotSender},
	Sink, SinkExt, Stream, StreamExt,
};
use libp2p_swarm::NegotiatedSubstream;
use std::task::{Context, Poll};

pub type WorkerStream = Box<dyn Stream<Item = WorkerCommand> + Unpin + Send>;
pub(crate) type WorkerSink = Box<dyn Sink<MixnetToBehaviorEvent, Error = SendError> + Unpin + Send>;

/// Opaque worker command.
pub struct WorkerCommand(pub(crate) Command);

pub(crate) enum Command {
	RegisterMessage(Option<MixnetId>, Vec<u8>, SendOptions),
	RegisterSurbs(Vec<u8>, Box<SurbsPayload>),
	AddPeer(NetworkId, Option<NegotiatedSubstream>, NegotiatedSubstream, OneShotSender<()>),
	AddPeerInbound(NetworkId, NegotiatedSubstream),
	RemoveConnectedPeer(NetworkId),
	NewGlobalRoutingSet(Vec<(MixnetId, MixPublicKey)>),
}

impl Command {
	pub(crate) fn into(self) -> WorkerCommand {
		WorkerCommand(self)
	}
}

/// Embed mixnet and process queue of instruction.
pub struct MixnetWorker<T> {
	mixnet: Mixnet<T, Connection>,
	worker_in: WorkerStream,
	worker_out: WorkerSink,
	// on heavy bandwidth, the worker may keep sending
	// without yielding, possibly keeping thread.
	// This counter ensure we yield from time to time.
	// When testing in debug, lowering budget can be
	// good,
	hits: usize,
	budget: usize,
}

impl<T: Configuration> MixnetWorker<T> {
	pub fn new(config: Config, topology: T, inner_channels: (WorkerSink, WorkerStream)) -> Self {
		let (worker_out, worker_in) = inner_channels;
		let budget = config.no_yield_budget;
		let mixnet = crate::core::Mixnet::new(config, topology);
		MixnetWorker { mixnet, worker_in, worker_out, hits: budget, budget }
	}

	pub fn restart(
		&mut self,
		new_id: Option<MixnetId>,
		new_keys: Option<(MixPublicKey, crate::MixSecretKey)>,
	) {
		self.mixnet.restart(new_id, new_keys);
	}

	/// Return false on shutdown.
	pub fn poll(&mut self, cx: &mut Context) -> Poll<MixnetEvent> {
		loop {
			// TODO this hits could probably be removed or make local
			if self.hits == 0 {
				self.hits = self.budget;
				cx.waker().wake_by_ref();
				return Poll::Pending
			}

			if let Poll::Ready(event) = self.worker_in.poll_next_unpin(cx) {
				if !self.on_command(cx, event) {
					return Poll::Ready(MixnetEvent::Shutdown)
				}
			}
			match self.mixnet.poll(cx) {
				Poll::Pending => return Poll::Pending,
				Poll::Ready(MixnetEvent::None) => (),
				Poll::Ready(event) => return Poll::Ready(event),
			}

			self.hits -= 1;
		}
	}

	fn on_command(&mut self, cx: &Context, result: Option<WorkerCommand>) -> bool {
		match result {
			Some(message) => match message.0 {
				Command::RegisterMessage(peer_id, message, send_options) => {
					match self.mixnet.register_message(peer_id, None, message, send_options) {
						Ok(()) => (),
						Err(e) => {
							log::error!(target: "mixnet", "Error registering message: {:?}", e);
						},
					}
					true
				},
				Command::RegisterSurbs(message, surb) => {
					match self.mixnet.register_surb(message, *surb) {
						Ok(()) => (),
						Err(e) => {
							log::error!(target: "mixnet", "Error registering surb: {:?}", e);
						},
					}
					true
				},
				Command::NewGlobalRoutingSet(set) => {
					self.mixnet.new_global_routing_set(&set[..]);
					true
				},
				Command::AddPeer(peer, inbound, outbound, close_handler) => {
					if self.mixnet.connected_mut(&peer).is_some() {
						log::warn!(target: "mixnet", "Replacing an existing connection for {:?}", peer);
					}
					let con = Connection::new(close_handler, inbound, outbound);
					self.mixnet.insert_connection(cx.waker().clone(), peer, con);
					true
				},
				Command::AddPeerInbound(peer, inbound) => {
					if let Some(con) = self.mixnet.connected_mut(&peer) {
						log::trace!(target: "mixnet", "Added inbound to peer: {:?}", peer);
						con.set_inbound(inbound);
					} else {
						log::warn!(target: "mixnet", "Received inbound for dropped peer: {:?}", peer);
					}
					true
				},
				Command::RemoveConnectedPeer(peer) => {
					self.disconnect_peer(&peer);
					true
				},
			},
			None => {
				// handler dropped, shutting down.
				log::debug!(target: "mixnet", "Worker input closed, shutting down.");
				false
			},
		}
	}

	fn disconnect_peer(&mut self, peer: &NetworkId) {
		log::trace!(target: "mixnet", "Disconnecting peer {:?}", peer);
		let _ = self.mixnet.remove_connected_peer(peer, true);
		if let Err(e) = self.worker_out.start_send_unpin(MixnetToBehaviorEvent::Disconnected(*peer))
		{
			log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
		}
	}

	pub fn mixnet_mut(&mut self) -> &mut Mixnet<T, Connection> {
		&mut self.mixnet
	}

	pub fn mixnet(&self) -> &Mixnet<T, Connection> {
		&self.mixnet
	}
}
