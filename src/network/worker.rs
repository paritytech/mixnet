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
	core::{Config, MixEvent, MixPublicKey, Mixnet, SurbsPayload},
	network::connection::Connection,
	traits::Configuration, SphinxConstants,
	MixnetEvent, SendOptions,
};
use futures::{
	channel::{mpsc::SendError, oneshot::Sender as OneShotSender},
	Sink, SinkExt, Stream, StreamExt,
};
use libp2p_core::PeerId;
use libp2p_swarm::NegotiatedSubstream;
use std::task::{Context, Poll};

pub type WorkerStream<S: SphinxConstants> = Box<dyn Stream<Item = WorkerCommand<S>> + Unpin + Send>;
pub type WorkerSink = Box<dyn Sink<MixnetEvent, Error = SendError> + Unpin + Send>;

/// Opaque worker command.
pub struct WorkerCommand<S: SphinxConstants>(pub(crate) Command<S>);

pub(crate) enum Command<S: SphinxConstants> {
	RegisterMessage(Option<crate::MixPeerId>, Vec<u8>, SendOptions),
	RegisterSurbs(Vec<u8>, Box<SurbsPayload<S>>),
	AddPeer(PeerId, Option<NegotiatedSubstream>, NegotiatedSubstream, OneShotSender<()>),
	AddPeerInbound(PeerId, NegotiatedSubstream),
	RemoveConnectedPeer(PeerId),
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
}

impl<T: Configuration> MixnetWorker<T> {
	pub fn new(config: Config, topology: T, inner_channels: (WorkerSink, WorkerStream)) -> Self {
		let (worker_out, worker_in) = inner_channels;
		let mixnet = crate::core::Mixnet::new(config, topology);
		MixnetWorker { mixnet, worker_in, worker_out }
	}

	pub fn restart(
		&mut self,
		new_id: Option<crate::MixPeerId>,
		new_keys: Option<(MixPublicKey, crate::MixSecretKey)>,
	) {
		self.mixnet.restart(new_id, new_keys);
	}

	pub fn local_id(&self) -> &crate::MixPeerId {
		self.mixnet.local_id()
	}

	pub fn public_key(&self) -> &crate::MixPublicKey {
		self.mixnet.public_key()
	}

	/// Return false on shutdown.
	pub fn poll(&mut self, cx: &mut Context) -> Poll<bool> {
		if let Poll::Ready(event) = self.worker_in.poll_next_unpin(cx) {
			// consumming worker command first TODO select version makes all slower
			return Poll::Ready(self.on_command(event))
		}
		self.mixnet.poll(cx, &mut self.worker_out).map(|mixnet| self.on_mixnet(mixnet))
	}

	fn on_mixnet(&mut self, result: MixEvent) -> bool {
		match result {
			MixEvent::None => (),
			MixEvent::Disconnected(peers) =>
				for peer in peers.into_iter() {
					if let Err(e) =
						self.worker_out.start_send_unpin(MixnetEvent::Disconnected(peer))
					{
						log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
					}
				},
		}
		true
	}

	fn on_command(&mut self, result: Option<WorkerCommand>) -> bool {
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
				Command::AddPeer(peer, inbound, outbound, close_handler) => {
					if let Some(_con) = self.mixnet.connected_mut(&peer) {
						log::warn!("Trying to replace an existing connection for {:?}", peer);
					} else {
						let con = Connection::new(close_handler, inbound, outbound);
						self.mixnet.insert_connection(peer, con);
					}
					log::trace!(target: "mixnet", "added peer out: {:?}", peer);
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

	fn disconnect_peer(&mut self, peer: &PeerId) {
		log::trace!(target: "mixnet", "Disconnecting peer {:?}", peer);
		log::error!(target: "mixnet", "Disconnecting peer {:?}", peer);
		if let Err(e) = self.worker_out.start_send_unpin(MixnetEvent::Disconnected(*peer)) {
			log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
		}
		self.mixnet.remove_connected_peer(peer);
	}

	pub fn mixnet_mut(&mut self) -> &mut Mixnet<T, Connection> {
		&mut self.mixnet
	}

	pub fn mixnet(&mut self) -> &mut Mixnet<T, Connection> {
		&mut self.mixnet
	}
}
