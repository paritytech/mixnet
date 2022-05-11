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

use std::collections::VecDeque;

use crate::{
	core::{Config, MixEvent, MixPublicKey, Mixnet, Packet, SurbsPayload, Topology},
	network::connection::Connection,
	MessageType, MixPeerId, SendOptions,
};
use futures::{
	channel::{mpsc::SendError, oneshot::Sender as OneShotSender},
	Sink, SinkExt, Stream, StreamExt,
};
use libp2p_core::PeerId;
use libp2p_swarm::NegotiatedSubstream;
use std::task::{Context, Poll};

pub type WorkerStream = Box<dyn Stream<Item = WorkerIn> + Unpin + Send>;
pub type WorkerSink = Box<dyn Sink<WorkerOut, Error = SendError> + Unpin + Send>;
pub type ConnectionEstablished = Option<OneShotSender<()>>;

pub enum WorkerIn {
	RegisterMessage(Option<MixPeerId>, Vec<u8>, SendOptions),
	RegisterSurbs(Vec<u8>, SurbsPayload),
	AddPeer(MixPeerId, Option<NegotiatedSubstream>, NegotiatedSubstream, OneShotSender<()>, ConnectionEstablished),
	AddPeerInbound(MixPeerId, NegotiatedSubstream),
	RemoveConnectedPeer(MixPeerId),
	ImportExternalMessage(MixPeerId, Packet),
}

// TODO consider simple mutex on peer connections.
pub enum WorkerOut {
	/// Message received from mixnet.
	ReceivedMessage(MixPeerId, Vec<u8>, MessageType),
	/// Handshake success in mixnet.
	Connected(PeerId, MixPublicKey),
	/// Peer connection dropped, sending info to behaviour for
	/// cleanup.
	Disconnected(PeerId),
	/// Dial a given PeerId.
	Dial(PeerId, Vec<libp2p_core::Multiaddr>, Option<OneShotSender<()>>),
}

/// Embed mixnet and process queue of instruction.
pub struct MixnetWorker<T> {
	mixnet: Mixnet<T, Connection>,
	worker_in: WorkerStream,
	worker_out: WorkerSink,

	// TODO move to Connection or at least add a delay here and drop if no connection
	// after deley.
	queue_packets: VecDeque<(MixPeerId, Vec<u8>)>,
}

impl<T: Topology> MixnetWorker<T> {
	pub fn new(config: Config, topology: T, inner_channels: (WorkerSink, WorkerStream)) -> Self {
		let (worker_out, worker_in) = inner_channels;
		let mixnet = crate::core::Mixnet::new(config, topology);
		MixnetWorker { mixnet, worker_in, worker_out, queue_packets: Default::default() }
	}

	pub fn local_id(&self) -> &MixPeerId {
		self.mixnet.local_id()
	}

	pub fn change_peer_limit_window(&mut self, peer: &MixPeerId, new_limit: Option<u32>) {
		if let Some(con) = self.mixnet.managed_connection_mut(peer) {
			con.change_limit_msg(new_limit);
		}
	}

	/// Return false on shutdown.
	pub fn poll(&mut self, cx: &mut Context) -> Poll<bool> {
		if let Some((peer_id, packet)) = self.queue_packets.pop_back() {
			match self.mixnet.managed_connection_mut(&peer_id).map(|c| c.try_send_packet(packet)) {
				Some(Some(packet)) => {
					self.queue_packets.push_front((peer_id, packet));
				},
				Some(None) => (),
				None => {
					// TODO could add delay and keep for a while in case connection happen later.
					// TODO in principle should be checked in topology. Actually if forwarding to an
					// external peer (eg surbs rep), this will need to dial (put rules behind a
					// topology check).
					log::error!(target: "mixnet", "Dropping packet, peer {:?} not connected in worker.", peer_id);
				},
			}
		}

		let mut result = Poll::Pending;
		match self.worker_in.poll_next_unpin(cx) {
			Poll::Ready(Some(message)) => match message {
				WorkerIn::RegisterMessage(peer_id, message, send_options) => {
					match self.mixnet.register_message(peer_id, message, send_options) {
						Ok(()) => (),
						Err(e) => {
							log::error!(target: "mixnet", "Error registering message: {:?}", e);
						},
					}
					return Poll::Ready(true)
				},
				WorkerIn::RegisterSurbs(message, surbs) => {
					match self.mixnet.register_surbs(message, surbs) {
						Ok(()) => (),
						Err(e) => {
							log::error!(target: "mixnet", "Error registering surbs: {:?}", e);
						},
					}
					return Poll::Ready(true)
				},
				WorkerIn::AddPeer(peer, inbound, outbound, handler, established) => {
					if !self.mixnet.accept_peer(&peer) {
						log::trace!("Rejected peer {:?}", peer);
						if let Err(e) = self.worker_out.start_send_unpin(WorkerOut::Disconnected(peer)) {
							log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
						}
					} else if let Some(_con) = self.mixnet.connected_mut(&peer) {
						log::error!("Trying to replace an existing connection for {:?}", peer);
					/*
					// TODO updating sound like a bad option.
					if let Some(i) = inbound {
						con.set_inbound(i);
					}
					con.inbound_waiting.1 = 0;
					con.outbound = Box::pin(outbound);
					con.outbound_waiting = None;
					// TODO Warning this will disconect a connection: rather spawn an error and
					// drop the query
					con.oneshot_handler = handler;
					*/
					} else {
						let con = Connection::new(handler, inbound, outbound);
						self.mixnet.insert_connection(peer, con, established);
					}
					log::trace!(target: "mixnet", "added peer out: {:?}", peer);
				},
				WorkerIn::AddPeerInbound(peer, inbound) => {
					if let Some(con) = self.mixnet.connected_mut(&peer) {
						log::trace!(target: "mixnet", "Added inbound to peer: {:?}", peer);
						con.set_inbound(inbound);
					} else {
						log::warn!(target: "mixnet", "Received inbound for dropped peer: {:?}", peer);
					}
				},
				WorkerIn::RemoveConnectedPeer(peer) => {
					self.disconnect_peer(&peer);
				},
				WorkerIn::ImportExternalMessage(peer, packet) => {
					if !self.import_packet(peer, packet) {
						return Poll::Ready(false)
					};
				},
			},
			Poll::Ready(None) => {
				// handler dropped, shutting down.
				log::debug!(target: "mixnet", "Worker input closed, shutting down.");
				return Poll::Ready(false)
			},
			_ => (),
		}

		if let Poll::Ready(e) = self.mixnet.poll(cx, &mut self.worker_out) {
			result = Poll::Ready(true);
			match e {
				MixEvent::None => (),
				MixEvent::Disconnected(peers) => {
					for peer in peers.into_iter() {
						if let Err(e) = self.worker_out.start_send_unpin(WorkerOut::Disconnected(peer)) {
							log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
						}
					}
				},
			}
		}

		result
	}

	fn disconnect_peer(&mut self, peer: &MixPeerId) {
		log::trace!(target: "mixnet", "Disconnecting peer {:?}", peer);
		log::error!(target: "mixnet", "Disconnecting peer {:?}", peer);
		if let Err(e) = self.worker_out.start_send_unpin(WorkerOut::Disconnected(peer.clone())) {
			log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
		}
		self.mixnet.remove_connected_peer(peer);
	}

	fn import_packet(&mut self, peer: MixPeerId, packet: Packet) -> bool {
		match self.mixnet.import_message(peer, packet) {
			Ok(Some((full_message, surbs))) => {
				if let Err(e) = self.worker_out.start_send_unpin(WorkerOut::ReceivedMessage(
					peer,
					full_message,
					surbs,
				)) {
					log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
					if e.is_disconnected() {
						return false
					}
				}
			},
			Ok(None) => (),
			Err(e) => {
				log::warn!(target: "mixnet", "Error importing message: {:?}", e);
			},
		}
		true
	}

	/// Try to connect to a given peer.
	/// If sender for reply, get message on connection established.
	pub fn dial(&mut self, peer: PeerId, addresses: Vec<libp2p_core::Multiaddr>, reply: ConnectionEstablished) -> bool {
		if let Err(e) = self.worker_out.start_send_unpin(WorkerOut::Dial(peer, addresses, reply)) {
			log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
			if e.is_disconnected() {
				return false
			}
		}
		true
	}
}
