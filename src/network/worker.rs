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

use std::{collections::VecDeque, num::Wrapping, time::Duration};

use crate::{
	core::{Config, MixEvent, MixPublicKey, Mixnet, Packet, SurbsPayload, Topology},
	network::connection::Connection,
	MessageType, MixPeerId, SendOptions, PACKET_SIZE,
};
use futures::{
	channel::{mpsc::SendError, oneshot::Sender as OneShotSender},
	future::FutureExt,
	Sink, SinkExt, Stream, StreamExt,
};
use futures_timer::Delay;
use libp2p_core::PeerId;
use libp2p_swarm::NegotiatedSubstream;
use std::task::{Context, Poll};

pub const WINDOW_LIMIT: Duration = Duration::from_secs(50); // TODO currently it tics connect
pub type WorkerStream = Box<dyn Stream<Item = WorkerIn> + Unpin + Send>;
pub type WorkerSink = Box<dyn Sink<WorkerOut, Error = SendError> + Unpin + Send>;

pub enum WorkerIn {
	RegisterMessage(Option<MixPeerId>, Vec<u8>, SendOptions),
	RegisterSurbs(Vec<u8>, SurbsPayload),
	AddPeer(MixPeerId, Option<NegotiatedSubstream>, NegotiatedSubstream, OneShotSender<()>),
	AddPeerInbound(MixPeerId, NegotiatedSubstream),
	RemoveConnectedPeer(MixPeerId),
	ImportExternalMessage(MixPeerId, Packet),
}

pub enum WorkerOut {
	/// Message received from mixnet.
	ReceivedMessage(MixPeerId, Vec<u8>, MessageType),
	/// Handshake success in mixnet.
	Connected(PeerId, MixPublicKey),
	/// Dial a given PeerId.
	Dial(PeerId, Vec<libp2p_core::Multiaddr>),
}

/// Embed mixnet and process queue of instruction.
pub struct MixnetWorker<T> {
	mixnet: Mixnet<T, Connection>,
	worker_in: WorkerStream,
	worker_out: WorkerSink,
	current_window: Wrapping<usize>,
	window_delay: Delay,

	// TODO move to Connection or at least add a delay here and drop if no connection
	// after deley.
	queue_packets: VecDeque<(MixPeerId, Vec<u8>)>,
}

impl<T: Topology> MixnetWorker<T> {
	pub fn new(config: Config, topology: T, inner_channels: (WorkerSink, WorkerStream)) -> Self {
		let (worker_out, worker_in) = inner_channels;
		let mixnet = crate::core::Mixnet::new(config, topology);
		let window_delay = Delay::new(WINDOW_LIMIT);
		MixnetWorker {
			mixnet,
			worker_in,
			worker_out,
			current_window: Wrapping(0),
			window_delay,
			queue_packets: Default::default(),
		}
	}

	pub fn local_id(&self) -> &MixPeerId {
		self.mixnet.local_id()
	}

	pub fn change_peer_limit_window(&mut self, peer: &MixPeerId, new_limit: Option<u32>) {
		if let Some(con) = self.mixnet.connected_mut2(peer) {
			con.limit_msg = new_limit;
		}
	}

	/// Return false on shutdown.
	pub fn poll(&mut self, cx: &mut Context) -> Poll<bool> {
		if let Some((peer_id, packet)) = self.queue_packets.pop_back() {
			match self.mixnet.connected_mut2(&peer_id).map(|c| c.try_send_packet(packet)) {
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
		if let Poll::Ready(_) = self.window_delay.poll_unpin(cx) {
			log::trace!(target: "mixnet", "New window");
			self.current_window += Wrapping(1);
			self.window_delay.reset(WINDOW_LIMIT);
			result = Poll::Ready(true); // wait on next delay TODO could also retrun:
		}

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
				WorkerIn::AddPeer(peer, inbound, outbound, handler) => {
					if let Some(_con) = self.mixnet.connected_mut(&peer) {
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
						self.mixnet.insert_connection(peer, con);
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
				MixEvent::SendMessage((peer_id, packet)) => {
					debug_assert!(packet.len() == PACKET_SIZE);
					self.queue_packets.push_front((peer_id, packet));
				},
				MixEvent::None => (),
			}
		}

		result
	}

	fn disconnect_peer(&mut self, peer: &MixPeerId) {
		log::trace!(target: "mixnet", "Disconnecting peer {:?}", peer);
		log::error!(target: "mixnet", "Disconnecting peer {:?}", peer);
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
}
