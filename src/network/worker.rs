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

use std::{
	collections::{HashMap, VecDeque},
	num::Wrapping,
	time::Duration,
};

use crate::{
	core::{
		Config, MixEvent, MixPublicKey, Mixnet, Packet, SurbsPayload, Topology, PUBLIC_KEY_LEN,
	},
	MessageType, MixPeerId, SendOptions, PACKET_SIZE,
};
use futures::{
	channel::{mpsc::SendError, oneshot::Sender as OneShotSender},
	future::FutureExt,
	AsyncRead, AsyncWrite, Sink, SinkExt, Stream, StreamExt,
};
use futures_timer::Delay;
use libp2p_core::PeerId;
use libp2p_swarm::NegotiatedSubstream;
use std::{
	pin::Pin,
	task::{Context, Poll},
};

pub const WINDOW_LIMIT: Duration = Duration::from_secs(5);
pub const READ_TIMEOUT: Duration = Duration::from_secs(120); // TODO a bit less, but currently not that many cover sent
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
	ReceivedMessage(MixPeerId, Vec<u8>, MessageType),
	Connected(PeerId, MixPublicKey),
}

/// Internal information tracked for an established connection.
struct Connection {
	peer_id: MixPeerId,
	read_timeout: Delay,                            // TODO use handler TTL instead?
	inbound: Option<Pin<Box<NegotiatedSubstream>>>, // TODO remove some pin with Ext traits
	outbound: Pin<Box<NegotiatedSubstream>>,        /* TODO just use a single stream for in and
	                                                 * out? */
	outbound_waiting: Option<(Vec<u8>, usize)>,
	inbound_waiting: (Vec<u8>, usize),
	// number of allowed message
	// in a window of time (can be modified
	// specifically by trait).
	limit_msg: Option<u32>,
	window_count: u32,
	current_window: Wrapping<usize>,
	public_key: Option<MixPublicKey>,
	packet_flushing: bool,
	handshake_flushing: bool,
	handshake_sent: bool,
	// inform connection handler when closing.
	oneshot_handler: OneShotSender<()>,
}

impl Connection {
	fn new(
		peer_id: MixPeerId,
		limit_msg: Option<u32>,
		oneshot_handler: OneShotSender<()>,
		inbound: Option<NegotiatedSubstream>,
		outbound: NegotiatedSubstream,
	) -> Self {
		Self {
			peer_id,
			read_timeout: Delay::new(READ_TIMEOUT),
			limit_msg,
			window_count: 0,
			current_window: Wrapping(0),
			inbound: inbound.map(|i| Box::pin(i)),
			outbound: Box::pin(outbound),
			outbound_waiting: None,
			inbound_waiting: (vec![0; PACKET_SIZE], 0),
			public_key: None,
			packet_flushing: false,
			handshake_flushing: false,
			handshake_sent: false,
			oneshot_handler,
		}
	}

	fn handshake_received(&self) -> bool {
		self.public_key.is_some()
	}

	fn is_ready(&self) -> bool {
		self.handshake_sent && self.handshake_received()
	}

	// return false on error
	fn try_send_handshake(
		&mut self,
		cx: &mut Context,
		public_key: &MixPublicKey,
	) -> Poll<Result<(), ()>> {
		if self.handshake_sent {
			// ignoring
			return Poll::Pending
		}
		if self.handshake_flushing {
			match self.outbound.as_mut().poll_flush(cx) {
				Poll::Ready(Ok(())) => {
					self.handshake_flushing = false;
					self.handshake_sent = true;
					return Poll::Ready(Ok(()))
				},
				Poll::Ready(Err(_)) => return Poll::Ready(Err(())),
				Poll::Pending => return Poll::Pending,
			}
		}
		let (handshake, mut ix) = self
			.outbound_waiting
			.take()
			.unwrap_or_else(|| (public_key.to_bytes().to_vec(), 0));

		match self.outbound.as_mut().poll_write(cx, &handshake.as_slice()[ix..]) {
			Poll::Pending => {
				// Not ready, buffing in next
				self.outbound_waiting = Some((handshake, ix));
				Poll::Pending
			},
			Poll::Ready(Ok(nb)) => {
				ix += nb;
				if ix == handshake.len() {
					self.handshake_flushing = true;
				} else {
					self.outbound_waiting = Some((handshake, ix));
				}
				Poll::Ready(Ok(()))
			},
			Poll::Ready(Err(e)) => {
				log::trace!(target: "mixnet", "Error sending to peer, closing: {:?}", e);
				Poll::Ready(Err(()))
			},
		}
	}

	fn try_packet_flushing(&mut self, cx: &mut Context) -> Poll<Result<(), ()>> {
		if let Some((waiting, mut ix)) = self.outbound_waiting.as_mut() {
			if ix < PACKET_SIZE {
				match self.outbound.as_mut().poll_write(cx, &waiting[ix..]) {
					Poll::Pending => return Poll::Pending,
					Poll::Ready(Ok(nb)) => {
						ix += nb;
						if ix != PACKET_SIZE {
							return Poll::Ready(Ok(()))
						}
						self.packet_flushing = true;
					},
					Poll::Ready(Err(e)) => {
						log::trace!(target: "mixnet", "Error sending to peer, closing: {:?}", e);
						return Poll::Ready(Err(()))
					},
				}
			}
		}
		self.outbound_waiting = None;

		if self.packet_flushing {
			match self.outbound.as_mut().poll_flush(cx) {
				Poll::Ready(Ok(())) => {
					self.packet_flushing = false;
					return Poll::Ready(Ok(()))
				},
				Poll::Ready(Err(_)) => return Poll::Ready(Err(())),
				Poll::Pending => return Poll::Pending,
			}
		}
		Poll::Ready(Ok(()))
	}

	// return packet if already sending one.
	fn try_send_packet(
		&mut self,
		cx: &mut Context,
		packet: Vec<u8>,
	) -> (Poll<Result<(), ()>>, Option<Vec<u8>>) {
		if !self.is_ready() {
			// Drop: TODO only drop after some
			return (Poll::Pending, None)
		}
		// TODO move connection to mixnet so we directly try send
		// their and have a mix queue in each connection.

		match self.try_packet_flushing(cx) {
			Poll::Ready(Ok(())) => (),
			Poll::Ready(Err(())) => return (Poll::Ready(Err(())), Some(packet)),
			Poll::Pending => return (Poll::Pending, Some(packet)),
		}
		if self.outbound_waiting.is_some() || self.packet_flushing {
			return (Poll::Ready(Ok(())), Some(packet))
		}
		match self.outbound.as_mut().poll_write(cx, &packet[..]) {
			Poll::Pending => {
				self.outbound_waiting = Some((packet, 0));
				(Poll::Pending, None)
			},
			Poll::Ready(Ok(nb)) => {
				if nb != PACKET_SIZE {
					self.outbound_waiting = Some((packet, nb));
				} else {
					self.packet_flushing = true;
				}
				(Poll::Ready(Ok(())), None)
			},
			Poll::Ready(Err(e)) => {
				log::trace!(target: "mixnet", "Error sending to peer, closing: {:?}", e);
				(Poll::Ready(Err(())), Some(packet))
			},
		}
	}

	fn try_recv_handshake(&mut self, cx: &mut Context) -> Poll<Result<Option<MixPublicKey>, ()>> {
		if self.handshake_received() {
			// ignore
			return Poll::Pending
		}
		match self.inbound.as_mut().map(|inbound| {
			inbound
				.as_mut()
				.poll_read(cx, &mut self.inbound_waiting.0[self.inbound_waiting.1..PUBLIC_KEY_LEN])
		}) {
			Some(Poll::Ready(Ok(nb))) => {
				self.read_timeout.reset(READ_TIMEOUT);
				self.inbound_waiting.1 += nb;
				if self.inbound_waiting.1 == PUBLIC_KEY_LEN {
					let mut pk = [0u8; PUBLIC_KEY_LEN];
					pk.copy_from_slice(&self.inbound_waiting.0[..PUBLIC_KEY_LEN]);
					self.inbound_waiting.1 = 0;
					self.public_key = Some(MixPublicKey::from(pk));
					log::trace!(target: "mixnet", "Handshake message from {:?}", self.peer_id);
				}
				Poll::Ready(Ok(self.public_key.clone()))
			},
			Some(Poll::Ready(Err(e))) => {
				log::trace!(target: "mixnet", "Error receiving from peer, closing: {:?}", e);
				Poll::Ready(Err(()))
			},
			Some(Poll::Pending) => Poll::Pending,
			None => Poll::Pending,
		}
	}

	fn try_recv_packet(
		&mut self,
		cx: &mut Context,
		current_window: Wrapping<usize>,
	) -> Poll<Result<Option<Packet>, ()>> {
		if !self.is_ready() {
			// TODO this is actually unreachable
			// ignore
			return Poll::Pending
		}
		match self.inbound.as_mut().map(|inbound| {
			inbound
				.as_mut()
				.poll_read(cx, &mut self.inbound_waiting.0[self.inbound_waiting.1..])
		}) {
			Some(Poll::Ready(Ok(nb))) => {
				self.read_timeout.reset(READ_TIMEOUT);
				self.inbound_waiting.1 += nb;
				let packet = if self.inbound_waiting.1 == PACKET_SIZE {
					let packet = Packet::from_vec(self.inbound_waiting.0.clone()).unwrap();
					self.inbound_waiting.1 = 0;
					log::trace!(target: "mixnet", "Packet received from {:?}", self.peer_id);
					if self.current_window == current_window {
						self.window_count += 1;
						if self.limit_msg.as_ref().map(|l| &self.window_count > l).unwrap_or(false)
						{
							log::warn!(target: "mixnet", "Receiving too many messages from {:?}, disconecting.", self.peer_id);
							// TODO this is racy eg if you are in the topology but topology is not
							// yet synch, you can get banned: need to just stop receiving for a
							// while, and sender should delay its sending for the same amount of
							// leniance.
							return Poll::Ready(Err(()))
						}
					} else {
						self.current_window = current_window;
						self.window_count = 1;
					}

					Some(packet)
				} else {
					None
				};
				Poll::Ready(Ok(packet))
			},
			Some(Poll::Ready(Err(e))) => {
				log::trace!(target: "mixnet", "Error receiving from peer, closing: {:?}", e);
				Poll::Ready(Err(()))
			},
			Some(Poll::Pending) => Poll::Pending,
			None => Poll::Pending,
		}
	}
}

/// Embed mixnet and process queue of instruction.
pub struct MixnetWorker<T> {
	pub mixnet: Mixnet<T>,
	worker_in: WorkerStream,
	worker_out: WorkerSink,

	default_limit_msg: Option<u32>,
	current_window: Wrapping<usize>,
	window_delay: Delay,

	connected: HashMap<PeerId, Connection>,
	// TODO move to Connection or at least add a delay here and drop if no connection
	// after deley.
	queue_packets: VecDeque<(MixPeerId, Vec<u8>)>,
}

impl<T: Topology> MixnetWorker<T> {
	pub fn new(config: Config, topology: T, inner_channels: (WorkerSink, WorkerStream)) -> Self {
		let default_limit_msg = config.limit_per_window;
		let (worker_out, worker_in) = inner_channels;
		let mixnet = crate::core::Mixnet::new(config, topology);
		let window_delay = Delay::new(WINDOW_LIMIT);
		MixnetWorker {
			mixnet,
			worker_in,
			worker_out,
			connected: Default::default(),
			current_window: Wrapping(0),
			default_limit_msg,
			window_delay,
			queue_packets: Default::default(),
		}
	}

	pub fn local_id(&self) -> &MixPeerId {
		self.mixnet.local_id()
	}

	pub fn change_peer_limit_window(&mut self, peer: &MixPeerId, new_limit: Option<u32>) {
		if let Some(con) = self.connected.get_mut(peer) {
			con.limit_msg = new_limit;
		}
	}

	/// Return false on shutdown.
	pub fn poll(&mut self, cx: &mut Context) -> Poll<bool> {
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
					if let Some(con) = self.connected.get_mut(&peer) {
						con.inbound = inbound.map(|i| Box::pin(i));
						con.inbound_waiting.1 = 0;
						con.outbound = Box::pin(outbound);
						con.outbound_waiting = None;
						// TODO Warning this will disconect a connection: rather spawn an error and
						// drop the query
						con.oneshot_handler = handler;
					} else {
						let con = Connection::new(
							peer.clone(),
							self.default_limit_msg.clone(),
							handler,
							inbound,
							outbound,
						);
						self.connected.insert(peer, con);
					}
					log::trace!(target: "mixnet", "added peer out: {:?}", peer);
				},
				WorkerIn::AddPeerInbound(peer, inbound) => {
					if let Some(con) = self.connected.get_mut(&peer) {
						log::trace!(target: "mixnet", "Added inbound to peer: {:?}", peer);
						con.inbound = Some(Box::pin(inbound));
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

		if let Poll::Ready(e) = self.mixnet.poll(cx) {
			match e {
				MixEvent::SendMessage((peer_id, packet)) => {
					debug_assert!(packet.len() == PACKET_SIZE);
					self.queue_packets.push_front((peer_id, packet));
				},
			}
		}

		if let Some((peer_id, packet)) = self.queue_packets.pop_back() {
			match self.connected.get_mut(&peer_id).map(|c| c.try_send_packet(cx, packet)) {
				Some((Poll::Ready(Ok(())), packet)) => {
					if let Some(packet) = packet {
						self.queue_packets.push_front((peer_id, packet));
					}
					return Poll::Ready(true)
				},
				Some((Poll::Ready(Err(())), _)) => {
					self.disconnect_peer(&peer_id);
				},
				Some((Poll::Pending, packet)) =>
					if let Some(packet) = packet {
						self.queue_packets.push_front((peer_id, packet));
					},
				None => {
					// TODO could add delay and keep for a while in case connection happen later.
					// TODO in principle should be checked in topology. Actually if forwarding to an
					// external peer (eg surbs rep), this will need to dial (put rules behind a
					// topology check).
					log::error!(target: "mixnet", "Dropping packet, peer {:?} not connected in worker.", peer_id);
				},
			}
		}

		let mut disconnected = Vec::new();
		let mut recv_packets = Vec::new();
		for (_, connection) in self.connected.iter_mut() {
			if !connection.is_ready() {
				match connection.try_recv_handshake(cx) {
					Poll::Ready(Ok(key)) => {
						key.map(|key| {
							// TODO only send if configured to. (used in test only)
							if let Err(e) = self.worker_out.start_send_unpin(WorkerOut::Connected(
								connection.peer_id.clone(),
								key.clone(),
							)) {
								log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
							}

							self.mixnet.add_connected_peer(connection.peer_id.clone(), key)
						});
						result = Poll::Ready(true);
					},
					Poll::Ready(Err(())) => {
						disconnected.push(connection.peer_id.clone());
						continue
					},
					Poll::Pending => (),
				}
				match connection.try_send_handshake(cx, &self.mixnet.public) {
					Poll::Ready(Ok(())) => {
						result = Poll::Ready(true);
					},
					Poll::Ready(Err(())) => {
						disconnected.push(connection.peer_id.clone());
						continue
					},
					Poll::Pending => (),
				}
			} else {
				match connection.try_recv_packet(cx, self.current_window) {
					Poll::Ready(Ok(Some(packet))) => {
						recv_packets.push((connection.peer_id.clone(), packet));
						result = Poll::Ready(true);
					},
					Poll::Ready(Ok(None)) => {},
					Poll::Ready(Err(())) => {
						disconnected.push(connection.peer_id.clone());
						continue
					},
					Poll::Pending => (),
				}
				match connection.try_packet_flushing(cx) {
					Poll::Ready(Ok(())) => {},
					Poll::Ready(Err(())) => {
						disconnected.push(connection.peer_id.clone());
						continue
					},
					Poll::Pending => (),
				}
			}

			match connection.read_timeout.poll_unpin(cx) {
				Poll::Ready(()) => {
					log::trace!(target: "mixnet", "Peer, no recv for too long: {:?}", connection.peer_id);
					disconnected.push(connection.peer_id.clone());
				},
				Poll::Pending => (),
			}
		}

		for (peer, packet) in recv_packets {
			if !self.import_packet(peer, packet) {
				return Poll::Ready(false)
			}
		}

		for peer in disconnected {
			self.disconnect_peer(&peer);
		}

		result
	}

	fn disconnect_peer(&mut self, peer: &MixPeerId) {
		log::trace!(target: "mixnet", "Disconnecting peer {:?}", peer);
		log::error!(target: "mixnet", "Disconnecting peer {:?}", peer);
		if let Some(con) = self.connected.remove(peer) {
			let _ = con.oneshot_handler.send(());
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
}
