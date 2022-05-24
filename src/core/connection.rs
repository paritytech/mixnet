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

//! Mixnet connection interface.

use crate::{
	core::{NetworkPeerId, QueuedPacket, WINDOW_MARGIN_PERCENT},
	MixPeerId, MixPublicKey, Packet, Topology, PACKET_SIZE,
};
use futures::FutureExt;
use futures_timer::Delay;
use std::{
	collections::BinaryHeap,
	num::Wrapping,
	task::{Context, Poll},
	time::{Duration, Instant},
};

const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Primitives needed from a network connection.
pub trait Connection {
	/// Start sending a message. This trait expects to queue a single message
	/// and return the message back if another message is currently being send.
	fn try_queue_send(&mut self, message: Vec<u8>) -> Option<Vec<u8>>;
	/// Send and flush, return true when queued message is written and flushed.
	/// Return false if ignored (no queued message).
	/// Return Error if connection broke.
	fn send_flushed(&mut self, cx: &mut Context) -> Poll<Result<bool, ()>>;
	/// Try receive a packet of a given size.
	/// Maximum supported size is `PACKET_SIZE`, return error otherwise.
	fn try_recv(&mut self, cx: &mut Context, size: usize) -> Poll<Result<Option<Vec<u8>>, ()>>;
}

pub(crate) enum ConnectionEvent {
	Established(MixPeerId, MixPublicKey),
	Received(Packet),
	Broken,
	None,
}

pub(crate) struct ManagedConnection<C> {
	connection: C,
	mixnet_id: Option<MixPeerId>,
	network_id: NetworkPeerId,
	handshake_sent: bool,
	public_key: Option<MixPublicKey>, // public key is only needed for creating cover messages.
	// Real messages queue, sorted by deadline.
	packet_queue: BinaryHeap<QueuedPacket>,
	next_packet: Option<Vec<u8>>,
	// If we did not receive for a while, close connection.
	read_timeout: Delay,
	// Number of allowed message
	// in a window of time, this attempt to prevent ddos
	// from nodes that are not part of the topology.
	limit_msg: Option<usize>,
	current_window: Wrapping<usize>,
	sent_in_window: usize,
	recv_in_window: usize,
}

impl<C: Connection> ManagedConnection<C> {
	pub fn new(
		network_id: NetworkPeerId,
		limit_msg: Option<usize>,
		connection: C,
		current_window: Wrapping<usize>,
	) -> Self {
		Self {
			connection,
			mixnet_id: None,
			network_id,
			read_timeout: Delay::new(READ_TIMEOUT),
			next_packet: None,
			limit_msg,
			current_window,
			public_key: None,
			handshake_sent: false,
			sent_in_window: 0,
			recv_in_window: 0,
			packet_queue: Default::default(),
		}
	}

	pub fn change_limit_msg(&mut self, limit: Option<usize>) {
		self.limit_msg = limit;
	}

	fn handshake_received(&self) -> bool {
		self.public_key.is_some() && self.mixnet_id.is_some()
	}

	fn is_ready(&self) -> bool {
		self.handshake_sent && self.handshake_received()
	}

	pub fn connection_mut(&mut self) -> &mut C {
		&mut self.connection
	}

	pub fn mixnet_id(&self) -> Option<&MixPeerId> {
		self.mixnet_id.as_ref()
	}

	pub fn network_id(&self) -> NetworkPeerId {
		self.network_id
	}

	fn try_send_handshake(
		&mut self,
		cx: &mut Context,
		public_key: &MixPublicKey,
		topology: &mut impl Topology,
	) -> Poll<Result<(), ()>> {
		if !self.handshake_sent {
			let handshake =
				if let Some(handshake) = topology.handshake(&self.network_id, public_key) {
					handshake
				} else {
					log::trace!(target: "mixnet", "Cannot create handshake with {}", self.network_id);
					return Poll::Ready(Err(()))
				};
			if self.connection.try_queue_send(handshake).is_none() {
				self.handshake_sent = true;
			} else {
				// should not happen as handshake is first ever paquet.
				log::error!(target: "mixnet", "Hanshake is first paquet");
				return Poll::Ready(Err(()))
			}
		}
		match self.connection.send_flushed(cx) {
			Poll::Ready(Ok(true)) => Poll::Ready(Ok(())),
			Poll::Ready(Ok(false)) => {
				// No message queued, handshake as been sent, just wait on reply
				// or timeout.
				Poll::Pending
			},
			Poll::Ready(Err(_)) => {
				log::trace!(target: "mixnet", "Error sending handshake to peer {:?}", self.network_id);
				Poll::Ready(Err(()))
			},
			Poll::Pending => Poll::Pending,
		}
	}

	fn try_send_flushed(&mut self, cx: &mut Context) -> Poll<Result<bool, ()>> {
		match self.connection.send_flushed(cx) {
			Poll::Ready(Ok(sent)) => Poll::Ready(Ok(sent)),
			Poll::Ready(Err(())) => {
				log::trace!(target: "mixnet", "Error sending to peer {:?}", self.network_id);
				Poll::Ready(Err(()))
			},
			Poll::Pending => Poll::Pending,
		}
	}

	// return packet if already sending one.
	pub fn try_queue_send_packet(&mut self, packet: Vec<u8>) -> Option<Vec<u8>> {
		if !self.is_ready() {
			log::error!(target: "mixnet", "Peer {:?} not ready, dropping a packet", self.network_id);
			return None
		}
		self.connection.try_queue_send(packet)
	}

	fn try_recv_handshake(
		&mut self,
		cx: &mut Context,
		topology: &mut impl Topology,
	) -> Poll<Result<(MixPeerId, MixPublicKey), ()>> {
		if self.handshake_received() {
			// ignore
			return Poll::Pending
		}
		match self.connection.try_recv(cx, topology.handshake_size()) {
			Poll::Ready(Ok(Some(handshake))) => {
				self.read_timeout.reset(READ_TIMEOUT);
				log::trace!(target: "mixnet", "Handshake message from {:?}", self.network_id);
				if let Some((peer_id, pk)) =
					topology.check_handshake(handshake.as_slice(), &self.network_id)
				{
					self.mixnet_id = Some(peer_id);
					self.public_key = Some(pk);
					Poll::Ready(Ok((peer_id, pk)))
				} else {
					log::trace!(target: "mixnet", "Invalid handshake from peer, closing: {:?}", self.network_id);
					Poll::Ready(Err(()))
				}
			},
			Poll::Ready(Ok(None)) => self.try_recv_handshake(cx, topology),
			Poll::Ready(Err(())) => {
				log::trace!(target: "mixnet", "Error receiving handshake from peer, closing: {:?}", self.network_id);
				Poll::Ready(Err(()))
			},
			Poll::Pending => Poll::Pending,
		}
	}

	fn try_recv_packet(
		&mut self,
		cx: &mut Context,
		current_window: Wrapping<usize>,
	) -> Poll<Result<Packet, ()>> {
		if !self.is_ready() {
			// this is actually unreachable but ignore it.
			return Poll::Pending
		}
		match self.connection.try_recv(cx, PACKET_SIZE) {
			Poll::Ready(Ok(Some(packet))) => {
				self.read_timeout.reset(READ_TIMEOUT);
				log::trace!(target: "mixnet", "Packet received from {:?}", self.network_id);
				let packet = Packet::from_vec(packet).unwrap();
				if self.current_window == current_window {
					if self.limit_msg.as_ref().map(|l| &self.recv_in_window > l).unwrap_or(false) {
						log::warn!(target: "mixnet", "Receiving too many messages {:?} / {:?} from {:?}, disconecting.", self.recv_in_window, self.limit_msg.as_ref().unwrap(), self.network_id);
						return Poll::Ready(Err(()))
					}
				} else {
					self.current_window = current_window;
				}
				Poll::Ready(Ok(packet))
			},
			Poll::Ready(Ok(None)) => self.try_recv_packet(cx, current_window),
			Poll::Ready(Err(())) => {
				log::trace!(target: "mixnet", "Error receiving from peer, closing: {:?}", self.network_id);
				Poll::Ready(Err(()))
			},
			Poll::Pending => Poll::Pending,
		}
	}

	pub(crate) fn queue_packet(
		&mut self,
		packet: QueuedPacket,
		packet_per_window: usize,
		local_id: &MixPeerId,
		topology: &impl Topology,
		external: bool,
	) -> Result<(), crate::Error> {
		if let Some(peer_id) = self.mixnet_id.as_ref() {
			let packet_per_window = packet_per_window * (100 + WINDOW_MARGIN_PERCENT) / 100;
			if self.packet_queue.len() > packet_per_window {
				log::error!(target: "mixnet", "Dropping packet, queue full: {:?}", self.network_id);
				return Err(crate::Error::QueueFull)
			}
			if !external &&
				!topology.routing_to(local_id, peer_id) &&
				topology.allowed_external(peer_id).is_none()
			{
				log::trace!(target: "mixnet", "Dropping a queued packet, not in topology or allowed external.");
				return Err(crate::Error::NoPath(Some(peer_id.clone())))
			}
			self.packet_queue.push(packet);
			Ok(())
		} else {
			Err(crate::Error::NoSphinxId)
		}
	}

	pub(crate) fn poll(
		&mut self,
		cx: &mut Context,
		local_id: &MixPeerId,
		handshake: &MixPublicKey,
		current_window: Wrapping<usize>,
		current_packet_in_window: usize,
		packet_per_window: usize,
		now: Instant,
		topology: &mut impl Topology,
	) -> Poll<ConnectionEvent> {
		let mut result = Poll::Pending;
		if !self.is_ready() {
			let mut result = Poll::Pending;
			match self.try_recv_handshake(cx, topology) {
				Poll::Ready(Ok(key)) => {
					self.current_window = current_window;
					self.sent_in_window = current_packet_in_window;
					self.recv_in_window = current_packet_in_window;
					result = Poll::Ready(ConnectionEvent::Established(key.0, key.1));
				},
				Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
				Poll::Pending => (),
			}
			match self.try_send_handshake(cx, handshake, topology) {
				Poll::Ready(Ok(())) =>
					if matches!(result, Poll::Pending) {
						result = Poll::Ready(ConnectionEvent::None);
					},
				Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
				Poll::Pending => (),
			}
			return result
		} else if let Some(peer_id) = self.mixnet_id {
			while self.sent_in_window < current_packet_in_window {
				match self.try_send_flushed(cx) {
					Poll::Ready(Ok(true)) => {
						self.sent_in_window += 1;
						break
					},
					Poll::Ready(Ok(false)) => {
						// nothing in queue, get next.
						if let Some(packet) = self.next_packet.take() {
							if let Some(packet) = self.try_queue_send_packet(packet) {
								log::error!(target: "mixnet", "try send fail with nothing in queue.");
								self.next_packet = Some(packet);
							}
							continue
						}
						let deadline = self
							.packet_queue
							.peek()
							.map_or(false, |p| p.deadline.map(|d| d <= now).unwrap_or(true));
						if deadline {
							if let Some(packet) = self.packet_queue.pop() {
								self.next_packet = Some(packet.data.into_vec());
							}
						} else if let Some(key) = self.public_key {
							if topology.routing_to(local_id, &peer_id) {
								self.next_packet = crate::core::cover_message_to(&peer_id, key)
									.map(|p| p.into_vec());
							} else {
								log::warn!(target: "mixnet", "Queued packent not anymore in topology.");
								break
							}
							if self.next_packet.is_none() {
								log::error!(target: "mixnet", "Could not create cover for {:?}", self.network_id);
								break
							}
						}
					},
					Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
					Poll::Pending => break,
				}
			}
			let (current, external) = if topology.routing_to(&peer_id, local_id) {
				(current_packet_in_window, false)
			} else {
				let (n, d) = topology.allowed_external(&peer_id).unwrap_or((0, 1));
				((current_packet_in_window * n) / d, true)
			};
			if self.recv_in_window < current {
				match self.try_recv_packet(cx, current_window) {
					Poll::Ready(Ok(packet)) => {
						self.recv_in_window += 1;
						result = Poll::Ready(ConnectionEvent::Received(packet));
					},
					Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
					Poll::Pending => (),
				}
			}

			if current_window != self.current_window {
				if self.current_window + Wrapping(1) != current_window {
					let skipped = current_window - self.current_window;
					log::error!(target: "mixnet", "Window skipped {:?} ignoring report.", skipped);
				} else if !external {
					let packet_per_window_less_margin =
						packet_per_window * (100 - WINDOW_MARGIN_PERCENT) / 100;
					if self.sent_in_window < packet_per_window_less_margin {
						// sent not enough: dest peer is not receiving enough
						log::warn!(target: "mixnet", "Low sent in window with {:?}, {:?} / {:?}", self.network_id, self.sent_in_window, packet_per_window_less_margin);
					}
					if self.recv_in_window < packet_per_window_less_margin {
						// recv not enough: origin peer is not sending enough
						log::warn!(target: "mixnet", "Low recv in window with {:?}, {:?} / {:?}", self.network_id, self.recv_in_window, packet_per_window_less_margin);
					}
				}

				self.current_window = current_window;
				self.sent_in_window = 0;
				self.recv_in_window = 0;
			}
		} else {
			log::trace!(target: "mixnet", "No sphinx id, dropping.");
			return Poll::Ready(ConnectionEvent::None)
		}

		match self.read_timeout.poll_unpin(cx) {
			Poll::Ready(()) => {
				log::trace!(target: "mixnet", "Peer, nothing received for too long.");
				return Poll::Ready(ConnectionEvent::Broken)
			},
			Poll::Pending => (),
		}
		result
	}
}
