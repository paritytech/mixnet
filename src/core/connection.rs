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
	core::{QueuedPacket, PUBLIC_KEY_LEN, WINDOW_MARGIN_PERCENT},
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

pub const READ_TIMEOUT: Duration = Duration::from_secs(120); // TODO a bit less, but currently not that many cover sent

pub trait Connection {
	/// Start send a message. This trait expect single message queue
	/// and return the message back if another message is currently being send.
	fn try_send(&mut self, message: Vec<u8>) -> Option<Vec<u8>>;
	/// Send and flush, return when all message is written and flushed.
	/// Return false if ignored.
	/// Return Error if connection broke.
	fn send_flushed(&mut self, cx: &mut Context) -> Poll<Result<bool, ()>>;
	/// Try receive a packet of a given size.
	fn try_recv(&mut self, cx: &mut Context, size: usize) -> Poll<Result<Option<Vec<u8>>, ()>>;
}

pub(crate) enum ConnectionEvent {
	Established(MixPublicKey),
	Received(Packet),
	Broken,
	None,
}

pub(crate) struct ManagedConnection<C> {
	pub(crate) connection: C, // TODO priv
	peer_id: MixPeerId,
	handshake_sent: bool,
	public_key: Option<MixPublicKey>,
	// Real messages queue, sorted by deadline.
	packet_queue: BinaryHeap<QueuedPacket>,
	next_packet: Option<Vec<u8>>,
	read_timeout: Delay, // TODO use handler TTL instead? yes or just if too late in receiving.
	// number of allowed message
	// in a window of time (can be modified
	// specifically by trait).
	limit_msg: Option<u32>,
	window_count: u32,
	current_window: Wrapping<usize>,
	sent_in_window: usize,
	recv_in_window: usize,
}

impl<C: Connection> ManagedConnection<C> {
	pub fn new(
		peer_id: MixPeerId,
		limit_msg: Option<u32>,
		connection: C,
		current_window: Wrapping<usize>,
	) -> Self {
		Self {
			connection,
			peer_id,
			read_timeout: Delay::new(READ_TIMEOUT),
			next_packet: None,
			limit_msg,
			window_count: 0,
			current_window,
			public_key: None,
			handshake_sent: false,
			sent_in_window: 0,
			recv_in_window: 0,
			packet_queue: Default::default(), // TODO can have init from pending (if dialing).
		}
	}

	pub fn change_limit_msg(&mut self, limit: Option<u32>) {
		self.limit_msg = limit;
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
		if !self.handshake_sent {
			if self.connection.try_send(public_key.to_bytes().to_vec()).is_none() {
				self.handshake_sent = true;
			} else {
				unreachable!("Handshak is first connection send");
			}
		}
		match self.connection.send_flushed(cx) {
			Poll::Ready(Ok(true)) => Poll::Ready(Ok(())),
			Poll::Ready(Ok(false)) => {
				// wait on handshake reply or time out.
				Poll::Pending
			},
			Poll::Ready(Err(_)) => {
				log::trace!(target: "mixnet", "Error sending handshake to peer {:?}", self.peer_id);
				return Poll::Ready(Err(()))
			},
			Poll::Pending => Poll::Pending,
		}
	}

	fn try_send_flushed(&mut self, cx: &mut Context) -> Poll<Result<bool, ()>> {
		match self.connection.send_flushed(cx) {
			Poll::Ready(Ok(true)) => Poll::Ready(Ok(true)),
			Poll::Ready(Ok(false)) => Poll::Ready(Ok(false)),
			Poll::Ready(Err(())) => {
				log::trace!(target: "mixnet", "Error sending to peer {:?}", self.peer_id);
				return Poll::Ready(Err(()))
			},
			Poll::Pending => Poll::Pending,
		}
	}

	// return packet if already sending one.
	pub fn try_send_packet(&mut self, packet: Vec<u8>) -> Option<Vec<u8>> {
		if !self.is_ready() {
			log::error!(target: "mixnet", "Error sending to peer {:?}", self.peer_id);
			// Drop: TODO only drop after some
			return None
		}
		log::trace!(target: "mixnet", "sp {:?}", self.peer_id);
		self.connection.try_send(packet)
	}

	fn try_recv_handshake(&mut self, cx: &mut Context) -> Poll<Result<MixPublicKey, ()>> {
		if self.handshake_received() {
			// ignore
			return Poll::Pending
		}
		match self.connection.try_recv(cx, PUBLIC_KEY_LEN) {
			Poll::Ready(Ok(Some(key))) => {
				self.read_timeout.reset(READ_TIMEOUT); // TODO remove this read_timeout
				log::trace!(target: "mixnet", "Handshake message from {:?}", self.peer_id);
				let mut pk = [0u8; PUBLIC_KEY_LEN];
				pk.copy_from_slice(&key[..]);
				let pk = MixPublicKey::from(pk);
				self.public_key = Some(pk.clone()); // TODO is public key needed: just bool?
				Poll::Ready(Ok(pk))
			},
			Poll::Ready(Ok(None)) => self.try_recv_handshake(cx),
			Poll::Ready(Err(())) => {
				log::trace!(target: "mixnet", "Error receiving handshake from peer, closing: {:?}", self.peer_id);
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
			// TODO this is actually unreachable
			// ignore
			return Poll::Pending
		}
		match self.connection.try_recv(cx, PACKET_SIZE) {
			Poll::Ready(Ok(Some(packet))) => {
				self.read_timeout.reset(READ_TIMEOUT); // TODO remove this read_timeout
				log::trace!(target: "mixnet", "Packet received from {:?}", self.peer_id);
				let packet = Packet::from_vec(packet).unwrap();
				if self.current_window == current_window {
					self.window_count += 1;
					if self.limit_msg.as_ref().map(|l| &self.window_count > l).unwrap_or(false) {
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
				Poll::Ready(Ok(packet))
			},
			Poll::Ready(Ok(None)) => self.try_recv_packet(cx, current_window),
			Poll::Ready(Err(())) => {
				log::trace!(target: "mixnet", "Error receiving from peer, closing: {:?}", self.peer_id);
				Poll::Ready(Err(()))
			},
			Poll::Pending => Poll::Pending,
		}
	}

	pub(crate) fn queue_packet(
		&mut self,
		packet: QueuedPacket,
		packet_per_window: usize,
	) -> Result<(), crate::Error> {
		if self.packet_queue.len() > packet_per_window {
			// TODO apply a margin ??
			log::error!(target: "mixnet", "Dropping packet, queue full: {:?}", self.peer_id);
			return Err(crate::Error::QueueFull)
		}
		self.packet_queue.push(packet);
		Ok(())
	}

	// TODO struct window progress!!
	pub(crate) fn poll<T: Topology>(
		&mut self,
		cx: &mut Context,
		handshake: &MixPublicKey,
		current_window: Wrapping<usize>,
		current_packet_in_window: usize,
		packet_per_window: usize,
		now: Instant,
		topology: &mut T,
	) -> Poll<ConnectionEvent> {
		let mut result = Poll::Pending;
		if !self.is_ready() {
			let mut result = Poll::Pending;
			match self.try_recv_handshake(cx) {
				Poll::Ready(Ok(key)) => {
					self.current_window = current_window;
					self.sent_in_window = current_packet_in_window;
					self.recv_in_window = current_packet_in_window;
					result = Poll::Ready(ConnectionEvent::Established(key));
				},
				Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
				Poll::Pending => (),
			}
			match self.try_send_handshake(cx, handshake) {
				Poll::Ready(Ok(())) =>
					if matches!(result, Poll::Pending) {
						result = Poll::Ready(ConnectionEvent::None);
					},
				Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
				Poll::Pending => (),
			}
			return result
		} else {
			while self.sent_in_window < current_packet_in_window {
				match self.try_send_flushed(cx) {
					Poll::Ready(Ok(true)) => {
						self.sent_in_window += 1;
						break;
					},
					Poll::Ready(Ok(false)) => {
						if let Some(packet) = self.next_packet.take() {
							if let Some(packet) = self.try_send_packet(packet) {
								log::error!(target: "mixnet", "try send fail when should be ready.");
								self.next_packet = Some(packet);

								// TODO this should be unreachable, error after a few loop ?
							}
							continue
						}
						let deadline = self
							.packet_queue
							.peek()
							.map_or(false, |p| p.deadline.map(|d| d <= now).unwrap_or(true));
						if deadline {
							if let Some(packet) = self.packet_queue.pop() {
								self.next_packet = Some(packet.data.0);
							}
						} else {
							//break;
							if let Some(key) = self.public_key.clone() {
								if topology.routing() {
									self.next_packet =
										crate::core::cover_message_to(&self.peer_id, key).map(|p| p.0);
								} else {
									break;
								}
								if self.next_packet.is_none() {
									log::error!(target: "mixnet", "Could not create cover for {:?}", self.peer_id);
									break
								}
							}
						}
					},
					Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
					Poll::Pending => break,
				}
			}
			if self.recv_in_window < current_packet_in_window {
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
					log::warn!(target: "mixnet", "Window skipped {:?} ignoring report", skipped);
				// TODO can have a last tick in window that require being within margin.
				} else {
					let packet_per_window_less_margin =
						packet_per_window * (100 - WINDOW_MARGIN_PERCENT) / 100;
					if self.sent_in_window < packet_per_window_less_margin {
						// sent not enough: dest peer is not receiving enough
						log::trace!(target: "mixnet", "Low sent in window with {:?}", self.peer_id);
						// TODO send info to topology
					}
					if self.recv_in_window < packet_per_window_less_margin {
						// recv not enough: origin peer is not sending enough
						log::trace!(target: "mixnet", "Low recv in window with {:?}", self.peer_id);
						// TODO send info to topology
					}
				}

				self.current_window = current_window;
				self.sent_in_window = 0;
				self.recv_in_window = 0;
			}
		}

		match self.read_timeout.poll_unpin(cx) {
			Poll::Ready(()) => {
				log::trace!(target: "mixnet", "Peer, no recv for too long");
				return Poll::Ready(ConnectionEvent::Broken)
			},
			Poll::Pending => (),
		}
		result
	}
}
