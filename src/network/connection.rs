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

//! Network connection.

use crate::{
	core::{MixPublicKey, Packet, PUBLIC_KEY_LEN},
	MixPeerId, PACKET_SIZE,
};
use futures::{channel::oneshot::Sender as OneShotSender, AsyncRead, AsyncWrite, FutureExt};
use std::{
	num::Wrapping,
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};

use crate::core::connection::ConnectionEvent;
use futures_timer::Delay;
use libp2p_swarm::NegotiatedSubstream;

pub const READ_TIMEOUT: Duration = Duration::from_secs(120); // TODO a bit less, but currently not that many cover sent

impl crate::core::connection::Connection for Connection {
	fn poll(&mut self, cx: &mut Context, handshake: &MixPublicKey) -> Poll<ConnectionEvent> {
		if !self.is_ready() {
			let mut result = Poll::Pending;
			match self.try_recv_handshake(cx) {
				Poll::Ready(Ok(key)) =>
					if let Some(key) = key {
						result = Poll::Ready(ConnectionEvent::Established(key));
					} else {
						result = Poll::Ready(ConnectionEvent::None);
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
			match self.try_packet_flushing(cx) {
				Poll::Ready(Ok(())) => {}, // recv will choose if pending
				Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
				Poll::Pending => (),
			}
			match self.try_recv_packet(cx, self.current_window) {
				Poll::Ready(Ok(Some(packet))) =>
					return Poll::Ready(ConnectionEvent::Received(packet)),
				Poll::Ready(Ok(None)) => return Poll::Ready(ConnectionEvent::None),
				Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
				Poll::Pending => (),
			}
		}

		match self.read_timeout.poll_unpin(cx) {
			Poll::Ready(()) => {
				log::trace!(target: "mixnet", "Peer, no recv for too long");
				return Poll::Ready(ConnectionEvent::Broken)
			},
			Poll::Pending => (),
		}
		Poll::Pending
	}
}

/// Internal information tracked for an established connection.
pub(crate) struct Connection {
	pub peer_id: MixPeerId,
	pub public_key: Option<MixPublicKey>,
	pub read_timeout: Delay, // TODO use handler TTL instead?
	pub inbound: Option<Pin<Box<NegotiatedSubstream>>>, // TODO remove some pin with Ext traits
	pub outbound: Pin<Box<NegotiatedSubstream>>, /* TODO just use a single stream for in and
	                          * out? */
	pub outbound_waiting: Option<(Vec<u8>, usize)>,
	pub inbound_waiting: (Vec<u8>, usize),
	// number of allowed message
	// in a window of time (can be modified
	// specifically by trait).
	pub limit_msg: Option<u32>,
	pub window_count: u32,
	pub current_window: Wrapping<usize>,
	pub packet_flushing: bool,
	pub handshake_flushing: bool,
	pub handshake_sent: bool,
	// inform connection handler when closing.
	// TODO just used by recv fail on dropping: use another type
	pub oneshot_handler: OneShotSender<()>,
}

impl Connection {
	pub fn new(
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
	pub fn try_send_packet(
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
