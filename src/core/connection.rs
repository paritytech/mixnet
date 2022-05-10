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

use crate::{core::PUBLIC_KEY_LEN, MixPeerId, MixPublicKey, Packet, PACKET_SIZE};
use futures::{channel::oneshot::Sender as OneShotSender, AsyncRead, AsyncWrite, FutureExt};
use std::{
	num::Wrapping,
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};

use crate::network::Connection2;
use futures_timer::Delay;
use libp2p_swarm::NegotiatedSubstream;

pub const READ_TIMEOUT: Duration = Duration::from_secs(120); // TODO a bit less, but currently not that many cover sent

pub(crate) enum ConnectionEvent {
	Established(MixPublicKey),
	Received(Packet),
	Broken,
	None,
}

// Note that connection expect flushing to happen between each packet.
pub(crate) trait Connection {
	fn poll(&mut self, cx: &mut Context, handshake: &MixPublicKey) -> Poll<ConnectionEvent>;
}

pub(crate) struct ManagedConnection<C> {
	pub(crate) connection: C, // TODO priv
	peer_id: MixPeerId,
	handshake_sent: bool,
	public_key: Option<MixPublicKey>,
	read_timeout: Delay, // TODO use handler TTL instead?
	// number of allowed message
	// in a window of time (can be modified
	// specifically by trait).
	pub limit_msg: Option<u32>, // TODO non public
	window_count: u32,
	pub current_window: Wrapping<usize>, // TODO non public
}

impl<C: Connection2> ManagedConnection<C> {
	pub fn new(peer_id: MixPeerId, limit_msg: Option<u32>, connection: C) -> Self {
		Self {
			connection,
			peer_id,
			read_timeout: Delay::new(READ_TIMEOUT),
			limit_msg,
			window_count: 0,
			current_window: Wrapping(0),
			public_key: None,
			handshake_sent: false,
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

	fn try_send_flushed(&mut self, cx: &mut Context) -> Poll<Result<(), ()>> {
		match self.connection.send_flushed(cx) {
			Poll::Ready(Ok(true)) => {
				Poll::Ready(Ok(()))
			},
			Poll::Ready(Ok(false)) => {
				// wait on next tick
				Poll::Pending
			},
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

	pub(crate) fn poll(&mut self, cx: &mut Context, handshake: &MixPublicKey) -> Poll<ConnectionEvent> {
		let mut result = Poll::Pending;
		if !self.is_ready() {
			let mut result = Poll::Pending;
			match self.try_recv_handshake(cx) {
				Poll::Ready(Ok(key)) => {
					result = Poll::Ready(ConnectionEvent::Established(key));
				},
				Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
				Poll::Pending => (),
			}
			match self.try_send_handshake(cx, handshake) {
				Poll::Ready(Ok(())) => {
					result = Poll::Ready(ConnectionEvent::None);
				},
				Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
				Poll::Pending => (),
			}
			return result
		} else {
			match self.try_send_flushed(cx) {
				Poll::Ready(Ok(())) => {
					result = Poll::Ready(ConnectionEvent::None);
				},
				Poll::Ready(Err(())) => return Poll::Ready(ConnectionEvent::Broken),
				Poll::Pending => (),
			}
			match self.try_recv_packet(cx, self.current_window) {
				Poll::Ready(Ok(packet)) => return Poll::Ready(ConnectionEvent::Received(packet)),
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
		result
	}
}
