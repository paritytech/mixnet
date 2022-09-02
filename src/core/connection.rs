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
//!
//! Connection bandwidth is limited on reception
//! of packet.

use crate::{
	core::{PacketType, QueuedPacket, WindowInfo, WINDOW_MARGIN_PERCENT},
	traits::{Configuration, Connection, Handshake, Topology},
	ConnectedKind, MixPeerId, MixPublicKey, NetworkPeerId, Packet, PeerCount, PACKET_SIZE,
};
use futures::FutureExt;
use futures_timer::Delay;
use std::{
	collections::BinaryHeap,
	num::Wrapping,
	task::{Context, Poll},
	time::Duration,
};

const READ_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) enum ConnectionEvent {
	Established(MixPeerId, MixPublicKey),
	Received((Packet, bool)),
	Broken,
	None,
}

pub(crate) struct ManagedConnection<C> {
	connection: C,
	mixnet_id: Option<MixPeerId>,
	network_id: NetworkPeerId,
	kind: ConnectedKind,
	handshake_sent: bool,
	handshake_received: bool,
	public_key: Option<MixPublicKey>, // public key is only needed for creating cover messages.
	// Real messages queue, sorted by deadline (`QueuedPacket` is ord desc by deadline).
	packet_queue: BinaryHeap<QueuedPacket>,
	next_packet: Option<(Vec<u8>, PacketType)>,
	// If we did not receive for a while, close connection.
	read_timeout: Delay,
	current_window: Wrapping<usize>,
	sent_in_window: usize,
	recv_in_window: usize,
	stats: Option<(ConnectionStats, Option<PacketType>)>,
}

impl<C: Connection> ManagedConnection<C> {
	pub fn new(
		network_id: NetworkPeerId,
		connection: C,
		current_window: Wrapping<usize>,
		with_stats: bool,
		peers: &mut PeerCount,
	) -> Self {
		peers.nb_pending_handshake += 1;
		Self {
			connection,
			mixnet_id: None,
			network_id,
			kind: ConnectedKind::PendingHandshake,
			read_timeout: Delay::new(READ_TIMEOUT),
			next_packet: None,
			current_window,
			public_key: None,
			handshake_sent: false,
			handshake_received: false,
			sent_in_window: 0,
			recv_in_window: 0,
			packet_queue: Default::default(),
			stats: with_stats.then(Default::default),
		}
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
		topology: &mut impl Handshake,
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
			Poll::Ready(Ok(sent)) => {
				if let Some((stats, kind)) = self.stats.as_mut() {
					stats.success_packet(kind.take());
				}
				Poll::Ready(Ok(sent))
			},
			Poll::Ready(Err(())) => {
				log::trace!(target: "mixnet", "Error sending to peer {:?}", self.network_id);
				if let Some((stats, kind)) = self.stats.as_mut() {
					stats.failure_packet(kind.take());
				};
				Poll::Ready(Err(()))
			},
			Poll::Pending => Poll::Pending,
		}
	}

	// return packet if already sending one.
	pub fn try_queue_send_packet(&mut self, packet: Vec<u8>) -> Option<Vec<u8>> {
		if !self.kind.is_mixnet_connected() {
			// TODO queue if pending handshake or a given number if trying reco!!
			log::error!(target: "mixnet", "Peer {:?} not ready, dropping a packet", self.network_id);
			return None
		}
		self.connection.try_queue_send(packet)
	}

	fn try_recv_handshake(
		&mut self,
		cx: &mut Context,
		topology: &mut impl Handshake,
		peers: &PeerCount,
	) -> Poll<Result<(MixPeerId, MixPublicKey), ()>> {
		if self.handshake_received {
			// ignore
			return Poll::Pending
		}
		match self.connection.try_recv(cx, topology.handshake_size()) {
			Poll::Ready(Ok(Some(handshake))) => {
				self.read_timeout.reset(READ_TIMEOUT);
				log::trace!(target: "mixnet", "Handshake message from {:?}", self.network_id);
				if let Some((peer_id, pk)) =
					topology.check_handshake(handshake.as_slice(), &self.network_id, peers)
				{
					self.mixnet_id = Some(peer_id);
					self.public_key = Some(pk);
					self.handshake_received = true;
					Poll::Ready(Ok((peer_id, pk)))
				} else {
					log::trace!(target: "mixnet", "Invalid handshake from peer, closing: {:?}", self.network_id);
					Poll::Ready(Err(()))
				}
			},
			Poll::Ready(Ok(None)) => self.try_recv_handshake(cx, topology, peers),
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
		if !self.kind.is_mixnet_connected() {
			// this is actually unreachable but ignore it.
			return Poll::Pending
		}
		match self.connection.try_recv(cx, PACKET_SIZE) {
			Poll::Ready(Ok(Some(packet))) => {
				self.read_timeout.reset(READ_TIMEOUT);
				log::trace!(target: "mixnet", "Packet received from {:?}", self.network_id);
				let packet = Packet::from_vec(packet).unwrap();
				if self.current_window != current_window {
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
		peers: &PeerCount,
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
				topology.bandwidth_external(peer_id, peers).is_none()
			{
				log::trace!(target: "mixnet", "Dropping a queued packet, not in topology or allowed external.");
				return Err(crate::Error::NoPath(Some(*peer_id)))
			}
			self.packet_queue.push(packet);
			if let Some((stats, _)) = self.stats.as_mut() {
				let mut len = self.packet_queue.len();
				if self.next_packet.is_some() {
					len += 1;
				}
				if len > stats.max_peer_paquet_queue_size {
					stats.max_peer_paquet_queue_size = len;
				}
			}
			Ok(())
		} else {
			Err(crate::Error::NoSphinxId)
		}
	}

	fn broken_connection(
		&mut self,
		topology: &mut impl Configuration,
		peers: &mut PeerCount,
	) -> Poll<ConnectionEvent> {
		peers.remove_peer(self.disconnected_kind());
		topology.peer_stats(peers);
		Poll::Ready(ConnectionEvent::Broken)
	}

	pub(crate) fn poll(
		&mut self,
		cx: &mut Context,
		local_id: &MixPeerId,
		handshake: &MixPublicKey,
		window: &WindowInfo,
		topology: &mut impl Configuration,
		peers: &mut PeerCount,
	) -> Poll<ConnectionEvent> {
		let mut result = Poll::Pending;
		// TODO add a state where we wait peer accept before sending cover?
		if !(self.handshake_sent && self.handshake_received) {
			let mut result = Poll::Pending;
			match self.try_recv_handshake(cx, topology, peers) {
				Poll::Ready(Ok(key)) => {
					self.current_window = window.current;
					self.sent_in_window = window.current_packet_limit;
					self.recv_in_window = window.current_packet_limit;
					// TODO nb_pending_handshake change here
					result = Poll::Ready(ConnectionEvent::Established(key.0, key.1));
				},
				Poll::Ready(Err(())) => return self.broken_connection(topology, peers),
				Poll::Pending => (),
			}
			match self.try_send_handshake(cx, handshake, topology) {
				Poll::Ready(Ok(())) =>
					if matches!(result, Poll::Pending) {
						result = Poll::Ready(ConnectionEvent::None);
					},
				Poll::Ready(Err(())) => return self.broken_connection(topology, peers),
				Poll::Pending => (),
			}
			return result
		} else if let Some(peer_id) = self.mixnet_id {
			// TODO this could be a poll on a channel.
			if self.kind == ConnectedKind::PendingHandshake || topology.changed_routing(&peer_id) {
				let old_kind = self.kind;
				self.kind = peers.add_peer(local_id, &peer_id, topology);
				peers.remove_peer(old_kind);
				topology.peer_stats(peers);
			}

			let routing = topology.can_route(local_id);

			// Forward first.
			while self.sent_in_window < window.current_packet_limit {
				match self.try_send_flushed(cx) {
					Poll::Ready(Ok(true)) => {
						// Did send message
						self.sent_in_window += 1;
						break
					},
					Poll::Ready(Ok(false)) => {
						// nothing in queue, get next.
						if let Some(packet) = self.next_packet.take() {
							if let Some(unsend) = self.try_queue_send_packet(packet.0) {
								log::error!(target: "mixnet", "try send should not fail on flushed queue.");
								if let Some((stats, _)) = self.stats.as_mut() {
									stats.failure_packet(Some(packet.1));
								}
								self.next_packet = Some((unsend, packet.1));
							} else if let Some(stats) = self.stats.as_mut() {
								stats.1 = Some(packet.1);
							}
							continue
						}
						let deadline = self
							.packet_queue
							.peek()
							.map_or(false, |p| p.deadline <= window.last_now);
						if deadline {
							if let Some(packet) = self.packet_queue.pop() {
								self.next_packet = Some((packet.data.into_vec(), packet.kind));
							}
						} else if let Some(key) = self.public_key {
							if routing && self.kind.routing_forward() {
								self.next_packet = crate::core::cover_message_to(&peer_id, key)
									.map(|p| (p.into_vec(), PacketType::Cover));
								if self.next_packet.is_none() {
									log::error!(target: "mixnet", "Could not create cover for {:?}", self.network_id);
									if let Some(stats) = self.stats.as_mut() {
										stats.0.number_cover_send_failed += 1;
									}
								}
							}
							if self.next_packet.is_none() {
								break
							}
						}
					},
					Poll::Ready(Err(())) => return self.broken_connection(topology, peers),
					Poll::Pending => break,
				}
			}

			// Limit reception.
			let (current, external) = if self.kind.routing_receive() {
				(window.current_packet_limit, false)
			} else {
				// TODO should cache topology with kind (and recalc when one new external,
				// not only when changed_routing)
				let (n, d) = topology.bandwidth_external(&peer_id, peers).unwrap_or((0, 1));
				((window.current_packet_limit * n) / d, true)
			};
			if self.recv_in_window < current {
				match self.try_recv_packet(cx, window.current) {
					Poll::Ready(Ok(packet)) => {
						self.recv_in_window += 1;
						result = Poll::Ready(ConnectionEvent::Received((packet, external)));
					},
					Poll::Ready(Err(())) => return self.broken_connection(topology, peers),
					Poll::Pending => (),
				}
			}

			if window.current != self.current_window {
				if self.current_window + Wrapping(1) != window.current {
					let skipped = window.current - self.current_window;
					log::error!(target: "mixnet", "Window skipped {:?} ignoring report.", skipped);
				} else if !external {
					let packet_per_window_less_margin =
						window.packet_per_window * (100 - WINDOW_MARGIN_PERCENT) / 100;
					if self.sent_in_window < packet_per_window_less_margin {
						// sent not enough: dest peer is not receiving enough
						log::warn!(target: "mixnet", "Low sent in window with {:?}, {:?} / {:?}", self.network_id, self.sent_in_window, packet_per_window_less_margin);
					}
					if self.recv_in_window < packet_per_window_less_margin {
						// recv not enough: origin peer is not sending enough
						log::warn!(target: "mixnet", "Low recv in window with {:?}, {:?} / {:?}", self.network_id, self.recv_in_window, packet_per_window_less_margin);
					}
				}

				self.current_window = window.current;
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
				return self.broken_connection(topology, peers)
			},
			Poll::Pending => (),
		}
		result
	}

	pub fn connection_stats(&mut self) -> Option<&mut ConnectionStats> {
		self.stats.as_mut().map(|stats| {
			// heuristic we just get the queue size when queried.
			stats.0.peer_paquet_queue_size = self.packet_queue.len();
			if self.next_packet.is_some() {
				stats.0.peer_paquet_queue_size += 1;
			}
			&mut stats.0
		})
	}

	pub fn disconnected_kind(&mut self) -> ConnectedKind {
		let kind = self.kind;
		self.handshake_sent = false;
		self.handshake_received = false;
		self.kind = ConnectedKind::Disconnected;
		kind
	}
}

impl<C> Drop for ManagedConnection<C> {
	fn drop(&mut self) {
		if let Some((stats, _)) = self.stats.as_mut() {
			if let Some(packet) = self.next_packet.take() {
				stats.failure_packet(Some(packet.1))
			}
			for packet in self.packet_queue.iter() {
				stats.failure_packet(Some(packet.kind))
			}
		}
	}
}

#[derive(Default, Debug)]
pub struct ConnectionStats {
	// Do not include external or self
	pub number_forwarded_success: usize,
	pub number_forwarded_failed: usize,

	pub number_from_external_forwarded_success: usize,
	pub number_from_external_forwarded_failed: usize,

	pub number_from_self_send_success: usize,
	pub number_from_self_send_failed: usize,

	pub number_surbs_reply_success: usize,
	pub number_surbs_reply_failed: usize,

	pub number_cover_send_success: usize,
	pub number_cover_send_failed: usize,

	pub max_peer_paquet_queue_size: usize,

	pub peer_paquet_queue_size: usize,
}

impl ConnectionStats {
	pub(crate) fn add(&mut self, other: &Self) {
		self.number_forwarded_success += other.number_forwarded_success;
		self.number_forwarded_failed += other.number_forwarded_failed;

		self.number_from_external_forwarded_success += other.number_from_external_forwarded_success;
		self.number_from_external_forwarded_failed += other.number_from_external_forwarded_success;

		self.number_from_self_send_success += other.number_from_self_send_success;
		self.number_from_self_send_failed += other.number_from_self_send_failed;

		self.number_surbs_reply_success += other.number_surbs_reply_success;
		self.number_surbs_reply_failed += other.number_surbs_reply_failed;

		self.number_cover_send_success += other.number_cover_send_success;
		self.number_cover_send_failed += other.number_cover_send_failed;

		self.max_peer_paquet_queue_size =
			std::cmp::max(self.max_peer_paquet_queue_size, other.max_peer_paquet_queue_size);

		self.peer_paquet_queue_size += other.peer_paquet_queue_size;
	}

	fn success_packet(&mut self, kind: Option<PacketType>) {
		let kind = if let Some(kind) = kind { kind } else { return };

		match kind {
			PacketType::Forward => {
				self.number_forwarded_success += 1;
			},
			PacketType::ForwardExternal => {
				self.number_from_external_forwarded_success += 1;
			},
			PacketType::SendFromSelf => {
				self.number_from_self_send_success += 1;
			},
			PacketType::Cover => {
				self.number_cover_send_success += 1;
			},
			PacketType::Surbs => {
				self.number_surbs_reply_success += 1;
			},
		}
	}

	fn failure_packet(&mut self, kind: Option<PacketType>) {
		let kind = if let Some(kind) = kind { kind } else { return };

		match kind {
			PacketType::Forward => {
				self.number_forwarded_failed += 1;
			},
			PacketType::ForwardExternal => {
				self.number_from_external_forwarded_failed += 1;
			},
			PacketType::SendFromSelf => {
				self.number_from_self_send_failed += 1;
			},
			PacketType::Cover => {
				self.number_cover_send_failed += 1;
			},
			PacketType::Surbs => {
				self.number_surbs_reply_failed += 1;
			},
		}
	}
}
