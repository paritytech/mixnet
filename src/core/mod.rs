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

// Mixnet core logic. This module tries to be network agnostic.

mod config;
pub(crate) mod connection;
mod error;
mod fragment;
mod sphinx;

use self::{fragment::MessageCollection, sphinx::Unwrapped};
pub use crate::core::sphinx::{hash, SprpKey, SurbsPayload, SurbsPersistance};
use crate::{
	core::connection::{ConnectionEvent, ConnectionStats, ManagedConnection},
	traits::{Configuration, Connection},
	DecodedMessage, MessageType, MixPeerId, MixnetEvent, NetworkPeerId, SendOptions, WorkerSink2,
};
pub use config::Config;
pub use error::Error;
use futures::{FutureExt, SinkExt};
use futures_timer::Delay;
use rand::{CryptoRng, Rng};
use rand_distr::Distribution;
pub use sphinx::Error as SphinxError;
use std::{
	cmp::Ordering,
	collections::{HashMap, VecDeque},
	num::Wrapping,
	task::{Context, Poll},
	time::{Duration, Instant},
};

/// Mixnet peer DH static public key.
pub type MixPublicKey = sphinx::PublicKey;
/// Mixnet peer DH static secret key.
pub type MixSecretKey = sphinx::StaticSecret;

/// Length of `MixPublicKey`
pub const PUBLIC_KEY_LEN: usize = 32;

/// Size of a mixnet packet.
pub const PACKET_SIZE: usize = sphinx::OVERHEAD_SIZE + fragment::FRAGMENT_PACKET_SIZE;

/// Size of the polling window in time.
pub const WINDOW_DELAY: Duration = Duration::from_secs(2);

pub const WINDOW_MARGIN_PERCENT: usize = 10;

/// Associated information to a packet or header.
pub struct TransmitInfo {
	sprp_keys: Vec<SprpKey>,
	surb_id: Option<ReplayTag>,
}

/// Sphinx packet struct, goal of this struct
/// is only to ensure the packet size is right.
#[derive(PartialEq, Eq, Debug)]
pub struct Packet(Vec<u8>);

impl Packet {
	fn new(header: &[u8], payload: &[u8]) -> Result<Self, SphinxError> {
		let mut packet = Vec::with_capacity(PACKET_SIZE);
		if header.len() != sphinx::HEADER_SIZE {
			return Err(SphinxError::InvalidPacket)
		}
		packet.extend_from_slice(header);
		packet.extend_from_slice(payload);
		Self::from_vec(packet)
	}

	pub fn from_vec(data: Vec<u8>) -> Result<Self, SphinxError> {
		if data.len() == PACKET_SIZE {
			Ok(Packet(data))
		} else {
			Err(SphinxError::InvalidPacket)
		}
	}

	fn into_vec(self) -> Vec<u8> {
		self.0
	}

	fn as_mut(&mut self) -> &mut [u8] {
		self.0.as_mut()
	}
}

pub enum MixEvent {
	Disconnected(Vec<NetworkPeerId>),
	None,
}

pub fn to_sphinx_id(id: &NetworkPeerId) -> Result<MixPeerId, Error> {
	let hash = id.as_ref();
	match libp2p_core::multihash::Code::try_from(hash.code()) {
		Ok(libp2p_core::multihash::Code::Identity) => {
			let decoded = libp2p_core::identity::PublicKey::from_protobuf_encoding(hash.digest())
				.map_err(|_e| Error::InvalidId(*id))?;
			let public = match decoded {
				libp2p_core::identity::PublicKey::Ed25519(key) => key.encode(),
				_ => return Err(Error::InvalidId(*id)),
			};
			Ok(public)
		},
		_ => Err(Error::InvalidId(*id)),
	}
}

fn exp_delay<R: Rng + CryptoRng + ?Sized>(rng: &mut R, target: Duration) -> Duration {
	let exp = rand_distr::Exp::new(1.0 / target.as_nanos() as f64).unwrap();
	Duration::from_nanos(exp.sample(rng).round() as u64)
}

/// Construct a Montgomery curve25519 private key from an Ed25519 secret key.
pub fn secret_from_ed25519(seed: &[u8; 32]) -> MixSecretKey {
	// An Ed25519 public key is derived off the left half of the SHA512 of the
	// secret scalar, hence a matching conversion of the secret key must do
	// the same to yield a Curve25519 keypair with the same public key.
	// let ed25519_sk = ed25519::SecretKey::from(ed);
	let mut curve25519_sk = [0; 32];
	let hash = <sha2::Sha512 as sha2::Digest>::digest(seed);
	curve25519_sk.copy_from_slice(&hash[..32]);
	curve25519_sk.into()
}

/// Construct a Montgomery curve25519 public key from an Ed25519 public key.
pub fn public_from_ed25519(ed25519_pk: [u8; 32]) -> MixPublicKey {
	curve25519_dalek::edwards::CompressedEdwardsY(ed25519_pk)
		.decompress()
		.expect("An Ed25519 public key is a valid point by construction.")
		.to_montgomery()
		.to_bytes()
		.into()
}

// only needed for stats
#[derive(PartialEq, Eq, Clone, Copy)]
enum PacketType {
	Forward,
	ForwardExternal,
	SendFromSelf,
	Surbs,
	Cover,
}

#[derive(PartialEq, Eq)]
/// A real traffic message that we need to forward.
pub(crate) struct QueuedPacket {
	deadline: Instant,
	kind: PacketType,
	pub data: Packet,
}

impl std::cmp::PartialOrd for QueuedPacket {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.deadline.cmp(&other.deadline).reverse())
	}
}

impl std::cmp::Ord for QueuedPacket {
	fn cmp(&self, other: &Self) -> Ordering {
		self.deadline.cmp(&other.deadline).reverse()
	}
}

/// Mixnet core. Mixes messages, tracks fragments and delays.
pub struct Mixnet<T, C> {
	pub topology: T,
	num_hops: usize,
	pub public: MixPublicKey,
	secret: MixSecretKey,
	local_id: MixPeerId,
	connected_peers: HashMap<NetworkPeerId, ManagedConnection<C>>,
	handshaken_peers: HashMap<MixPeerId, NetworkPeerId>,
	// Incomplete incoming message fragments.
	fragments: fragment::MessageCollection,
	// Message waiting for surb.
	surb: SurbsCollection,
	// Received message filter.
	replay_filter: ReplayFilter,
	// Timer for the next poll for messages.
	next_message: Delay,
	// Average delay at which we poll for real or cover messages.
	average_traffic_delay: Duration,
	// Average delay for each packet at each hop.
	average_hop_delay: Duration,
	// If true keep original message with surb
	// and return it with surb reply.
	persist_surb_query: bool,

	window: WindowInfo,
}

/// Mixnet window current state.
pub struct WindowInfo {
	packet_per_window: usize,
	current_start: Instant,
	current: Wrapping<usize>,
	current_packet_limit: usize,
	last_now: Instant,
	delay: Delay,
	stats: Option<WindowStats>,
}

impl<T: Configuration, C: Connection> Mixnet<T, C> {
	/// Create a new instance with given config.
	pub fn new(config: Config, topology: T) -> Self {
		let packet_duration_nanos =
			(PACKET_SIZE * 8) as u64 * 1_000_000_000 / config.target_bytes_per_second as u64;
		let average_traffic_delay = Duration::from_nanos(packet_duration_nanos);
		let packet_per_window = (WINDOW_DELAY.as_nanos() / packet_duration_nanos as u128) as usize;
		debug_assert!(packet_per_window > 0);

		let now = Instant::now();
		let stats = topology.collect_windows_stats().then(WindowStats::default);
		Mixnet {
			topology,
			surb: SurbsCollection::new(&config),
			replay_filter: ReplayFilter::new(&config),
			persist_surb_query: config.persist_surb_query,
			num_hops: config.num_hops as usize,
			public: config.public_key,
			secret: config.secret_key,
			local_id: config.local_id,
			fragments: MessageCollection::new(),
			connected_peers: Default::default(),
			handshaken_peers: Default::default(),
			next_message: Delay::new(Duration::from_millis(0)),
			average_hop_delay: Duration::from_millis(config.average_message_delay_ms as u64),
			average_traffic_delay,
			window: WindowInfo {
				current_start: now,
				last_now: now,
				current: Wrapping(0),
				current_packet_limit: 0,
				delay: Delay::new(WINDOW_DELAY),
				packet_per_window,
				stats,
			},
		}
	}

	pub fn restart(
		&mut self,
		new_id: Option<crate::MixPeerId>,
		new_keys: Option<(MixPublicKey, crate::MixSecretKey)>,
	) {
		if let Some(id) = new_id {
			self.local_id = id
		}
		if let Some((pub_key, priv_key)) = new_keys {
			self.public = pub_key;
			self.secret = priv_key;
		}
		// disconnect all (need a new handshake).
		for (_mix_id, connection) in std::mem::take(&mut self.connected_peers).into_iter() {
			if let Some(mix_id) = connection.mixnet_id() {
				self.handshaken_peers.remove(mix_id);
				self.topology.disconnected(mix_id);
			}
		}
	}

	pub fn insert_connection(&mut self, peer: NetworkPeerId, connection: C) {
		let connection = ManagedConnection::new(
			peer,
			connection,
			self.window.current,
			self.window.stats.is_some(),
		);
		self.connected_peers.insert(peer, connection);
	}

	pub fn connected_mut(&mut self, peer: &NetworkPeerId) -> Option<&mut C> {
		self.connected_peers.get_mut(peer).map(|c| c.connection_mut())
	}

	pub fn local_id(&self) -> &MixPeerId {
		&self.local_id
	}

	pub fn public_key(&self) -> &crate::MixPublicKey {
		&self.public
	}

	fn queue_packet(
		&mut self,
		recipient: MixPeerId,
		data: Packet,
		delay: Duration,
		kind: PacketType,
	) -> Result<(), Error> {
		if let Some(connection) = self
			.handshaken_peers
			.get(&recipient)
			.and_then(|r| self.connected_peers.get_mut(r))
		{
			let deadline = self.window.last_now + delay;
			connection.queue_packet(
				QueuedPacket { deadline, data, kind },
				self.window.packet_per_window,
				&self.local_id,
				&self.topology,
				false,
			)?;
		} else {
			return Err(Error::Unreachable(data))
		}
		Ok(())
	}

	// When node are not routing, the packet is not delayed
	// and sent immediatly.
	fn queue_external_packet(
		&mut self,
		recipient: MixPeerId,
		data: Packet,
		kind: PacketType,
	) -> Result<(), Error> {
		if let Some(connection) = self
			.handshaken_peers
			.get(&recipient)
			.and_then(|r| self.connected_peers.get_mut(r))
		{
			let deadline = self.window.last_now;
			connection.queue_packet(
				QueuedPacket { deadline, data, kind },
				self.window.packet_per_window,
				&self.local_id,
				&self.topology,
				true,
			)?;
		} else {
			return Err(Error::Unreachable(data))
		}
		Ok(())
	}

	/// Send a new message to the network. Message is split int multiple fragments and each fragment
	/// is sent over and individual path to the recipient. If no recipient is specified, a random
	/// recipient is selected.
	pub fn register_message(
		&mut self,
		peer_id: Option<MixPeerId>,
		peer_pub_key: Option<MixPublicKey>,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> Result<(), Error> {
		let mut rng = rand::thread_rng();

		let (maybe_peer_id, peer_pub_key) = if let Some(id) = peer_id {
			(Some(id), peer_pub_key)
		} else if let Some((id, key)) =
			self.topology.random_recipient(&self.local_id, &send_options)
		{
			(Some(id), Some(key))
		} else {
			(None, None)
		};

		let peer_id =
			if let Some(id) = maybe_peer_id { id } else { return Err(Error::NoPath(None)) };

		let mut surb_query =
			(self.persist_surb_query && send_options.with_surb).then(|| message.clone());

		let chunks = fragment::create_fragments(&mut rng, message, send_options.with_surb)?;
		let paths = self.random_paths(
			&peer_id,
			peer_pub_key.as_ref(),
			&send_options.num_hop,
			chunks.len(),
			None,
		)?;

		let mut surb = if send_options.with_surb {
			//let ours = (MixPeerId, MixPublicKey);
			let paths = self
				.random_paths(
					&peer_id,
					peer_pub_key.as_ref(),
					&send_options.num_hop,
					1,
					paths.last(),
				)?
				.remove(0);
			let first_node = paths[0].0;
			let paths: Vec<_> = paths
				.into_iter()
				.map(|(id, public_key)| sphinx::PathHop { id, public_key })
				.collect();

			Some((first_node, paths))
		} else {
			None
		};
		let nb_chunks = chunks.len();
		let mut packets = Vec::with_capacity(nb_chunks);
		for (n, chunk) in chunks.into_iter().enumerate() {
			let (first_id, _) = *paths[n].first().unwrap();
			let hops: Vec<_> = paths[n]
				.iter()
				.map(|(id, key)| sphinx::PathHop { id: *id, public_key: *key })
				.collect();
			let chunk_surb = if n == 0 { surb.take() } else { None };
			let (packet, surb_keys) =
				sphinx::new_packet(&mut rng, hops, chunk.into_vec(), chunk_surb)
					.map_err(Error::SphinxError)?;
			if let Some(TransmitInfo { sprp_keys: keys, surb_id: Some(surb_id) }) = surb_keys {
				let persistance = SurbsPersistance {
					keys,
					query: surb_query.take(),
					recipient: *paths[n].last().unwrap(),
				};
				self.surb.insert(surb_id, persistance, self.window.last_now);
			}
			packets.push((first_id, packet));
		}

		if self.topology.is_first_node(&self.local_id) {
			for (peer_id, packet) in packets {
				let delay = exp_delay(&mut rng, self.average_hop_delay);
				self.queue_packet(peer_id, packet, delay, PacketType::SendFromSelf)?;
			}
		} else {
			for (peer_id, packet) in packets {
				self.queue_external_packet(peer_id, packet, PacketType::SendFromSelf)?;
			}
		}
		Ok(())
	}

	/// Send a new surb message to the network.
	/// Message cannot be bigger than a single fragment.
	pub fn register_surb(&mut self, message: Vec<u8>, surb: SurbsPayload) -> Result<(), Error> {
		let SurbsPayload { first_node, first_key, header } = surb;
		let mut rng = rand::thread_rng();

		let mut chunks = fragment::create_fragments(&mut rng, message, false)?;
		if chunks.len() != 1 {
			return Err(Error::BadSurbsLength)
		}

		let packet = sphinx::new_surb_packet(first_key, chunks.remove(0).into_vec(), header)
			.map_err(Error::SphinxError)?;
		let dest = first_node;
		if self.topology.can_route(&self.local_id) {
			let delay = exp_delay(&mut rng, self.average_hop_delay);
			self.queue_packet(dest, packet, delay, PacketType::Surbs)?;
		} else {
			self.queue_external_packet(dest, packet, PacketType::Surbs)?;
		}
		Ok(())
	}

	/// Handle new packet coming from the network. Removes one layer of Sphinx encryption and either
	/// adds the result to the queue for forwarding, or accepts the fragment addressed to us. If the
	/// fragment completes the message, full message is returned.
	pub fn import_message(
		&mut self,
		peer_id: MixPeerId,
		message: Packet,
	) -> Result<Option<(Vec<u8>, MessageType)>, Error> {
		let next_delay =
			|| exp_delay(&mut rand::thread_rng(), self.average_hop_delay).as_millis() as u32;
		let result = sphinx::unwrap_packet(
			&self.secret,
			message,
			&mut self.surb,
			&mut self.replay_filter,
			next_delay,
		);
		match result {
			Err(e) => {
				log::debug!(target: "mixnet", "Error unpacking message received from {:?} :{:?}", peer_id, e);
				return Ok(None)
			},
			Ok(Unwrapped::Payload(payload)) => {
				if let Some(m) = self.fragments.insert_fragment(payload, MessageType::StandAlone)? {
					log::debug!(target: "mixnet", "Imported message from {:?} ({} bytes)", peer_id, m.0.len());
					return Ok(Some(m))
				} else {
					log::trace!(target: "mixnet", "Inserted fragment message from {:?}", peer_id);
				}
			},
			Ok(Unwrapped::SurbsReply(payload, query, recipient)) => {
				if let Some(m) = self
					.fragments
					.insert_fragment(payload, MessageType::FromSurbs(query, recipient))?
				{
					log::debug!(target: "mixnet", "Imported surb from {:?} ({} bytes)", peer_id, m.0.len());
					return Ok(Some(m))
				} else {
					log::error!(target: "mixnet", "Surbs fragment from {:?}", peer_id);
				}
			},
			Ok(Unwrapped::SurbsQuery(encoded_surb, payload)) => {
				debug_assert!(encoded_surb.len() == crate::core::sphinx::SURBS_REPLY_SIZE);
				if let Some(m) = self.fragments.insert_fragment(
					payload,
					MessageType::WithSurbs(Box::new(encoded_surb.into())),
				)? {
					log::debug!(target: "mixnet", "Imported message from {:?} ({} bytes)", peer_id, m.0.len());
					return Ok(Some(m))
				} else {
					log::warn!(target: "mixnet", "Inserted fragment message from {:?}, stored surb enveloppe.", peer_id);
				}
			},
			Ok(Unwrapped::Forward((next_id, delay, packet))) => {
				// See if we can forward the message
				log::debug!(target: "mixnet", "Forward message from {:?} to {:?}", peer_id, next_id);
				let kind = if self.window.stats.is_some() && !self.topology.can_route(&peer_id) {
					PacketType::ForwardExternal
				} else {
					PacketType::Forward
				};
				self.queue_packet(next_id, packet, Duration::from_nanos(delay as u64), kind)?;
			},
		}
		Ok(None)
	}

	/// Should be called when a peer is disconnected.
	pub fn remove_connected_peer(&mut self, id: &NetworkPeerId) {
		if let Some(mix_id) = self.connected_peers.remove(id).and_then(|c| c.mixnet_id().cloned()) {
			self.handshaken_peers.remove(&mix_id);
			self.topology.disconnected(&mix_id);
		}
	}

	fn random_paths(
		&mut self,
		recipient: &MixPeerId,
		recipient_key: Option<&MixPublicKey>,
		num_hops: &Option<usize>,
		count: usize,
		last_query_if_surb: Option<&Vec<(MixPeerId, MixPublicKey)>>,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
		let (start, recipient) = if last_query_if_surb.is_some() {
			((recipient, recipient_key), (&self.local_id, Some(&self.public)))
		} else {
			((&self.local_id, Some(&self.public)), (recipient, recipient_key))
		};

		let num_hops = num_hops.unwrap_or(self.num_hops);
		if num_hops > sphinx::MAX_HOPS {
			return Err(Error::TooManyHops)
		}

		log::trace!(target: "mixnet", "Random path, length {:?}", num_hops);
		self.topology.random_path(
			start,
			recipient,
			count,
			num_hops,
			sphinx::MAX_HOPS,
			last_query_if_surb,
		)
	}

	fn cleanup(&mut self, now: Instant) {
		self.fragments.cleanup(now);
		self.surb.cleanup(now);
		self.replay_filter.cleanup(now);
	}

	// Poll for new messages to send over the wire.
	pub fn poll(&mut self, cx: &mut Context<'_>, results: &mut WorkerSink2) -> Poll<MixEvent> {
		if Poll::Ready(()) == self.next_message.poll_unpin(cx) {
			let now = Instant::now();
			self.window.last_now = now;
			// if everything is pending, window delay will wake up context switch window,
			// and log insufficient receive messages.
			if self.window.delay.poll_unpin(cx).is_ready() {
				let duration = now - self.window.current_start;
				let nb_spent = (duration.as_millis() / WINDOW_DELAY.as_millis()) as usize;

				self.window.current += Wrapping(nb_spent);
				for _ in 0..nb_spent {
					self.window.current_start += WINDOW_DELAY;
				}

				if let Some(stats) = self.window.stats.as_mut() {
					*stats = Default::default();
					stats.last_window = self.window.current.0 - nb_spent;
					stats.window = self.window.current.0;
					stats.number_connected = self.connected_peers.len();
					for (_, c) in self.connected_peers.iter_mut() {
						if let Some(stat) = c.connection_stats() {
							stats.sum_connected.add(stat);
							*stat = Default::default();
						}
					}

					self.topology.window_stats(stats);
				}

				self.window.delay.reset(WINDOW_DELAY);
				while !matches!(self.window.delay.poll_unpin(cx), Poll::Pending) {
					self.window.delay.reset(WINDOW_DELAY);
				}
			}

			let duration = now - self.window.current_start;
			self.window.current_packet_limit = ((duration.as_millis() as u64 *
				self.window.packet_per_window as u64) /
				WINDOW_DELAY.as_millis() as u64) as usize;

			self.cleanup(now);
			let next_delay = self.average_traffic_delay;
			while !matches!(self.next_message.poll_unpin(cx), Poll::Pending) {
				self.next_message.reset(next_delay);
			}
		}

		let mut all_pending = true;
		let mut disconnected = Vec::new();
		let mut recv_packets = Vec::new();

		// TODO shuffled iterator?
		for (peer_id, connection) in self.connected_peers.iter_mut() {
			match connection.poll(
				cx,
				&self.local_id,
				&self.public,
				&self.window,
				&mut self.topology,
			) {
				Poll::Ready(ConnectionEvent::Established(_id, key)) => {
					all_pending = false;
					if let Some(sphinx_id) = connection.mixnet_id() {
						self.handshaken_peers.insert(*sphinx_id, connection.network_id());
						self.topology.connected(*sphinx_id, key);
					}
					if let Err(e) = results
						.start_send_unpin(MixnetEvent::Connected(connection.network_id(), key))
					{
						log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
					}
				},
				Poll::Ready(ConnectionEvent::Broken) => {
					// same as pending
					disconnected.push(*peer_id);
				},
				Poll::Ready(ConnectionEvent::None) => {
					all_pending = false;
				},
				Poll::Ready(ConnectionEvent::Received(packet)) => {
					all_pending = false;
					if let Some(sphinx_id) = connection.mixnet_id() {
						recv_packets.push((*sphinx_id, packet));
					}
				},
				Poll::Pending => (),
			}
		}

		for (peer, (packet, external)) in recv_packets {
			if !self.import_packet(peer, packet, results) {
				// warning this only indicate a peer send wrong packet, but cannot presume
				// who (can be external).
				log::trace!(target: "mixnet", "Error importing packet, wrong format.");
				if let Some(stats) = self.window.stats.as_mut() {
					if external {
						stats.number_from_external_received_valid += 1;
					} else {
						stats.number_received_valid += 1;
					}
				}
			}
		}

		if !disconnected.is_empty() {
			for peer in disconnected.iter() {
				log::trace!(target: "mixnet", "Disconnecting peer {:?}", peer);
				self.remove_connected_peer(peer);
			}

			return Poll::Ready(MixEvent::Disconnected(disconnected))
		}

		if all_pending {
			Poll::Pending
		} else {
			Poll::Ready(MixEvent::None)
		}
	}

	fn import_packet(
		&mut self,
		peer: MixPeerId,
		packet: Packet,
		results: &mut WorkerSink2,
	) -> bool {
		match self.import_message(peer, packet) {
			Ok(Some((message, kind))) => {
				if let Err(e) = results.start_send_unpin(MixnetEvent::Message(DecodedMessage {
					peer,
					message,
					kind,
				})) {
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

/// Message id, use as surb key and replay protection.
/// This is the result of hashing the secret.
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct ReplayTag([u8; crate::core::sphinx::HASH_OUTPUT_SIZE]);

pub struct SurbsCollection {
	pending: MixnetCollection<ReplayTag, SurbsPersistance>,
}

impl SurbsCollection {
	pub fn new(config: &Config) -> Self {
		SurbsCollection { pending: MixnetCollection::new(config.surb_ttl_ms) }
	}

	pub fn insert(&mut self, surb_id: ReplayTag, surb: SurbsPersistance, now: Instant) {
		self.pending.insert(surb_id, surb, now);
	}

	fn cleanup(&mut self, now: Instant) {
		self.pending.cleanup(now);
	}
}

/// Filter packet that have already be seen filter.
/// Warning, this is a weak security, and does not avoid
/// spaming the network. Just allow avoiding decoding payload
/// or replying to existing payload.
/// TODO lru the filters over a ttl which should be similar to key rotation.
/// TODO also lru over a max number of elements.
/// TODO eventually bloom filter and disk backend.
pub struct ReplayFilter {
	seen: MixnetCollection<ReplayTag, ()>,
}

impl ReplayFilter {
	pub fn new(config: &Config) -> Self {
		ReplayFilter { seen: MixnetCollection::new(config.replay_ttl_ms) }
	}

	pub fn insert(&mut self, tag: ReplayTag, now: Instant) {
		self.seen.insert(tag, (), now);
	}

	pub fn contains(&mut self, tag: &ReplayTag) -> bool {
		self.seen.contains(tag)
	}

	fn cleanup(&mut self, now: Instant) {
		self.seen.cleanup(now);
	}
}

// TODO this could be optimize, but here simple size inefficient implementation
struct MixnetCollection<K, V> {
	messages: HashMap<K, (V, Wrapping<usize>)>,
	expiration: Duration,
	exp_deque: VecDeque<(Instant, Option<K>)>,
	exp_deque_offset: Wrapping<usize>,
}

type Entry<'a, K, V> = std::collections::hash_map::Entry<'a, K, (V, Wrapping<usize>)>;

impl<K, V> MixnetCollection<K, V>
where
	K: Eq + std::hash::Hash + Clone,
{
	pub fn new(expiration_ms: u64) -> Self {
		Self {
			messages: Default::default(),
			expiration: Duration::from_millis(expiration_ms),
			exp_deque: VecDeque::new(),
			exp_deque_offset: Wrapping(0),
		}
	}

	pub fn insert(&mut self, key: K, value: V, now: Instant) {
		let ix = self.next_inserted_entry();
		self.messages.insert(key.clone(), (value, ix));
		self.inserted_entry(key, now)
	}

	pub fn remove(&mut self, key: &K) -> Option<V> {
		if let Some((value, ix)) = self.messages.remove(key) {
			self.removed(ix);
			Some(value)
		} else {
			None
		}
	}

	pub fn contains(&mut self, key: &K) -> bool {
		self.messages.contains_key(key)
	}

	pub fn entry(&mut self, key: K) -> Entry<K, V> {
		self.messages.entry(key)
	}

	pub fn removed_entry(&mut self, e: (V, Wrapping<usize>)) -> V {
		self.removed(e.1);
		e.0
	}

	fn removed(&mut self, ix: Wrapping<usize>) {
		let ix = ix - self.exp_deque_offset;
		self.exp_deque[ix.0].1 = None;
		if ix + Wrapping(1) == Wrapping(self.exp_deque.len()) {
			loop {
				if let Some(last) = self.exp_deque.back() {
					if last.1.is_none() {
						self.exp_deque.pop_back();
						continue
					}
				}
				break
			}
		}
		if ix == Wrapping(0) {
			loop {
				if let Some(first) = self.exp_deque.front() {
					if first.1.is_none() {
						self.exp_deque.pop_front();
						self.exp_deque_offset += Wrapping(1);
						continue
					}
				}
				break
			}
		}
	}

	pub fn next_inserted_entry(&self) -> Wrapping<usize> {
		self.exp_deque_offset + Wrapping(self.exp_deque.len())
	}

	pub fn inserted_entry(&mut self, k: K, now: Instant) {
		let expires = now + self.expiration;
		self.exp_deque.push_back((expires, Some(k)));
	}

	pub fn cleanup(&mut self, now: Instant) -> usize {
		let count = self.messages.len();
		while let Some(first) = self.exp_deque.front() {
			if first.0 > now {
				break
			}
			if let Some(first) = first.1.as_ref() {
				self.messages.remove(first);
			}
			self.exp_deque.pop_front();
			self.exp_deque_offset += Wrapping(1);
		}
		count - self.messages.len()
	}
}

pub(crate) fn cover_message_to(peer_id: &MixPeerId, peer_key: MixPublicKey) -> Option<Packet> {
	let mut rng = rand::thread_rng();
	let message = fragment::Fragment::create_cover_fragment(&mut rng);
	let hops = vec![sphinx::PathHop { id: *peer_id, public_key: peer_key }];
	let (packet, _no_surb) = sphinx::new_packet(&mut rng, hops, message.into_vec(), None).ok()?;
	Some(packet)
}

/// Generate a mixnet key pair.
pub fn generate_new_keys() -> (MixPublicKey, MixSecretKey) {
	let mut secret = [0u8; 32];
	use rand::RngCore;
	rand::thread_rng().fill_bytes(&mut secret);
	let secret_key: MixSecretKey = secret.into();
	let public_key = MixPublicKey::from(&secret_key);
	(public_key, secret_key)
}

/// Stat collected for a window (or more if a window is skipped).
#[derive(Default, Debug)]
pub struct WindowStats {
	pub window: usize,
	pub last_window: usize,
	pub number_connected: usize,
	pub sum_connected: ConnectionStats,
	// Do not include external
	pub number_received_valid: usize,
	pub number_received_invalid: usize,

	pub number_from_external_received_valid: usize,
	pub number_from_external_received_invalid: usize,
}

#[test]
fn test_ttl_map() {
	type Map = MixnetCollection<Vec<u8>, Vec<u8>>;

	let start = Instant::now();
	let mut data = Map::new(1000);
	for i in 0..10 {
		let now = start + Duration::from_millis(i as u64 * 100);
		data.insert(vec![i], vec![i], now);
	}
	for i in 0..10 {
		assert!(data.contains(&vec![i]));
	}
	assert_eq!(data.cleanup(start + Duration::from_millis(1000 + 4 * 100)), 5);
	for i in 0..5 {
		assert!(!data.contains(&vec![i]));
	}
	for i in 5..10 {
		assert!(data.contains(&vec![i]));
	}
	data.remove(&vec![8]);
	assert!(data.contains(&vec![9]));
	assert!(!data.contains(&vec![8]));
	for i in 5..8 {
		assert!(data.contains(&vec![i]));
	}
	assert_eq!(data.exp_deque.len(), 5);
	data.remove(&vec![9]);
	assert_eq!(data.exp_deque.len(), 3);
	assert_eq!(data.cleanup(start + Duration::from_millis(1000 + 9 * 100)), 3);
	for i in 0..10 {
		assert!(!data.contains(&vec![i]));
	}
}
