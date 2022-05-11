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
mod topology;

use self::{fragment::MessageCollection, sphinx::Unwrapped};
pub use crate::core::sphinx::{SurbsPayload, SurbsPersistance};
use crate::{
	core::connection::{ConnectionEvent, ManagedConnection},
	MessageType, MixPeerId, SendOptions, WorkerOut, WorkerSink2,
};
pub use config::Config;
pub use connection::Connection;
pub use error::Error;
use futures::{channel::oneshot::Sender as OneShotSender, FutureExt, SinkExt};
use futures_timer::Delay;
use libp2p_core::{identity::ed25519, PeerId};
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
pub use topology::{NoTopology, Topology};

/// Mixnet peer DH static public key.
pub type MixPublicKey = sphinx::PublicKey;
/// Mixnet peer DH static secret key.
pub type MixSecretKey = sphinx::StaticSecret;

/// Length of `MixPublicKey`
pub const PUBLIC_KEY_LEN: usize = 32;

/// Size of a mixnet packent.
pub const PACKET_SIZE: usize = sphinx::OVERHEAD_SIZE + fragment::FRAGMENT_PACKET_SIZE;

// TODO should be in conf (having too big window with a big bandwidth
// can stuck node, small window will make evident issue faster).
// TODO adapt packet per window from this.
pub const WINDOW_DELAY: Duration = Duration::from_secs(2);

// TODO in config
pub const WINDOW_MARGIN_PERCENT: usize = 10;

/// Sphinx packet struct ensuring fix len of inner array.
#[derive(PartialEq, Eq, Debug)]
pub struct Packet(Vec<u8>);

impl Packet {
	fn new(header: &[u8], payload: &[u8]) -> Result<Self, SphinxError> {
		let mut packet = Vec::with_capacity(PACKET_SIZE);
		if header.len() != sphinx::HEADER_SIZE {
			return Err(SphinxError::InvalidPacket)
		}
		packet.extend_from_slice(&header[..]);
		packet.extend_from_slice(&payload[..]);
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

type SphinxPeerId = [u8; 32];

pub enum MixEvent {
	Disconnected(Vec<MixPeerId>),
	None,
}

fn to_sphinx_id(id: &MixPeerId) -> Result<SphinxPeerId, Error> {
	let hash = id.as_ref();
	match libp2p_core::multihash::Code::try_from(hash.code()) {
		Ok(libp2p_core::multihash::Code::Identity) => {
			let decoded = libp2p_core::identity::PublicKey::from_protobuf_encoding(hash.digest())
				.map_err(|_e| Error::InvalidId(id.clone()))?;
			let public = match decoded {
				libp2p_core::identity::PublicKey::Ed25519(key) => key.encode(),
				_ => return Err(Error::InvalidId(id.clone())),
			};
			Ok(public)
		},
		_ => Err(Error::InvalidId(id.clone())),
	}
}

fn to_libp2p_id(id: SphinxPeerId) -> Result<PeerId, Error> {
	let encoded = libp2p_core::identity::ed25519::PublicKey::decode(&id)
		.map_err(|_e| Error::InvalidSphinxId(id.clone()))?;
	let key = libp2p_core::identity::PublicKey::Ed25519(encoded);
	Ok(MixPeerId::from_public_key(&key))
}

fn exp_delay<R: Rng + CryptoRng + ?Sized>(rng: &mut R, target: Duration) -> Duration {
	let exp = rand_distr::Exp::new(1.0 / target.as_nanos() as f64).unwrap();
	Duration::from_nanos(exp.sample(rng).round() as u64)
}

/// Construct a Montgomery curve25519 private key from an Ed25519 secret key.
pub fn secret_from_ed25519(ed25519_sk: &ed25519::SecretKey) -> MixSecretKey {
	// An Ed25519 public key is derived off the left half of the SHA512 of the
	// secret scalar, hence a matching conversion of the secret key must do
	// the same to yield a Curve25519 keypair with the same public key.
	// let ed25519_sk = ed25519::SecretKey::from(ed);
	let mut curve25519_sk = [0; 32];
	let hash = <sha2::Sha512 as sha2::Digest>::digest(ed25519_sk.as_ref());
	curve25519_sk.copy_from_slice(&hash[..32]);
	curve25519_sk.into()
}

/// Construct a Montgomery curve25519 public key from an Ed25519 public key.
pub fn public_from_ed25519(ed25519_pk: &ed25519::PublicKey) -> MixPublicKey {
	curve25519_dalek::edwards::CompressedEdwardsY(ed25519_pk.encode())
		.decompress()
		.expect("An Ed25519 public key is a valid point by construction.")
		.to_montgomery()
		.to_bytes()
		.into()
}

#[derive(PartialEq, Eq)]
/// A real traffic message that we need to forward.
pub(crate) struct QueuedPacket {
	deadline: Option<Instant>, // TODO could replace by sent in window and window index
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
	connected_peers: HashMap<MixPeerId, ManagedConnection<C>>,
	// Incomplete incoming message fragments.
	fragments: fragment::MessageCollection,
	// Message waiting for surbs.
	surbs: SurbsCollection,
	// Received message filter.
	replay_filter: ReplayFilter,
	// Timer for the next poll for messages.
	next_message: Delay,
	// Average delay at which we poll for real or cover messages.
	average_traffic_delay: Duration,
	// Average delay for each packet at each hop.
	average_hop_delay: Duration,
	// If true keep original message with surbs
	// and return it with surbs reply.
	persist_surbs_query: bool,

	// TODO replace by a rec limit over a window
	// with a given number of received message = to the number
	// of send, just add some leniency so in case late try to query more.
	default_limit_msg: Option<u32>,

	packet_per_window: usize,
	current_window_start: Instant,
	current_window: Wrapping<usize>,
	current_packet_in_window: usize,
	last_now: Instant,

	window_delay: Delay,
}

impl<T: Topology, C: Connection> Mixnet<T, C> {
	/// Create a new instance with given config.
	pub fn new(config: Config, topology: T) -> Self {
		let window_delay = Delay::new(WINDOW_DELAY);
		let packet_duration_nanos =
			(PACKET_SIZE * 8) as u64 * 1_000_000_000 / config.target_bits_per_second as u64;
		let average_traffic_delay = Duration::from_nanos(packet_duration_nanos);
		let packet_per_window = (WINDOW_DELAY.as_nanos() / packet_duration_nanos as u128) as usize;
		debug_assert!(packet_per_window > 0);

		let now = Instant::now();
		Mixnet {
			topology,
			surbs: SurbsCollection::new(&config),
			replay_filter: ReplayFilter::new(&config),
			persist_surbs_query: config.persist_surbs_query,
			num_hops: config.num_hops as usize,
			public: config.public_key,
			secret: config.secret_key,
			local_id: config.local_id,
			fragments: MessageCollection::new(),
			connected_peers: Default::default(),
			next_message: Delay::new(Duration::from_millis(0)),
			average_hop_delay: Duration::from_millis(config.average_message_delay_ms as u64),
			average_traffic_delay,
			default_limit_msg: config.limit_per_window,
			current_window_start: now,
			last_now: now,
			current_window: Wrapping(0),
			current_packet_in_window: 0,
			window_delay,
			packet_per_window,
		}
	}

	pub fn insert_connection(
		&mut self,
		peer: MixPeerId,
		connection: C,
		established: Option<OneShotSender<()>>,
	) {
		let connection = ManagedConnection::new(
			peer.clone(),
			self.default_limit_msg.clone(),
			connection,
			self.current_window,
			established,
		);
		self.connected_peers.insert(peer, connection);
	}

	pub fn connected_mut(&mut self, peer: &MixPeerId) -> Option<&mut C> {
		self.connected_peers.get_mut(peer).map(|c| &mut c.connection)
	}

	pub(crate) fn managed_connection_mut(
		&mut self,
		peer: &MixPeerId,
	) -> Option<&mut ManagedConnection<C>> {
		self.connected_peers.get_mut(peer)
	}

	pub fn local_id(&self) -> &MixPeerId {
		&self.local_id
	}

	fn queue_packet(
		&mut self,
		recipient: MixPeerId,
		data: Packet,
		delay: Duration,
	) -> Result<(), Error> {
		if let Some(connection) = self.connected_peers.get_mut(&recipient) {
			let deadline = Some(self.last_now + delay); // TODO could get now from param
			connection.queue_packet(
				QueuedPacket { deadline, data },
				self.packet_per_window,
				&self.local_id,
				&self.topology,
				false,
			)?;
		} else {
			return Err(Error::Unreachable(data))
			// TODO maybe if in topology, try dial and add to local size restricted heap
			/*		if self.packet_queue.len() >= MAX_QUEUED_PACKETS {
						return Err(Error::QueueFull)
					}
					let deadline = Some(Instant::now() + delay);
					self.packet_queue.push(QueuedPacket { deadline, data, recipient });
			*/
		}
		Ok(())
	}

	// When node are not routing, the packet is not delayed
	// and sent immediatly.
	fn queue_external_packet(&mut self, recipient: MixPeerId, data: Packet) -> Result<(), Error> {
		if let Some(connection) = self.connected_peers.get_mut(&recipient) {
			let deadline = Some(self.last_now); // TODO remove option for deadline (we don't want to skip other packets
			connection.queue_packet(
				QueuedPacket { deadline, data },
				self.packet_per_window,
				&self.local_id,
				&self.topology,
				true,
			)?;
		} else {
			return Err(Error::Unreachable(data))
			// TODO if in topology, try dial and add to local size restricted heap
			/*		if self.packet_queue.len() >= MAX_QUEUED_PACKETS {
						return Err(Error::QueueFull)
					}
					let deadline = Some(Instant::now() + delay);
					self.packet_queue.push(QueuedPacket { deadline, data, recipient });
			*/
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
		} else {
			if let Some((id, key)) = self.topology.random_recipient(&self.local_id) {
				(Some(id), Some(key))
			} else {
				(None, None)
			}
		};

		let peer_id =
			if let Some(id) = maybe_peer_id { id } else { return Err(Error::NoPath(None)) };

		let mut surbs_query =
			(self.persist_surbs_query && send_options.with_surbs).then(|| message.clone());

		let chunks = fragment::create_fragments(&mut rng, message, send_options.with_surbs)?;
		let paths = self.random_paths(
			&peer_id,
			peer_pub_key.as_ref(),
			&send_options.num_hop,
			chunks.len(),
			false,
		)?;

		let mut surbs = if send_options.with_surbs {
			//let ours = (MixPeerId, MixPublicKey);
			let paths = self
				.random_paths(&peer_id, peer_pub_key.as_ref(), &send_options.num_hop, 1, true)?
				.remove(0);
			let first_node = to_sphinx_id(&paths[0].0).unwrap();
			let paths: Vec<_> = paths
				.into_iter()
				.map(|(id, key)| sphinx::PathHop {
					id: to_sphinx_id(&id).unwrap(),
					public_key: key.into(),
				})
				.collect();

			Some((first_node, paths))
		} else {
			None
		};
		let nb_chunks = chunks.len();
		let mut packets = Vec::with_capacity(nb_chunks);
		for (n, chunk) in chunks.into_iter().enumerate() {
			let (first_id, _) = paths[n].first().unwrap().clone();
			let hops: Vec<_> = paths[n]
				.iter()
				.map(|(id, key)| sphinx::PathHop {
					id: to_sphinx_id(id).unwrap(),
					public_key: (*key).into(),
				})
				.collect();
			let chunk_surbs = if n == 0 { surbs.take() } else { None };
			let (packet, surbs_keys) =
				sphinx::new_packet(&mut rng, hops, chunk.into_vec(), chunk_surbs)
					.map_err(|e| Error::SphinxError(e))?;
			if let Some((keys, surbs_id)) = surbs_keys {
				let persistance = SurbsPersistance { keys, query: surbs_query.take() };
				self.surbs.insert(surbs_id, persistance, self.last_now);
			}
			packets.push((first_id, packet));
		}

		if self.topology.is_first_node(&self.local_id) {
			for (peer_id, packet) in packets {
				let delay = exp_delay(&mut rng, self.average_hop_delay);
				self.queue_packet(peer_id, packet, delay)?;
			}
		} else {
			for (peer_id, packet) in packets {
				self.queue_external_packet(peer_id, packet)?;
			}
		}
		Ok(())
	}

	/// Send a new surbs message to the network.
	/// Message cannot be bigger than a single fragment.
	pub fn register_surbs(&mut self, message: Vec<u8>, surbs: SurbsPayload) -> Result<(), Error> {
		let SurbsPayload { first_node, first_key, header } = surbs;
		let mut rng = rand::thread_rng();

		let mut chunks = fragment::create_fragments(&mut rng, message, false)?;
		if chunks.len() != 1 {
			return Err(Error::BadSurbsLength)
		}

		let packet = sphinx::new_surbs_packet(first_key, chunks.remove(0).into_vec(), header)
			.map_err(|e| Error::SphinxError(e))?;
		let dest = to_libp2p_id(first_node)?;
		if self.topology.neighbors(&self.local_id).is_some() {
			// TODO is routing function
			let delay = exp_delay(&mut rng, self.average_hop_delay);
			self.queue_packet(dest, packet, delay)?;
		} else {
			// TODO this would need to attempt dial (or just
			// generate surbs passing by same peer as the one we
			// just received: means surbs reply should be done
			// quickly).
			self.queue_external_packet(dest, packet)?;
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
			&mut self.surbs,
			&mut self.replay_filter,
			next_delay,
		);
		match result {
			Err(e) => {
				log::debug!(target: "mixnet", "Error unpacking message received from {} :{:?}", peer_id, e);
				return Ok(None)
			},
			Ok(Unwrapped::Payload(payload)) => {
				if let Some(m) = self.fragments.insert_fragment(payload, MessageType::StandAlone)? {
					log::debug!(target: "mixnet", "Imported message from {} ({} bytes)", peer_id, m.0.len());
					return Ok(Some(m))
				} else {
					log::trace!(target: "mixnet", "Inserted fragment message from {}", peer_id);
				}
			},
			Ok(Unwrapped::SurbsReply(payload, query)) => {
				if let Some(m) =
					self.fragments.insert_fragment(payload, MessageType::FromSurbs(query))?
				{
					log::debug!(target: "mixnet", "Imported surbs from {} ({} bytes)", peer_id, m.0.len());
					return Ok(Some(m))
				} else {
					log::error!(target: "mixnet", "Surbs fragment from {}", peer_id);
				}
			},
			Ok(Unwrapped::SurbsQuery(encoded_surbs, payload)) => {
				debug_assert!(encoded_surbs.len() == crate::core::sphinx::SURBS_REPLY_SIZE);
				if let Some(m) = self
					.fragments
					.insert_fragment(payload, MessageType::WithSurbs(encoded_surbs.into()))?
				{
					log::debug!(target: "mixnet", "Imported message from {} ({} bytes)", peer_id, m.0.len());
					return Ok(Some(m))
				} else {
					log::warn!(target: "mixnet", "Inserted fragment message from {}, stored surbs enveloppe.", peer_id);
				}
			},
			Ok(Unwrapped::Forward((next_id, delay, packet))) => {
				// See if we can forward the message
				let next_id = to_libp2p_id(next_id)?;
				log::debug!(target: "mixnet", "Forward message from {} to {}", peer_id, next_id);
				self.queue_packet(next_id, packet, Duration::from_nanos(delay as u64))?;
			},
		}
		Ok(None)
	}

	/// Should be called when a peer is disconnected.
	pub fn remove_connected_peer(&mut self, id: &MixPeerId) {
		self.connected_peers.remove(id);
		self.topology.disconnect(id);
	}

	fn random_paths(
		&self,
		recipient: &MixPeerId,
		recipient_key: Option<&MixPublicKey>,
		num_hops: &Option<usize>,
		count: usize,
		surbs: bool,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
		let (start, recipient) = if surbs {
			((recipient, recipient_key), (&self.local_id, Some(&self.public)))
		} else {
			((&self.local_id, Some(&self.public)), (recipient, recipient_key))
		};

		let num_hops = num_hops.clone().unwrap_or(self.num_hops);
		if num_hops > sphinx::MAX_HOPS {
			return Err(Error::TooManyHops)
		}

		log::trace!(target: "mixnet", "Random path, length {:?}", num_hops);
		self.topology.random_path(start, recipient, count, num_hops, sphinx::MAX_HOPS)
	}

	fn cleanup(&mut self, now: Instant) {
		self.fragments.cleanup(now);
		self.surbs.cleanup(now);
		self.replay_filter.cleanup(now);
	}

	// Poll for new messages to send over the wire.
	pub fn poll(&mut self, cx: &mut Context<'_>, results: &mut WorkerSink2) -> Poll<MixEvent> {
		if Poll::Ready(()) == self.next_message.poll_unpin(cx) {
			let now = Instant::now();
			self.last_now = now;
			if let Poll::Ready(_) = self.window_delay.poll_unpin(cx) {
				let duration = now - self.current_window_start;
				let nb_spent = (duration.as_millis() / WINDOW_DELAY.as_millis()) as usize;

				self.current_window += Wrapping(nb_spent);
				for _ in 0..nb_spent {
					self.current_window_start += WINDOW_DELAY;
				}
				self.window_delay.reset(WINDOW_DELAY);
				while !matches!(self.window_delay.poll_unpin(cx), Poll::Pending) {
					self.window_delay.reset(WINDOW_DELAY);
				}
			}

			let duration = now - self.current_window_start;
			self.current_packet_in_window = ((duration.as_millis() as u64 *
				self.packet_per_window as u64) /
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
		// TODO futures unordered
		for (peer_id, connection) in self.connected_peers.iter_mut() {
			// TODO loop on ready
			// and import inside (requires to split connected from other mixnet
			// fields: would remove need for connection event received.
			match connection.poll(
				cx,
				&self.local_id,
				&self.public,
				self.current_window,
				self.current_packet_in_window,
				self.packet_per_window,
				self.last_now,
				&mut self.topology,
			) {
				Poll::Ready(ConnectionEvent::Established(key)) => {
					all_pending = false;
					if let Err(e) =
						results.start_send_unpin(WorkerOut::Connected(peer_id.clone(), key.clone()))
					{
						log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
					}

					self.topology.connected(peer_id.clone(), key);
				},
				Poll::Ready(ConnectionEvent::Received(packet)) => {
					all_pending = false;
					recv_packets.push((peer_id.clone(), packet));
				},
				Poll::Ready(ConnectionEvent::Broken) => {
					// same as pending
					disconnected.push(peer_id.clone());
				},
				Poll::Ready(ConnectionEvent::None) => {
					all_pending = false;
				},
				Poll::Pending => (),
			}
		}

		for (peer, packet) in recv_packets {
			if !self.import_packet(peer, packet, results) {
				// TODO what kind of log: cannot really make anything of error
				// since one can send use dummy packet.
			}
		}

		if disconnected.len() > 0 {
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
			Ok(Some((full_message, surbs))) => {
				if let Err(e) =
					results.start_send_unpin(WorkerOut::ReceivedMessage(peer, full_message, surbs))
				{
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

	pub fn accept_peer(&mut self, peer_id: &MixPeerId) -> bool {
		self.topology.routing_to(&self.local_id, peer_id) ||
			self.topology.routing_to(peer_id, &self.local_id) ||
			self.topology.allow_external(peer_id).is_some()
	}
}

/// Message id, use as surbs key and replay protection.
/// This is the result of hashing the secret.
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct ReplayTag([u8; crate::core::sphinx::HASH_OUTPUT_SIZE]);

pub struct SurbsCollection {
	pending: MixnetCollection<ReplayTag, SurbsPersistance>,
}

impl SurbsCollection {
	pub fn new(config: &Config) -> Self {
		SurbsCollection { pending: MixnetCollection::new(config.surbs_ttl_ms) }
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
		loop {
			if let Some(first) = self.exp_deque.front() {
				if first.0 > now {
					break
				}
				if let Some(first) = first.1.as_ref() {
					self.messages.remove(first);
				}
			} else {
				break
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
	let hops =
		vec![sphinx::PathHop { id: to_sphinx_id(peer_id).unwrap(), public_key: peer_key.into() }];
	let (packet, _no_surbs) = sphinx::new_packet(&mut rng, hops, message.into_vec(), None).ok()?;
	Some(packet)
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
