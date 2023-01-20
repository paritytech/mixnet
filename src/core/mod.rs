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
mod error;
mod fragment;
mod sphinx;
mod topology;

pub use crate::core::{config::Config, sphinx::SurbPayload};
use crate::{
	core::{
		fragment::MessageCollection,
		sphinx::{SentSurbInfo, SprpKey},
	},
	MessageType, MixPeerId, NetworkPeerId, SendOptions,
};
pub use error::Error;
use futures::FutureExt;
use futures_timer::Delay;
use rand::{CryptoRng, Rng};
use rand_distr::Distribution;
pub use sphinx::Error as SphinxError;
use sphinx::Unwrapped;
use std::{
	cmp::Ordering,
	collections::{BinaryHeap, HashMap, VecDeque},
	num::Wrapping,
	task::{Context, Poll},
	time::{Duration, Instant},
	sync::Arc,
};

pub use topology::SessionTopology;

pub type Surb = Box<SurbPayload>;

/// Mixnet peer network address.
pub type MixPeerAddress = libp2p_core::Multiaddr;
/// Mixnet peer DH static public key.
pub type MixPublicKey = sphinx::PublicKey;
/// Mixnet peer DH static secret key.
pub type MixSecretKey = sphinx::StaticSecret;

/// Length of `MixPublicKey`
pub const PUBLIC_KEY_LEN: usize = 32;

const MAX_QUEUED_PACKETS: usize = 8192;
/// Size of a mixnet packet.
pub const PACKET_SIZE: usize = sphinx::OVERHEAD_SIZE + fragment::FRAGMENT_PACKET_SIZE;

/// Associated information to a packet or header.
pub struct HeaderInfo {
	sprp_keys: Vec<SprpKey>,
	surb_id: Option<ReplayTag>,
}

/// Sphinx packet struct, goal of this struct
/// is only to ensure the packet size is right.
#[derive(PartialEq, Eq, Debug)]
pub struct Packet(pub Vec<u8>);

impl Packet {
	fn new(header: &[u8], payload: &[u8]) -> Self {
		let mut packet = Vec::with_capacity(PACKET_SIZE);
		debug_assert!(header.len() == sphinx::HEADER_SIZE);
		packet.extend_from_slice(header);
		packet.extend_from_slice(payload);
		Self::from_vec(packet)
	}

	pub fn from_vec(data: Vec<u8>) -> Self {
		debug_assert!(data.len() == PACKET_SIZE);
		Packet(data)
	}

	fn into_vec(self) -> Vec<u8> {
		self.0
	}

	fn as_mut(&mut self) -> &mut [u8] {
		self.0.as_mut()
	}
}

pub type SessionIndex = u32;

// TODO: public key store mod
pub struct PublicKeyStore;

pub enum MixEvent {
	SendMessage((MixPeerId, Vec<u8>)),
}

pub fn to_mix_peer_id(id: &NetworkPeerId) -> Result<MixPeerId, Error> {
	let hash = id.as_ref();
	match libp2p_core::multihash::Code::try_from(hash.code()) {
		Ok(libp2p_core::multihash::Code::Identity) => {
			let decoded = libp2p_core::identity::PublicKey::from_protobuf_encoding(hash.digest())
				.map_err(|_e| Error::InvalidId(*id))?;
			let public = match decoded {
				libp2p_core::identity::PublicKey::Ed25519(key) => key.encode(),
			};
			Ok(public)
		},
		_ => Err(Error::InvalidId(*id)),
	}
}

pub fn to_network_peer_id(id: MixPeerId) -> Result<NetworkPeerId, Error> {
	let encoded = libp2p_core::identity::ed25519::PublicKey::decode(&id)
		.map_err(|_e| Error::InvalidSphinxId(id.clone()))?;
	let key = libp2p_core::identity::PublicKey::Ed25519(encoded);
	Ok(NetworkPeerId::from_public_key(&key))
}

fn exp_delay<R: Rng + CryptoRng + ?Sized>(rng: &mut R, target: Duration) -> Duration {
	let exp = rand_distr::Exp::new(1.0 / target.as_nanos() as f64).unwrap();
	let delay = Duration::from_nanos(exp.sample(rng).round() as u64);
	log::trace!(target: "mixnet", "delay {:?} for {:?}", delay, target);
	delay
}

/// Construct a Montgomery curve25519 private key from an Ed25519 secret key.
pub fn secret_from_ed25519(seed: &[u8]) -> MixSecretKey {
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
pub fn public_from_ed25519(ed25519_pk: &libp2p_core::identity::ed25519::PublicKey) -> MixPublicKey {
	curve25519_dalek::edwards::CompressedEdwardsY(ed25519_pk.encode())
		.decompress()
		.expect("An Ed25519 public key is a valid point by construction.")
		.to_montgomery()
		.to_bytes()
		.into()
}

#[derive(PartialEq, Eq)]
/// A real traffic message that we need to forward.
struct QueuedPacket {
	deadline: Instant,
	pub data: Packet,
	recipient: MixPeerId,
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
pub struct Mixnet {
	topology: SessionTopology,
	num_hops: usize,
	secret: MixSecretKey,
	local_id: MixPeerId,
	connected_peers: HashMap<MixPeerId, MixPublicKey>,
	// Incomplete incoming message fragments.
	fragments: MessageCollection,
	// Real messages queue, sorted by deadline.
	packet_queue: BinaryHeap<QueuedPacket>,
	// Message waiting for surb.
	pending_surbs: SurbsCollection,
	// Received message filter.
	replay_filter: ReplayFilter,
	// Timer for the next poll for messages.
	next_message: Delay,
	// Average delay at which we poll for real or cover messages.
	average_traffic_delay: Duration,
	// Average delay for each packet at each hop.
	average_hop_delay: Duration,
}

/// Message id, use as surb key and replay protection.
/// This is the result of hashing the secret.
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct ReplayTag(pub [u8; crate::core::sphinx::HASH_OUTPUT_SIZE]);

pub struct SurbsCollection {
	pending: TimedHashMap<ReplayTag, SentSurbInfo>,
}

impl SurbsCollection {
	pub fn new(config: &Config) -> Self {
		SurbsCollection { pending: TimedHashMap::new(config.surb_ttl_ms) }
	}

	pub fn insert(&mut self, surb_id: ReplayTag, surb: SentSurbInfo, now: Instant) {
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
	seen: TimedHashMap<ReplayTag, ()>,
}

impl ReplayFilter {
	pub fn new(config: &Config) -> Self {
		ReplayFilter { seen: TimedHashMap::new(config.replay_ttl_ms) }
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
struct TimedHashMap<K, V> {
	messages: HashMap<K, (V, Wrapping<usize>)>,
	expiration: Duration,
	exp_deque: VecDeque<(Instant, Option<K>)>,
	exp_deque_offset: Wrapping<usize>,
}

type Entry<'a, K, V> = std::collections::hash_map::Entry<'a, K, (V, Wrapping<usize>)>;

impl<K, V> TimedHashMap<K, V>
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

pub fn generate_new_keys() -> (MixPublicKey, MixSecretKey) {
	let mut secret = [0u8; 32];
	use rand::RngCore;
	rand::thread_rng().fill_bytes(&mut secret);
	let secret_key: MixSecretKey = secret.into();
	let public_key = MixPublicKey::from(&secret_key);
	(public_key, secret_key)
}

impl Mixnet {
	/// Create a new instance with given config.
	pub fn new(config: Config, _keystore: Arc<PublicKeyStore>) -> Self {
		Mixnet {
			pending_surbs: SurbsCollection::new(&config),
			replay_filter: ReplayFilter::new(&config),
			topology: Default::default(),
			num_hops: config.num_hops as usize,
			secret: config.secret_key,
			local_id: config.local_id,
			connected_peers: Default::default(),
			fragments: MessageCollection::new(),
			packet_queue: Default::default(),
			next_message: Delay::new(Duration::from_millis(0)),
			average_hop_delay: Duration::from_millis(config.average_message_delay_ms as u64),
			average_traffic_delay: Duration::from_nanos(
				(PACKET_SIZE * 8) as u64 * 1_000_000_000 / config.target_bits_per_second as u64,
			),
		}
	}

	pub fn gateways(&self) -> Vec<MixPeerAddress> {
		let mut rng = rand::thread_rng();
		self.topology.gateways(&mut rng)
	}

	pub fn set_session_topolgy(&mut self, _index: SessionIndex, topology: SessionTopology) {
		self.topology = topology;
	}

	pub fn start_session(&mut self, _index: SessionIndex) {
		unimplemented!()
	}

	fn queue_packet(
		&mut self,
		recipient: MixPeerId,
		data: Vec<u8>, // TODO switch to Packet or Message (TODO merge both)
		delay: Duration,
	) -> Result<(), Error> {
		if self.packet_queue.len() >= MAX_QUEUED_PACKETS {
			return Err(Error::QueueFull)
		}
		let deadline = Instant::now() + delay;
		self.packet_queue
			.push(QueuedPacket { deadline, data: Packet::from_vec(data), recipient }); // TODO use right error
		Ok(())
	}

	/// Send a new message to the network. Message is split int multiple fragments and each fragment
	/// is sent over and individual path to the recipient. If no recipient is specified, a random
	/// recipient is selected.
	pub fn register_message(
		&mut self,
		peer_id: Option<MixPeerId>,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> Result<(), Error> {
		let mut rng = rand::thread_rng();

		let maybe_peer_id = if let Some(id) = peer_id {
			Some(id)
		} else {
			self.topology.random_recipient(&mut rng)
		};

		let peer_id =
			if let Some(id) = maybe_peer_id { id } else { return Err(Error::NoPath(None)) };

		let chunks = fragment::create_fragments(&mut rng, message, send_options.with_surb)?;
		let paths = self.random_paths(
			&self.local_id.clone(),
			&peer_id,
			&send_options.num_hop,
			chunks.len(),
		)?;

		let mut surb = if send_options.with_surb {
			let Some(peer_id) =
				paths.last().and_then(|path| path.last()).map(|peer_id| &peer_id.0) else {
					return Err(Error::NoPath(None))
				};
			let paths = self
				.random_paths(peer_id, &self.local_id.clone(), &send_options.num_hop, 1)?
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

		let mut packets = Vec::with_capacity(chunks.len());
		for (n, chunk) in chunks.into_iter().enumerate() {
			let (first_id, _) = paths[n].first().unwrap().clone();
			let hops: Vec<_> = paths[n]
				.iter()
				.map(|(id, key)| sphinx::PathHop { id: *id, public_key: (*key).into() })
				.collect();
			let chunk_surb = if n == 0 { surb.take() } else { None };
			let (packet, surb_keys) =
				sphinx::new_packet(&mut rng, hops, chunk.into_vec(), chunk_surb)
					.map_err(|e| Error::SphinxError(e))?;
			if let Some(HeaderInfo { sprp_keys: keys, surb_id: Some(surb_id) }) = surb_keys {
				let persistance = SentSurbInfo { keys, recipient: *paths[n].last().unwrap() };
				self.pending_surbs
					.insert(surb_id, persistance.into(), std::time::Instant::now());
			}

			packets.push((first_id, packet));
		}

		for (peer_id, packet) in packets {
			let delay = exp_delay(&mut rng, self.average_hop_delay);
			self.queue_packet(peer_id, packet.into_vec(), delay)?;
		}
		Ok(())
	}

	pub fn register_surb_reply(
		&mut self,
		message: Vec<u8>,
		surb: Surb,
	) -> Result<(), Error> {
		let SurbPayload { first_node, first_key, header } = *surb;
		let mut rng = rand::thread_rng();

		let mut chunks = fragment::create_fragments(&mut rng, message, false)?;
		if chunks.len() != 1 {
			return Err(Error::MessageTooLarge) // TODO change error
		}

		let packet = sphinx::new_surb_packet(first_key, chunks.remove(0).into_vec(), header)
			.map_err(Error::SphinxError)?;
		let dest = first_node;
		// TODO no delay?
		let delay = exp_delay(&mut rng, self.average_hop_delay);
		self.queue_packet(dest, packet.into_vec(), delay)?;
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
			&mut self.pending_surbs,
			&mut self.replay_filter,
			next_delay,
		);
		match result {
			Err(e) => {
				log::debug!(target: "mixnet", "Error unpacking message received from {:?}: {:?}", peer_id, e);
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
			Ok(Unwrapped::Forward((next_id, delay, packet))) => {
				// See if we can forward the message
				log::debug!(target: "mixnet", "Forward message from {:?} to {:?}", peer_id, next_id);
				self.queue_packet(next_id, packet.into_vec(), Duration::from_nanos(delay as u64))?;
			},
			Ok(Unwrapped::SurbReply(payload, recipient)) => {
				if let Some(m) =
					self.fragments.insert_fragment(payload, MessageType::FromSurb(recipient))?
				{
					log::debug!(target: "mixnet", "Imported surb from {:?} ({} bytes)", peer_id, m.0.len());
					return Ok(Some(m))
				} else {
					log::error!(target: "mixnet", "Surb fragment from {:?}", peer_id);
				}
			},
			Ok(Unwrapped::PayloadWithSurb(encoded_surb, payload)) => {
				debug_assert!(encoded_surb.len() == crate::core::sphinx::SURB_REPLY_SIZE);
				if let Some(m) = self.fragments.insert_fragment(
					payload,
					MessageType::WithSurb(Box::new(encoded_surb.into())),
				)? {
					log::debug!(target: "mixnet", "Imported message from {:?} ({} bytes)", peer_id, m.0.len());
					return Ok(Some(m))
				} else {
					log::warn!(target: "mixnet", "Inserted fragment message from {:?}, stored surb envelope.", peer_id);
				}
			},
		}
		Ok(None)
	}

	/// Should be called when a new peer is connected.
	pub fn add_connected_peer(&mut self, id: MixPeerId, public_key: MixPublicKey) {
		self.connected_peers.insert(id, public_key);
	}

	/// Should be called when a peer is disconnected.
	pub fn remove_connected_peer(&mut self, id: &MixPeerId) {
		self.connected_peers.remove(id);
	}

	fn cover_message(&mut self) -> Option<(MixPeerId, Packet)> {
		let mut rng = rand::thread_rng();
		let message = fragment::Fragment::create_cover_fragment(&mut rng);
		let (id, key) = self.random_cover_path()?;

		let hop = sphinx::PathHop { id, public_key: key.into() };
		let (packet, _no_surb) =
			sphinx::new_packet(&mut rng, vec![hop], message.into_vec(), None).ok()?;
		Some((id, packet))
	}

	fn random_paths(
		&self,
		start: &MixPeerId,
		recipient: &MixPeerId,
		num_hops: &Option<usize>,
		count: usize,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
		let mut rng = rand::thread_rng();
		let mut result = Vec::new();
		for _ in 0 .. count {
			match self.topology.random_path_to(&mut rng, &start, recipient, num_hops.unwrap_or(self.num_hops)) {
				Some(path) => result.push(path),
				None => return Err(Error::NoPath(Some(recipient.clone()))),
			}
		}
		Ok(result)
	}

	fn random_cover_path(&self) -> Option<(MixPeerId, MixPublicKey)> {
		// Select a random connected peer
		let neighbors = self.neighbors();

		if neighbors.is_empty() {
			return None
		}

		let mut rng = rand::thread_rng();
		let n: usize = rng.gen_range(0..neighbors.len());
		Some(neighbors[n].clone())
	}

	fn cleanup(&mut self, now: Instant) {
		self.fragments.cleanup(now);
		self.pending_surbs.cleanup(now);
		self.replay_filter.cleanup(now);
	}

	fn neighbors(&self) -> Vec<(MixPeerId, MixPublicKey)> {
		self.connected_peers
			.iter()
			.map(|(id, key)| (id.clone(), key.clone()))
			.collect::<Vec<_>>()
	}

	// Poll for new messages to send over the wire.
	pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<MixEvent> {
		if Poll::Ready(()) == self.next_message.poll_unpin(cx) {
			cx.waker().wake_by_ref();
			let now = Instant::now();
			self.cleanup(now);
			let mut rng = rand::thread_rng();
			let next_delay = exp_delay(&mut rng, self.average_traffic_delay);
			self.next_message.reset(next_delay);
			let deadline = self.packet_queue.peek().map_or(false, |p| p.deadline <= now);
			if deadline {
				if let Some(packet) = self.packet_queue.pop() {
					log::trace!(target: "mixnet", "Outbound message for {:?}", packet.recipient);
					return Poll::Ready(MixEvent::SendMessage((
						packet.recipient,
						packet.data.into_vec(),
					)))
				}
			}
			// No packet to produce, generate cover traffic
			if let Some((recipient, data)) = self.cover_message() {
				log::trace!(target: "mixnet", "Cover message for {:?}", recipient);
				return Poll::Ready(MixEvent::SendMessage((recipient, data.into_vec())))
			}
		}
		Poll::Pending
	}
}
