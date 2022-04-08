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

pub use crate::core::sphinx::{SurbsEncoded, SurbsPersistance};
pub use config::Config;
pub use error::Error;
use futures::FutureExt;
use futures_timer::Delay;
use libp2p_core::{identity::ed25519, PeerId};
use rand::{prelude::IteratorRandom, CryptoRng, Rng};
use rand_distr::Distribution;
pub use sphinx::Error as SphinxError;
use std::{
	cmp::Ordering,
	collections::{BinaryHeap, HashMap, HashSet},
	task::{Context, Poll},
	time::{Duration, Instant},
};
pub use topology::Topology;

use self::{fragment::MessageCollection, sphinx::Unwrapped};

/// Mixnet peer identity.
pub type MixPeerId = PeerId;
/// Mixnet peer DH static public key.
pub type MixPublicKey = sphinx::PublicKey;
/// Mixnet peer DH static secret key.
pub type MixSecretKey = sphinx::StaticSecret;

/// Length of `MixPublicKey`
pub const PUBLIC_KEY_LEN: usize = 32;

const MAX_QUEUED_PACKETS: usize = 8192;
const PACKET_SIZE: usize = sphinx::OVERHEAD_SIZE + fragment::FRAGMENT_PACKET_SIZE;

type SphinxPeerId = [u8; 32];

pub enum MixEvent {
	SendMessage((MixPeerId, Vec<u8>)),
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
struct QueuedPacket {
	deadline: Instant,
	recipient: MixPeerId,
	data: Vec<u8>,
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
	topology: Option<Box<dyn Topology>>,
	num_hops: usize,
	secret: MixSecretKey,
	local_id: MixPeerId,
	connected_peers: HashMap<MixPeerId, MixPublicKey>,
	// Incomplete incoming message fragments.
	fragments: fragment::MessageCollection,
	// Message waiting for surbs.
	surbs: SurbsCollection,
	// Received message filter.
	replay_filter: ReplayFilter,
	// Real messages queue, sorted by deadline.
	packet_queue: BinaryHeap<QueuedPacket>,
	// Timer for the next poll for messages.
	next_message: Delay,
	// Average delay at which we poll for real or cover messages.
	average_traffic_delay: Duration,
	// Average delay for each packet at each hop.
	average_hop_delay: Duration,
}

impl Mixnet {
	/// Create a new instance with given config.
	pub fn new(config: Config) -> Self {
		Mixnet {
			topology: config.topology,
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
			surbs: SurbsCollection::new(),
			replay_filter: ReplayFilter::new(),
		}
	}

	fn queue_packet(
		&mut self,
		recipient: MixPeerId,
		data: Vec<u8>,
		delay: Duration,
	) -> Result<(), Error> {
		if self.packet_queue.len() >= MAX_QUEUED_PACKETS {
			return Err(Error::QueueFull)
		}
		let deadline = Instant::now() + delay;
		self.packet_queue.push(QueuedPacket { deadline, data, recipient });
		Ok(())
	}

	/// Send a new message to the network. Message is split int multiple fragments and each fragment
	/// is sent over and individual path to the recipient. If no recipient is specified, a random
	/// recipient is selected.
	pub fn register_message(
		&mut self,
		peer_id: Option<MixPeerId>,
		message: Vec<u8>,
		with_surbs: bool,
	) -> Result<(), Error> {
		let mut rng = rand::thread_rng();

		let maybe_peer_id = if let Some(id) = peer_id {
			Some(id)
		} else {
			if let Some(t) = self.topology.as_ref() {
				t.random_recipient()
			} else {
				// Select a random connected peer
				self.connected_peers.keys().choose(&mut rng).cloned()
			}
		};

		let peer_id =
			if let Some(id) = maybe_peer_id { id } else { return Err(Error::NoPath(None)) };

		let chunks = fragment::create_fragments(&mut rng, message, with_surbs)?;
		let paths = self.random_paths(&peer_id, chunks.len(), false)?;

		let mut surbs = if with_surbs {
			//let ours = (MixPeerId, MixPublicKey);
			let paths = self.random_paths(&peer_id, 1, true)?.remove(0);
			let first_node = to_sphinx_id(&paths[0].0).unwrap();
			let paths: Vec<_> = paths
				.into_iter()
				.map(|(id, key)| sphinx::PathHop {
					id: to_sphinx_id(&id).unwrap(),
					public_key: key.into(),
					delay: Some(exp_delay(&mut rng, self.average_hop_delay).as_millis() as u32),
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
					delay: Some(exp_delay(&mut rng, self.average_hop_delay).as_millis() as u32),
				})
				.collect();
			let chunk_surbs = if n == 0 { surbs.take() } else { None };
			let (packet, surbs_keys) = sphinx::new_packet(&mut rng, hops, chunk, chunk_surbs)
				.map_err(|e| Error::SphinxError(e))?;
			debug_assert!(packet.len() == PACKET_SIZE);
			if let Some((keys, surbs_id)) = surbs_keys {
				let persistance = SurbsPersistance { keys };
				self.surbs.insert(surbs_id, persistance);
			}
			packets.push((first_id, packet));
		}

		for (peer_id, packet) in packets {
			let delay = exp_delay(&mut rng, self.average_hop_delay);
			self.queue_packet(peer_id, packet, delay)?;
		}
		Ok(())
	}

	/// Send a new surbs message to the network.
	/// Message cannot be bigger than a single fragment.
	pub fn register_surbs(&mut self, message: Vec<u8>, surbs: SurbsEncoded) -> Result<(), Error> {
		let SurbsEncoded { first_node, first_key, header } = surbs;
		let mut rng = rand::thread_rng(); // TODO get a handle to rng in self.

		let mut chunks = fragment::create_fragments(&mut rng, message, false)?;
		if chunks.len() != 1 {
			return Err(Error::BadSurbsLength)
		}

		let packet = sphinx::new_surbs_packet(first_key, chunks.remove(0), header)
			.map_err(|e| Error::SphinxError(e))?;
		let delay = exp_delay(&mut rng, self.average_hop_delay);
		let dest = to_libp2p_id(first_node)?;
		self.queue_packet(dest, packet, delay)?;
		Ok(())
	}

	/// Handle new packet coming from the network. Removes one layer of Sphinx encryption and either
	/// adds the result to the queue for forwarding, or accepts the fragment addressed to us. If the
	/// fragment completes the message, full message is returned.
	pub fn import_message(
		&mut self,
		peer_id: MixPeerId,
		message: Vec<u8>,
	) -> Result<Option<(Vec<u8>, Option<SurbsEncoded>)>, Error> {
		if message.len() != PACKET_SIZE {
			return Err(Error::BadFragment)
		}

		let next_delay = || exp_delay(&mut rand::thread_rng(), self.average_hop_delay).as_millis() as u32;
		let result = sphinx::unwrap_packet(&self.secret, message, &mut self.surbs, &mut self.replay_filter, next_delay);
		match result {
			Err(e) => {
				log::debug!(target: "mixnet", "Error unpacking message received from {} :{:?}", peer_id, e);
				return Ok(None)
			},
			Ok(Unwrapped::Payload(payload)) => {
				if let Some(m) = self.fragments.insert_fragment(payload, None)? {
					log::debug!(target: "mixnet", "Imported message from {} ({} bytes)", peer_id, m.0.len());
					return Ok(Some(m))
				} else {
					log::trace!(target: "mixnet", "Inserted fragment message from {}", peer_id);
				}
			},
			Ok(Unwrapped::SurbsReply(payload)) => {
				if let Some(m) = self.fragments.insert_fragment(payload, None)? {
					log::debug!(target: "mixnet", "Imported surbs from {} ({} bytes)", peer_id, m.0.len());
					return Ok(Some(m))
				} else {
					log::error!(target: "mixnet", "Surbs fragment from {}", peer_id);
				}
			},
			Ok(Unwrapped::SurbsQuery(encoded_surbs, payload)) => {
				debug_assert!(encoded_surbs.len() == crate::core::sphinx::SURBS_REPLY_SIZE);
				if let Some(m) =
					self.fragments.insert_fragment(payload, Some(encoded_surbs.into()))?
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

	/// Should be called when a new peer is connected.
	pub fn add_connected_peer(&mut self, id: MixPeerId, public_key: MixPublicKey) {
		self.connected_peers.insert(id, public_key);
	}

	/// Should be called when a peer is disconnected.
	pub fn remove_connected_peer(&mut self, id: &MixPeerId) {
		self.connected_peers.remove(id);
	}

	fn cover_message(&mut self) -> Option<(MixPeerId, Vec<u8>)> {
		let mut rng = rand::thread_rng();
		let message = fragment::create_cover_fragment(&mut rng);
		let (id, key) = self.random_cover_path()?;

		let hop =
			sphinx::PathHop { id: to_sphinx_id(&id).unwrap(), public_key: key.into(), delay: None };
		let (packet, _no_surbs) = sphinx::new_packet(&mut rng, vec![hop], message, None).ok()?;
		Some((id, packet))
	}

	fn random_paths(
		&self,
		recipient: &MixPeerId,
		count: usize,
		surbs: bool,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
		// Generate all possible paths and select one at random
		let mut partial = Vec::new();
		let mut paths = Vec::new();
		let (start, recipient) =
			if surbs { (recipient, &self.local_id) } else { (&self.local_id, recipient) };

		if self.topology.is_none() {
			// No topology is defined. Check if direct connection is possible.
			match self.connected_peers.get(&recipient) {
				Some(key) if count == 1 => return Ok(vec![vec![(*recipient, key.clone())]]),
				_ => return Err(Error::NoPath(Some(*recipient))),
			}
		}

		self.gen_paths(&mut partial, &mut paths, start, recipient);

		if paths.is_empty() {
			return Err(Error::NoPath(Some(*recipient)))
		}

		let mut rng = rand::thread_rng();
		let mut result = Vec::new();
		while result.len() < count {
			// TODO this path pool looks fishy: should persist or it is very costy for nothing
			let n: usize = rng.gen_range(0..paths.len());
			result.push(paths[n].clone());
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

	fn gen_paths(
		&self,
		partial: &mut Vec<(MixPeerId, MixPublicKey)>,
		paths: &mut Vec<Vec<(MixPeerId, MixPublicKey)>>,
		last: &MixPeerId,
		target: &MixPeerId,
	) {
		let neighbors = self.topology.as_ref().map(|t| t.neighbors(&last)).unwrap_or_default();
		for (id, key) in neighbors {
			if partial.len() < self.num_hops - 1 {
				partial.push((id.clone(), key));
				self.gen_paths(partial, paths, &id, target);
				partial.pop();
			}

			if partial.len() == self.num_hops - 1 {
				// About to complete path. Only select paths that end up at target.
				if &id != target {
					continue
				}
				partial.push((id, key));
				paths.push(partial.clone());
				partial.pop();
			}
		}
	}

	fn cleanup(&mut self) {
		let now = Instant::now();
		self.fragments.cleanup(now);
		self.surbs.cleanup(now);
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
			self.cleanup();
			let mut rng = rand::thread_rng();
			let next_delay = exp_delay(&mut rng, self.average_traffic_delay);
			self.next_message.reset(next_delay);
			let now = Instant::now();
			let deadline = self.packet_queue.peek().map_or(false, |p| p.deadline <= now);
			if deadline {
				if let Some(packet) = self.packet_queue.pop() {
					log::trace!(target: "mixnet", "Outbound message for {:?}", packet.recipient);
					return Poll::Ready(MixEvent::SendMessage((packet.recipient, packet.data)))
				}
			}
			// No packet to produce, generate cover traffic
			if let Some((recipient, data)) = self.cover_message() {
				log::trace!(target: "mixnet", "Cover message for {:?}", recipient);
				return Poll::Ready(MixEvent::SendMessage((recipient, data)))
			}
		}
		Poll::Pending
	}
}

/// Message id, use as surbs key and replay protection.
/// This is the result of hashing the secret.
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct ReplayTag([u8; crate::core::sphinx::HASH_OUTPUT_SIZE]);

pub struct SurbsCollection {
	// TODO LRU this so we clean up old persistance.
	// TODO define collection in sphinx module? (rem lot of pub)
	pending: HashMap<ReplayTag, SurbsPersistance>,
}

impl SurbsCollection {
	pub fn new() -> Self {
		SurbsCollection { pending: HashMap::new() }
	}

	pub fn insert(&mut self, surb_id: ReplayTag, surb: SurbsPersistance) {
		self.pending.insert(surb_id, surb);
	}

	fn cleanup(&mut self, now: Instant) {
		// TODO implement
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
	seen: HashSet<ReplayTag>,
}

impl ReplayFilter {
	pub fn new() -> Self {
		ReplayFilter { seen: HashSet::new() }
	}

	pub fn insert(&mut self, tag: ReplayTag) {
		self.seen.insert(tag);
	}

	pub fn contains(&mut self, tag: &ReplayTag) -> bool {
		self.seen.contains(tag)
	}

	fn cleanup(&mut self, now: Instant) {
		// TODO implement
	}
}
