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
pub use crate::core::{
	fragment::FRAGMENT_PACKET_SIZE,
	sphinx::{hash, SprpKey, SurbsPayload, SurbsPersistance, SurbsPersistances, PAYLOAD_TAG_SIZE},
};
use crate::{
	core::connection::{ConnectionResult, ConnectionStats, ManagedConnection},
	traits::{Configuration, Connection, NewRoutingSet, ShouldConnectTo},
	DecodedMessage, MessageType, MixnetId, NetworkId, SendOptions,
};
pub use config::Config;
pub use error::Error;
use futures::{Future, FutureExt};
use futures_timer::Delay;
use rand::{CryptoRng, Rng};
use rand_distr::Distribution;
pub use sphinx::Error as SphinxError;
use std::{
	cmp::Ordering,
	collections::{HashMap, VecDeque},
	num::Wrapping,
	pin::Pin,
	task::{Context, Poll},
	time::{Duration, Instant},
};

/// Mixnet peer DH static public key.
pub type MixPublicKey = sphinx::PublicKey;
/// Mixnet peer DH static secret key.
pub type MixSecretKey = sphinx::StaticSecret;

/// Length of `MixPublicKey`
pub const PUBLIC_KEY_LEN: usize = 32;

/// Try reconnect, warning is rounded to window size.
/// TODO in conf
pub const TRY_RECONNECT_MS: usize = 5_000;

/// Attempt reconnect every nb attempt to try reconnect.
/// This apply twice less for peer above a given threshold.
pub const TRY_RECONNECT_DYN_NB: usize = 3;

/// Size of a mixnet packet.
pub const PACKET_SIZE: usize = sphinx::OVERHEAD_SIZE + fragment::FRAGMENT_PACKET_SIZE;

pub const WINDOW_MARGIN_PERCENT: usize = 10;

/// Associated information to a packet or header.
pub struct TransmitInfo {
	sprp_keys: Vec<SprpKey>,
	surb_id: Option<ReplayTag>,
}

/// Status of the connection with a given peer.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
enum ConnectedKind {
	// Connection start by a configurable handshake.
	// For external node it can be simply to check
	// we allow external data (or to keep connection
	// for a while until we believe our topology is correct).
	// For node already identified as part of mixnet
	// it can be a way to give info faster (eg key is
	// known from topology but we did not know the connected
	// peer own the key).
	PendingHandshake,
	// We and connected peer are part of mixnet topology,
	// a constant bandwidth from us to the peer is needed.
	RoutingForward,
	// We and connected peer are part of mixnet topology,
	// a constant bandwidth from the peer to us is needed.
	RoutingReceive,
	// We and connected peer are part of mixnet topology,
	// a constant bandwidth from in both direction is needed.
	RoutingReceiveForward,
	// Connected node is external, we just proxy request
	// if we are routing forward and allows it.
	// If we are routing we may want to keep some connection
	// to serve external request.
	// If we are not routing the connection should really not
	// be needed.
	External,
	// Both nodes are routing, but are not connected on topology.
	// Act as External but can be worth maintaining/caching differently.
	ExternalRouting,
	// No connection, keeping information for a later connect.
	Disconnected,
}

impl ConnectedKind {
	// At this point do not accept mixnet protocol message, but only
	// raw sphinx messages.
	fn is_mixnet_routing(self) -> bool {
		matches!(
			self,
			ConnectedKind::RoutingForward |
				ConnectedKind::RoutingReceive |
				ConnectedKind::RoutingReceiveForward
		)
	}

	fn routing_forward(self) -> bool {
		matches!(self, ConnectedKind::RoutingForward | ConnectedKind::RoutingReceiveForward)
	}

	fn routing_receive(self) -> bool {
		matches!(self, ConnectedKind::RoutingReceive | ConnectedKind::RoutingReceiveForward)
	}

	fn is_disconnected(self) -> bool {
		matches!(self, ConnectedKind::Disconnected)
	}

	fn is_external(self) -> bool {
		matches!(self, ConnectedKind::External | ConnectedKind::ExternalRouting)
	}

	fn is_pending_handshake(self) -> bool {
		matches!(self, ConnectedKind::PendingHandshake)
	}
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

pub enum MixnetEvent {
	/// A new peer has connected.
	Connected(NetworkId, MixPublicKey),
	Disconnected(Vec<(NetworkId, Option<MixnetId>, bool)>),
	TryConnect(Vec<(MixnetId, Option<NetworkId>)>),
	/// A message has reached us.
	Message(DecodedMessage),
	/// Shutdown signal.
	Shutdown,
	None,
}

pub fn to_sphinx_id(id: &NetworkId) -> Result<MixnetId, Error> {
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

fn exp_delay<R: Rng + CryptoRng + ?Sized>(rng: &mut R, target: Duration) -> Duration {
	let exp = rand_distr::Exp::new(1.0 / target.as_nanos() as f64).unwrap();
	let delay = Duration::from_nanos(exp.sample(rng).round() as u64);
	log::trace!(target: "mixnet", "delay {:?} for {:?}", delay, target);
	delay
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
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum PacketType {
	// Forward a received packet
	Forward,
	// Forward a packet received from an external peer.
	ForwardExternal,
	// Forward a packet that we did emit
	SendFromSelf,
	// Forward a surb packet
	Surbs,
	// Forward a Cover we did create.
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

impl QueuedPacket {
	pub fn injected_packet(&self) -> bool {
		// Surbs are injected as we did the reply.
		// (surbs received from external users are seen as standard ForwardExternal)
		matches!(self.kind, PacketType::SendFromSelf | PacketType::Surbs)
	}

	pub fn external_packet(&self) -> bool {
		matches!(self.kind, PacketType::ForwardExternal)
	}
}

#[derive(Default)]
struct DisconnectedPeer {
	handshaken: Option<NetworkId>,
	next_reconnect_attempt: usize,
}

/// Mixnet core. Mixes messages, tracks fragments and delays.
pub struct Mixnet<T, C> {
	pub topology: T,
	num_hops: usize,
	local_id: MixnetId,
	public: MixPublicKey,
	secret: MixSecretKey,
	connected_peers: HashMap<NetworkId, ManagedConnection<C>>,
	peer_counts: PeerCount,

	peers_to_network_id: HashMap<MixnetId, NetworkId>,
	// TODO ttl map this and clean connected somehow
	// TODO consider removal
	disconnected_peers: HashMap<MixnetId, DisconnectedPeer>,
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

	window_size: Duration,

	keep_handshaken_disconnected_address: bool,

	forward_unconnected_message_queue: Option<QueuedUnconnectedPackets>,

	pending_events: VecDeque<MixnetEvent>,

	/// try to connect to better peers or unconnected peers every N windows.
	try_reconnect_every: usize,

	/// Countdown to next attempt at finding new connections.
	next_try_reconnect: usize,

	/// If define we use internal reception buffer with limitted lenience.
	/// We receive eagerly and if buffer limit size is exceeded, we close connection.
	/// First window after a connection is always ignored.
	/// TODO do not allow reconnect on close connection.
	receive_buffer: Option<usize>,
}

/// Mixnet window current state.
pub struct WindowInfo {
	packet_per_window: usize,
	graceful_topology_change_period: Option<(Duration, usize)>,

	current_start: Instant,
	current: Wrapping<usize>,
	current_packet_limit: usize,
	last_now: Instant,
	stats: Option<WindowStats>,
}

impl<T: Configuration, C: Connection> Mixnet<T, C> {
	/// Create a new instance with given config.
	pub fn new(config: Config, topology: T) -> Self {
		let mut window_size = Duration::from_millis(config.window_size_ms);
		let packet_duration_nanos =
			PACKET_SIZE as u64 * 1_000_000_000 / config.target_bytes_per_second as u64;
		let average_traffic_delay = Duration::from_nanos(packet_duration_nanos);
		let mut packet_per_window =
			(window_size.as_nanos() / packet_duration_nanos as u128) as usize;
		if packet_per_window == 0 {
			packet_per_window = 1;
			window_size = Duration::from_nanos(packet_duration_nanos);
			// TODO should round to upper millis or 10 / 100 millis
			// TODO apply same rule put to ensure minimum number of packet in window (window of 1
			// packet does not make much sense).
			log::warn!("Mixnet bandwidth too low, forcing it at one packet per window, forcing window size to {:?}", window_size);
		}
		debug_assert!(packet_per_window > 0);

		let now = Instant::now();
		let stats = topology.collect_windows_stats().then(WindowStats::default);
		let graceful_topology_change_period = (config.graceful_topology_change_period_ms != 0)
			.then(|| {
				let nb_packet =
					config.graceful_topology_change_period_ms * 1_000_000 / packet_duration_nanos;
				(
					Duration::from_millis(config.graceful_topology_change_period_ms as u64),
					nb_packet as usize,
				)
			});
		let receive_buffer = config
			.receive_margin_ms
			.map(|size_ms| (size_ms * 1_000_000 / packet_duration_nanos) as usize);
		let forward_unconnected_message_queue = (config.queue_message_unconnected_ms > 0 &&
			config.queue_message_unconnected_number > 0)
			.then(|| {
				QueuedUnconnectedPackets::new(
					config.queue_message_unconnected_ms,
					config.queue_message_unconnected_number,
				)
			});

		let mut try_reconnect_every = TRY_RECONNECT_MS / config.window_size_ms as usize;
		if TRY_RECONNECT_MS % config.window_size_ms as usize > 0 {
			try_reconnect_every += 1;
		}
		let next_try_reconnect = 0; // try connect on first poll.
		Mixnet {
			topology,
			surb: SurbsCollection::new(&config),
			replay_filter: ReplayFilter::new(&config),
			persist_surb_query: config.persist_surb_query,
			num_hops: config.num_hops as usize,
			local_id: config.local_id,
			public: config.public_key,
			secret: config.secret_key,
			fragments: MessageCollection::new(),
			connected_peers: Default::default(),
			peer_counts: Default::default(),
			peers_to_network_id: Default::default(),
			disconnected_peers: Default::default(),
			pending_events: Default::default(),
			forward_unconnected_message_queue,
			keep_handshaken_disconnected_address: config.keep_handshaken_disconnected_address,
			next_message: Delay::new(Duration::from_millis(0)),
			average_hop_delay: Duration::from_millis(config.average_message_delay_ms as u64),
			average_traffic_delay,
			try_reconnect_every,
			next_try_reconnect,
			window_size,
			window: WindowInfo {
				packet_per_window,
				graceful_topology_change_period,

				current_start: now,
				last_now: now,
				current: Wrapping(0),
				current_packet_limit: 0,
				stats,
			},
			receive_buffer,
		}
	}

	pub fn restart(
		&mut self,
		new_id: Option<crate::MixnetId>,
		new_keys: Option<(MixPublicKey, crate::MixSecretKey)>,
	) {
		if let Some(id) = new_id {
			self.local_id = id;
		}
		if let Some((pub_key, priv_key)) = new_keys {
			self.public = pub_key;
			self.secret = priv_key;
		}
		// disconnect all (need a new handshake).
		for (_mix_id, mut connection) in std::mem::take(&mut self.connected_peers).into_iter() {
			self.peer_counts.remove_peer(connection.set_disconnected_kind());
			if let Some(mix_id) = connection.mixnet_id() {
				self.peers_to_network_id.remove(mix_id);
				self.topology.disconnected(mix_id);
			}
		}
		self.topology.peer_stats(&self.peer_counts);
	}

	pub fn insert_connection(
		&mut self,
		waker: futures::task::Waker,
		peer: NetworkId,
		connection: C,
	) {
		if let Some(peer_id) = self.remove_connected_peer(&peer, false) {
			log::warn!(target: "mixnet", "Removing old connection with {:?}, on handshake restart", peer_id);
		}
		let connection = ManagedConnection::new(
			waker,
			self.local_id,
			self.public,
			peer,
			connection,
			self.window.current,
			self.window.stats.is_some(),
			&mut self.peer_counts,
			self.receive_buffer,
		);
		self.connected_peers.insert(peer, connection);
		self.topology.peer_stats(&self.peer_counts);
	}

	pub fn connected_mut(&mut self, peer: &NetworkId) -> Option<&mut C> {
		self.connected_peers.get_mut(peer).map(|c| c.connection_mut())
	}

	pub fn local_id(&self) -> &MixnetId {
		&self.local_id
	}

	pub fn public_key(&self) -> &crate::MixPublicKey {
		&self.public
	}

	fn queue_packet(
		&mut self,
		recipient: MixnetId,
		data: Packet,
		delay: Duration,
		kind: PacketType,
	) -> Result<(), Error> {
		if let Some(connection) = self
			.peers_to_network_id
			.get(&recipient)
			.and_then(|r| self.connected_peers.get_mut(r))
		{
			let deadline = self.window.last_now + delay;
			connection.queue_packet(
				QueuedPacket { deadline, data, kind },
				self.window.packet_per_window,
				&self.topology,
				&self.peer_counts,
			)?;
		} else {
			if let Some(queue) = self.forward_unconnected_message_queue.as_mut() {
				if kind != PacketType::Cover {
					let deadline = self.window.last_now + delay;
					queue.insert(
						recipient,
						QueuedPacket { deadline, data, kind },
						self.window.last_now,
					);
					return Ok(())
				}
			}
			return Err(Error::Unreachable)
		}
		Ok(())
	}

	// When node are not routing, the packet is not delayed
	// and sent immediatly.
	fn queue_external_packet(
		&mut self,
		recipient: MixnetId,
		first_hop: MixnetId,
		data: Packet,
		kind: PacketType,
		with_surb: Option<ReplayTag>,
	) -> Result<(), Error> {
		if let Some(connection) = self
			.peers_to_network_id
			.get(&recipient)
			.and_then(|r| self.connected_peers.get_mut(r))
		{
			let deadline = self.window.last_now;
			// TODO change this just pass data?
			connection.queue_external_packet(
				first_hop,
				with_surb,
				QueuedPacket { deadline, data, kind },
			)?;
		} else {
			return Err(Error::Unreachable)
		}
		Ok(())
	}

	fn queue_external_reply(
		&mut self,
		recipient: MixnetId,
		tag: ReplayTag,
		data: Vec<u8>,
	) -> Result<(), Error> {
		if let Some(connection) = self
			.peers_to_network_id
			.get(&recipient)
			.and_then(|r| self.connected_peers.get_mut(r))
		{
			connection.queue_external_reply(tag, data)?;
		} else {
			return Err(Error::Unreachable)
		}
		Ok(())
	}

	/// Send a new message to the network. Message is split into multiple fragments and each
	/// fragment is sent over an individual path to the recipient. If no recipient is specified, a
	/// random recipient is selected.
	pub fn register_message(
		&mut self,
		peer_id: Option<MixnetId>,
		peer_pub_key: Option<MixPublicKey>,
		message: Vec<u8>,
		send_options: SendOptions,
	) -> Result<(), Error> {
		self.try_apply_topology_change();
		let mut rng = rand::thread_rng();

		let is_external = !self.topology.can_route(&self.local_id);
		let mut surb_query =
			(self.persist_surb_query && send_options.with_surb).then(|| message.clone());

		let chunks = fragment::create_fragments(&mut rng, message, send_options.with_surb)?;
		let (first_external, paths) = self.random_paths(
			peer_id.as_ref(),
			peer_pub_key.as_ref(),
			&send_options.num_hop,
			chunks.len(),
			None,
			is_external,
		)?;

		let mut surb = if send_options.with_surb {
			let peer_id = if peer_id.is_none() {
				// a random dest has ben create in path
				paths.last().and_then(|path| path.last()).map(|peer_id| &peer_id.0)
			} else {
				peer_id.as_ref()
			};
			let paths = self
				.random_paths(
					peer_id,
					peer_pub_key.as_ref(),
					&send_options.num_hop,
					1,
					Some(first_external.as_ref()),
					is_external,
				)?
				.1
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
			let mut surb_tag = None;
			if let Some(TransmitInfo { sprp_keys: keys, surb_id: Some(surb_id) }) = surb_keys {
				let persistance = SurbsPersistance {
					keys,
					query: surb_query.take(),
					recipient: *paths[n].last().unwrap(),
				};
				if first_external.is_some() {
					surb_tag = Some(surb_id.clone());
				}
				self.surb.insert(surb_id, persistance.into(), self.window.last_now);
			}
			if let Some(target) = first_external {
				packets.push((target, packet, Some((first_id, surb_tag))));
			} else {
				packets.push((first_id, packet, None));
			}
		}

		for (peer_id, packet, is_external) in packets {
			if let Some((first_hop, with_surb)) = is_external {
				self.queue_external_packet(
					peer_id,
					first_hop,
					packet,
					PacketType::SendFromSelf,
					with_surb,
				)?;
			} else {
				// TODO delay may not be useful here (since secondary
				// queue used).
				let delay = exp_delay(&mut rng, self.average_hop_delay);
				self.queue_packet(peer_id, packet, delay, PacketType::SendFromSelf)?;
			}
		}
		Ok(())
	}

	/// Change of globably allowed peer to be in routing set.
	pub fn new_global_routing_set(&mut self, set: &[(MixnetId, MixPublicKey)]) {
		self.topology.handle_new_routing_set(NewRoutingSet { peers: &set })
	}

	/// Send a new surb message to the network.
	/// Message cannot be bigger than a single fragment.
	pub fn register_surb(&mut self, message: Vec<u8>, surb: SurbsPayload) -> Result<(), Error> {
		self.try_apply_topology_change();
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
			unimplemented!()
			//self.queue_external_packet(dest, packet, PacketType::Surbs)?;
		}
		Ok(())
	}

	/// Handle new packet coming from the network. Removes one layer of Sphinx encryption and either
	/// adds the result to the queue for forwarding, or accepts the fragment addressed to us. If the
	/// fragment completes the message, full message is returned.
	fn import_message(
		&mut self,
		peer_id: MixnetId,
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
			Ok(Unwrapped::SurbsReplyExternal(external_peer, tag, payload)) => {
				self.queue_external_reply(external_peer, tag, payload)?;
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
	pub fn remove_connected_peer(&mut self, id: &NetworkId, with_event: bool) -> Option<MixnetId> {
		let mix_id = self.connected_peers.remove(id).and_then(|mut c| {
			self.peer_counts.remove_peer(c.set_disconnected_kind());
			c.mixnet_id().cloned()
		});

		if with_event {
			self.pending_events.push_back(MixnetEvent::Disconnected(vec![(
				*id,
				mix_id.clone(),
				false,
			)]));
		}

		if let Some(mix_id) = mix_id {
			self.peers_to_network_id.remove(&mix_id);
			self.topology.disconnected(&mix_id);
			if self.keep_handshaken_disconnected_address {
				self.disconnected_peers.insert(
					mix_id,
					DisconnectedPeer {
						handshaken: Some(*id),
						next_reconnect_attempt: TRY_RECONNECT_DYN_NB,
					},
				);
			}
			Some(mix_id)
		} else {
			None
		}
	}

	fn random_paths(
		&mut self,
		recipient: Option<&MixnetId>,
		recipient_key: Option<&MixPublicKey>,
		num_hops: &Option<usize>,
		count: usize,
		is_surb: Option<Option<&MixnetId>>,
		is_external: bool,
	) -> Result<(Option<MixnetId>, Vec<Vec<(MixnetId, MixPublicKey)>>), Error> {
		let (start, recipient) = if let Some(external) = is_surb {
			if let Some(recipient) = recipient {
				if let Some(first) = external {
					// send to the first external peer that will reply to use
					(Some((recipient, recipient_key)), Some((first, None)))
				} else {
					(Some((recipient, recipient_key)), Some((&self.local_id, Some(&self.public))))
				}
			} else {
				// no recipient for a surb could be unreachable too.
				return Err(Error::NoPath(None))
			}
		} else {
			(
				(!is_external).then(|| (&self.local_id, Some(&self.public))),
				recipient.map(|r| (r, recipient_key)),
			)
		};

		let num_hops = num_hops.unwrap_or(self.num_hops);
		if num_hops > sphinx::MAX_HOPS {
			return Err(Error::TooManyHops)
		}

		log::trace!(target: "mixnet", "Random path, length {:?}", num_hops);
		self.topology.random_path_ext(&self.local_id, start, recipient, count, num_hops)
	}

	fn cleanup(&mut self, now: Instant) {
		self.fragments.cleanup(now);
		self.surb.cleanup(now);
		self.replay_filter.cleanup(now);
		if let Some(queue) = self.forward_unconnected_message_queue.as_mut() {
			queue.cleanup(now)
		}
	}

	fn try_apply_topology_change(&mut self) {
		if let Some(changed) = self.topology.changed_route() {
			for peer_id in changed {
				if let Some(net_id) = self.peers_to_network_id.get(&peer_id) {
					if let Some(connection) = self.connected_peers.get_mut(net_id) {
						connection.update_kind(
							&mut self.peer_counts,
							&mut self.topology,
							self.forward_unconnected_message_queue.as_mut(),
							&self.window,
							false,
						);
					}
				}
			}
		}
		if let Some(need_conn) = self.topology.try_connect() {
			let mut try_connect = Vec::new();
			for (peer_id, mut maybe_net_id) in need_conn {
				if let Some(net_id) = maybe_net_id.as_ref() {
					if let Some(connection) = self.connected_peers.get_mut(net_id) {
						if connection.mixnet_id() == Some(&peer_id) {
							log::trace!(target: "mixnet", "New routing set, already connected to peer.");
							connection.update_kind(
								&mut self.peer_counts,
								&mut self.topology,
								self.forward_unconnected_message_queue.as_mut(),
								&self.window,
								false,
							);
							continue
						} else {
							// TODO log error
							// change of peer id for network other peer should have broken
							// connection already
							// TODO disconnect and reconnect, but disconnect with the keep alive
							// mechanism to process last forward.
							// Aka keep managed connection for a while and build another one.
							// And drop managed from connected_peers (put in slow_close managed
							// connection) to be able to renew other another handler and p2p
							// conn_id. Also new connection all run as half bandwidth during
							// connection period as long as close connection period in all case.
						}
					}
				}
				if let Some(net_id) = self.peers_to_network_id.get(&peer_id) {
					if let Some(connection) = self.connected_peers.get_mut(net_id) {
						if maybe_net_id.is_some() && maybe_net_id.as_ref() != Some(net_id) {
							// existing connection with change of network id.
							// TODO slow disconnect.
							// TODO log error
						} else {
							log::trace!(target: "mixnet", "New routing set, already connected to peer.");
							connection.update_kind(
								&mut self.peer_counts,
								&mut self.topology,
								self.forward_unconnected_message_queue.as_mut(),
								&self.window,
								false,
							);
							continue
						}
					} else {
						maybe_net_id = Some(*net_id);
					}
				} else if let Some(net_id) = self.disconnected_peers.get(&peer_id) {
					maybe_net_id = net_id.handshaken.clone();
				}
				log::trace!(target: "mixnet", "try connect {:?} -> {:?} - {:?}", self.local_id, peer_id, maybe_net_id.is_some());
				try_connect.push((peer_id, maybe_net_id));
			}
			if !try_connect.is_empty() {
				self.pending_events.push_back(MixnetEvent::TryConnect(try_connect));
			}
		}
	}

	fn try_reconnect(&mut self) {
		let mut try_connect = Vec::new();
		let ShouldConnectTo { peers, number, is_static } = self.topology.should_connect_to();
		let already_connected = self.peer_counts.nb_connected_forward_routing;
		if already_connected >= number && is_static {
			return
		}

		if is_static {
			for peer in peers.iter() {
				if try_connect.len() == number - already_connected {
					break
				}
				if !self.peers_to_network_id.contains_key(peer) {
					let disco_peer = self.disconnected_peers.get(peer);
					try_connect.push((*peer, disco_peer.and_then(|peer| peer.handshaken.clone())));
				}
			}
		} else {
			// try connect more
			for (i, peer) in peers.iter().enumerate() {
				if i > number {
					if try_connect.len() >= number - already_connected {
						// this means that peers late in should connect
						// will see their connection attempt not decrease.
						// Could be parameterized for a less steep curve.
						break
					}
				}
				if !self.peers_to_network_id.contains_key(peer) {
					let disco_peer = self.disconnected_peers.entry(*peer).or_default();
					if disco_peer.next_reconnect_attempt == 0 {
						try_connect.push((*peer, disco_peer.handshaken.clone()));
						disco_peer.next_reconnect_attempt = TRY_RECONNECT_DYN_NB;
					} else {
						disco_peer.next_reconnect_attempt -= 1;
					}
				}
			}
		};

		if !try_connect.is_empty() {
			self.pending_events.push_back(MixnetEvent::TryConnect(try_connect));
		}
	}

	fn poll_inner(&mut self, cx: &mut Context<'_>) -> Poll<MixnetEvent> {
		if let Some(event) = self.pending_events.pop_front() {
			return Poll::Ready(event)
		}

		self.try_apply_topology_change();
		let mut try_reconnect = false;

		if Poll::Ready(()) == self.next_message.poll_unpin(cx) {
			let now = Instant::now();
			self.window.last_now = now;
			let duration = now - self.window.current_start;
			if duration > self.window_size {
				let nb_spent = (duration.as_millis() / self.window_size.as_millis()) as usize;

				if nb_spent > 1 {
					// TODO in a sane system this should disconnect (but only make sense
					// if we transmit connection tables).
					log::warn!("Skipping bandwidth of {} windows", nb_spent);
				}

				self.window.current += Wrapping(nb_spent);
				for _ in 0..nb_spent {
					self.window.current_start += self.window_size;
				}

				if self.next_try_reconnect <= nb_spent {
					try_reconnect = true;
					self.next_try_reconnect = self.try_reconnect_every;
				} else {
					self.next_try_reconnect -= nb_spent;
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

					self.topology.window_stats(stats, &self.peer_counts);
				}
			}

			let duration = now - self.window.current_start;
			self.window.current_packet_limit = ((duration.as_millis() as u64 *
				self.window.packet_per_window as u64) /
				self.window_size.as_millis() as u64) as usize;

			// force at least one packet per window at start.
			self.window.current_packet_limit += 1;

			self.cleanup(now);
			let next_delay = self.average_traffic_delay;
			while !matches!(self.next_message.poll_unpin(cx), Poll::Pending) {
				self.next_message.reset(next_delay);
			}
		}

		let mut all_pending = true;
		let mut disconnected = Vec::new();
		let mut recv_packets = Vec::new();
		let mut queue_packet = None;

		// TODO consider returning a list of event to try put this in all pending more frequently.
		for (peer_id, connection) in self.connected_peers.iter_mut() {
			match connection.poll(
				cx,
				&self.window,
				&mut self.topology,
				&mut self.peer_counts,
				self.forward_unconnected_message_queue.as_mut(),
			) {
				Poll::Ready(ConnectionResult::Established(_peer_id, key)) => {
					all_pending = false;
					if let Some(sphinx_id) = connection.mixnet_id() {
						self.topology.connected(*sphinx_id, key);
						self.topology.peer_stats(&self.peer_counts);
						self.disconnected_peers.remove(sphinx_id);
						self.peers_to_network_id.insert(*sphinx_id, connection.network_id());
					}

					self.pending_events
						.push_back(MixnetEvent::Connected(connection.network_id(), key));
				},
				Poll::Ready(ConnectionResult::Broken(mixnet_id)) => {
					let ShouldConnectTo { peers: _, number: _, is_static } =
						self.topology.should_connect_to();
					let mut retry = false;
					if let Some(mixnet_id) = mixnet_id.as_ref() {
						if is_static {
							// TODO or just peers.contains mixnet_id (could make more sense)
							if self.topology.routing_to(&self.local_id, mixnet_id) {
								retry = true;
							}
						} else {
							// TODO should try more prio up to some limit among all disco
						}
					}

					// same as pending
					disconnected.push((*peer_id, mixnet_id, retry));
				},
				Poll::Ready(ConnectionResult::Received(packet)) => {
					all_pending = false;
					if let Some(sphinx_id) = connection.mixnet_id() {
						recv_packets.push((*sphinx_id, packet));
					}
				},
				Poll::Ready(ConnectionResult::ExternalQuery(recipient, data, surbs)) => {
					all_pending = false;
					if let Some(tag) = surbs {
						if let Some(id) = connection.mixnet_id() {
							// TODO protect from deleting an existing one
							self.surb.insert(
								tag.clone(),
								SurbsPersistances::FromExternal(*id, tag),
								self.window.last_now,
							);
						}
					}
					queue_packet = Some((recipient, data));
				},
				Poll::Ready(ConnectionResult::ExternalReply(tag, payload)) => {
					all_pending = false;
					match sphinx::read_surb_payload(&tag, payload, &mut self.surb) {
						Ok(Unwrapped::SurbsReply(payload, query, recipient)) => {
							if let Ok(Some((message, kind))) = self
								.fragments
								.insert_fragment(payload, MessageType::FromSurbs(query, recipient))
							{
								log::debug!(target: "mixnet", "Imported surb from {:?} ({} bytes)", peer_id, message.len());
								return Poll::Ready(MixnetEvent::Message(DecodedMessage {
									peer: connection.mixnet_id().cloned().unwrap_or_default(),
									message,
									kind,
								}))
							} else {
								log::error!(target: "mixnet", "Surbs fragment from {:?}", peer_id);
							}
						},
						Ok(_) => {
							// is actually unreachable
							log::trace!(target: "mixnet", "Unexpected surbs exteraln reply content.");
						},
						Err(error) => {
							log::trace!(target: "mixnet", "Error reading external surb reply {:?}.", error);
						},
					}
				},

				Poll::Pending => (),
			}
		}

		if let Some((recipient, data)) = queue_packet {
			let mut rng = rand::thread_rng();
			let delay = exp_delay(&mut rng, self.average_hop_delay);
			if let Err(error) =
				self.queue_packet(recipient, data, delay, PacketType::ForwardExternal)
			{
				log::trace!(target: "mixnet", "Error adding external packet {:}.", error);
				// TODO reply with meta protocol to external with a failure.
			}
		}

		for (peer, packet) in recv_packets {
			if !self.import_packet(peer, packet) {
				log::trace!(target: "mixnet", "Error importing packet, wrong format.");
				if let Some(stats) = self.window.stats.as_mut() {
					stats.number_received_valid += 1;
				}
			}
		}

		if try_reconnect {
			self.try_reconnect();
		}

		if !disconnected.is_empty() {
			for (peer, from, retry) in disconnected.iter() {
				log::trace!(target: "mixnet", "Disconnecting peer {:?} from {:?}, retry {:?}", from, self.local_id, retry);
				self.remove_connected_peer(peer, false);
			}

			return Poll::Ready(MixnetEvent::Disconnected(disconnected))
		}

		if all_pending {
			Poll::Pending
		} else {
			Poll::Ready(MixnetEvent::None)
		}
	}

	fn import_packet(&mut self, peer: MixnetId, packet: Packet) -> bool {
		match self.import_message(peer, packet) {
			Ok(Some((message, kind))) => {
				self.pending_events.push_back(MixnetEvent::Message(DecodedMessage {
					peer,
					message,
					kind,
				}));
			},
			Ok(None) => (),
			Err(e) => {
				log::warn!(target: "mixnet", "Error importing message: {:?}", e);
			},
		}
		true
	}
}

impl<T: Configuration, C: Connection> Future for Mixnet<T, C> {
	type Output = MixnetEvent;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		self.get_mut().poll_inner(cx)
	}
}

/// Message id, use as surb key and replay protection.
/// This is the result of hashing the secret.
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct ReplayTag(pub [u8; crate::core::sphinx::HASH_OUTPUT_SIZE]);

pub struct SurbsCollection {
	pending: MixnetCollection<ReplayTag, SurbsPersistances>,
}

impl SurbsCollection {
	pub fn new(config: &Config) -> Self {
		SurbsCollection { pending: MixnetCollection::new(config.surb_ttl_ms) }
	}

	pub fn insert(&mut self, surb_id: ReplayTag, surb: SurbsPersistances, now: Instant) {
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

struct QueuedUnconnectedPackets {
	messages: HashMap<MixnetId, VecDeque<(QueuedPacket, Wrapping<usize>)>>,
	expiration: Duration,
	exp_deque: VecDeque<(Instant, Option<MixnetId>)>,
	exp_deque_offset: Wrapping<usize>,
	queue_message_unconnected_number: u32,
}

impl QueuedUnconnectedPackets {
	pub fn new(ttl_ms: u64, queue_message_unconnected_number: u32) -> Self {
		QueuedUnconnectedPackets {
			messages: Default::default(),
			expiration: Duration::from_millis(ttl_ms),
			exp_deque: Default::default(),
			exp_deque_offset: Wrapping(0),
			queue_message_unconnected_number,
		}
	}

	fn insert(&mut self, recipient: MixnetId, packet: QueuedPacket, now: Instant) {
		let expires = now + self.expiration;
		let ix = self.exp_deque_offset + Wrapping(self.exp_deque.len());
		let queue = self.messages.entry(recipient).or_default();
		if queue.len() == self.queue_message_unconnected_number as usize {
			if let Some((message, ix)) = queue.pop_front() {
				let ix = ix - self.exp_deque_offset;
				self.exp_deque[ix.0].1 = None;
				log::error!("Dropped message {:?} after {:?}", message.kind, self.expiration);
			}
		}
		queue.push_back((packet, ix));
		self.exp_deque.push_back((expires, Some(recipient)));
	}

	fn remove(
		&mut self,
		recipient: &MixnetId,
	) -> Option<VecDeque<(QueuedPacket, Wrapping<usize>)>> {
		let result = self.messages.remove(recipient);
		if let Some(paquets) = result.as_ref() {
			for (_, ix) in paquets.iter() {
				let ix = ix - self.exp_deque_offset;
				self.exp_deque[ix.0].1 = None;
			}
		}
		result
	}

	fn cleanup(&mut self, now: Instant) {
		while let Some(first) = self.exp_deque.front() {
			if first.0 > now {
				break
			}
			if let Some(first) = first.1.as_ref() {
				let mut remove = false;
				if let Some(messages) = self.messages.get_mut(first) {
					if let Some(message) = messages.pop_front() {
						debug_assert!(message.1 == self.exp_deque_offset);
						log::error!(
							"Dropped message {:?} after {:?}",
							message.0.kind,
							self.expiration
						);
					}
					if messages.is_empty() {
						remove = true;
					}
				}
				if remove {
					self.messages.remove(first);
				}
			}
			self.exp_deque.pop_front();
			self.exp_deque_offset += Wrapping(1);
		}
	}
}

pub(crate) fn cover_message_to(peer_id: &MixnetId, peer_key: MixPublicKey) -> Option<Packet> {
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
}

/// Current number of connected peers for the mixnet.
#[derive(Default, Debug)]
pub struct PeerCount {
	/// Total number of nodes connected but
	/// not already accepted.
	pub nb_pending_handshake: usize,
	/// Total number of connected nodes (handshake
	/// successful).
	pub nb_connected: usize,
	/// Number of mixnet peer we send and proxy
	/// to.
	pub nb_connected_forward_routing: usize,
	/// Number of mixnet peer we proxy and receive
	/// from.
	pub nb_connected_receive_routing: usize,
	/// Number of external nodes connection kept on mixnet.
	pub nb_connected_external: usize,
}

impl PeerCount {
	fn add_peer<T: Configuration>(
		&mut self,
		local_id: &MixnetId,
		peer: &MixnetId,
		topology: &T,
	) -> ConnectedKind {
		let is_routing_self = topology.can_route(peer);
		let is_routing_peer = topology.can_route(peer);

		self.nb_connected += 1;
		match (is_routing_self, is_routing_peer) {
			(true, true) => {
				let forward = topology.routing_to(local_id, peer);
				let receiv = topology.routing_to(peer, local_id);
				match (forward, receiv) {
					(true, true) => {
						self.nb_connected_receive_routing += 1;
						self.nb_connected_forward_routing += 1;
						ConnectedKind::RoutingReceiveForward
					},
					(true, false) => {
						self.nb_connected_forward_routing += 1;
						ConnectedKind::RoutingForward
					},
					(false, true) => {
						self.nb_connected_receive_routing += 1;
						ConnectedKind::RoutingReceive
					},
					(false, false) => {
						self.nb_connected_external += 1;
						ConnectedKind::ExternalRouting
					},
				}
			},
			(false, true) | (true, false) => {
				self.nb_connected_external += 1;
				ConnectedKind::External
			},
			(false, false) => {
				self.nb_connected_external += 1;
				ConnectedKind::External
			},
		}
	}

	fn remove_peer(&mut self, kind: ConnectedKind) {
		match kind {
			ConnectedKind::PendingHandshake => {
				self.nb_pending_handshake -= 1;
			},
			ConnectedKind::External | ConnectedKind::ExternalRouting => {
				self.nb_connected -= 1;
				self.nb_connected_external -= 1;
			},
			ConnectedKind::RoutingReceive => {
				self.nb_connected -= 1;
				self.nb_connected_receive_routing -= 1;
			},
			ConnectedKind::RoutingForward => {
				self.nb_connected -= 1;
				self.nb_connected_forward_routing -= 1;
			},
			ConnectedKind::RoutingReceiveForward => {
				self.nb_connected -= 1;
				self.nb_connected_forward_routing -= 1;
				self.nb_connected_receive_routing -= 1;
			},
			ConnectedKind::Disconnected => (),
		}
	}
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
