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

//! Topology where direct peers are resolved
//! by hashing peers id (so randomly distributed).

use crate::{
	traits::{NewRoutingSet, ShouldConnectTo, Topology},
	Error, MixPublicKey, MixnetId, NetworkId, PeerCount,
};
use log::{debug, error, trace};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Configuaration for this hash table.
/// Allows to use table from external source.
pub trait Configuration {
	/// Version for routing table.
	type Version: TableVersion;

	/// Routing tables are transmitted externally eg from DHT or
	/// read on a blockchain or registry.
	const DISTRIBUTE_ROUTES: bool;

	/// Minimal number of node for accepting to add new message.
	const LOW_MIXNET_THRESHOLD: usize;

	/// Minimal number of paths for sending to recipient.
	const LOW_MIXNET_PATHS: usize;

	/// Number of connection a routing peer should have active (with
	/// constant message bandwidth).
	const NUMBER_CONNECTED_FORWARD: usize;
	// Since hashing routed, should be same as NUMBER_CONNECTED_BACKWARD,
	// just we allow some lower value for margin.
	const NUMBER_CONNECTED_BACKWARD: usize;

	/// Percent of additional bandwidth allowed for external
	/// node message reception.
	const EXTERNAL_BANDWIDTH: (usize, usize);

	/// Default parameters for the topology.
	const DEFAULT_PARAMETERS: Parameters;
}

/// Configuration parameters for topology.
#[derive(Clone)]
pub struct Parameters {
	// limit to external connection
	pub max_external: Option<usize>,

	// When running as external number of consumer connection
	// with validator to try to maintain.
	pub number_consumer_connection: Option<usize>,
}

pub trait TableVersion: Default + Clone + Eq + PartialEq + Ord + std::fmt::Debug + 'static {
	/// Associated table content did change.
	fn register_change(&mut self);
}

impl TableVersion for () {
	fn register_change(&mut self) {}
}

/// A topology where connections are determined by taking first
/// hashes of a set of mixpeers.
///
/// This assumes all peers are connected (`external_routing_table` defaults to `false`).
/// And routing table are updated on mixpeer set changes.
pub struct TopologyHashTable<C: Configuration> {
	local_id: MixnetId,

	// true when we are in routing set.
	routing: bool,

	routing_table: RoutingTable<C::Version>,

	// The connected nodes (for first hop use `rtouting_peers` joined `connected_nodes`).
	connected_nodes: HashSet<MixnetId>,

	// All rooting peers are considered connected (when building message except first hop).
	allowed_routing: BTreeSet<MixnetId>,

	changed_routing: BTreeSet<MixnetId>,

	try_connect: BTreeMap<MixnetId, Option<NetworkId>>,

	// This is only routing peers we got info for.
	routing_peers: BTreeMap<MixnetId, RoutingTable<C::Version>>,

	default_num_hop: usize,

	target_bytes_per_seconds: usize,

	params: Parameters,

	// all path of a given size.
	// on every change to routing table this is cleared TODO make change synchronously to
	// avoid full calc every time.
	//
	// This assume topology is balanced, so we can just run random selection at each hop.
	// TODO check topology balancing and balance if needed (keeping only peers with right incoming
	// and outgoing?)
	// TODO find something better
	// TODO could replace HashMap by vec and use indices as ptr
	paths: BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
	paths_depth: usize,

	// Ordered theorical connections by priority.
	should_connect_to: Vec<MixnetId>,

	// Connection to peer that are more prioritary: attempt connect.
	// This is only used when `DISTRIBUTE_ROUTE` is true.
	// TODO should be part of mixnet core/mod struct.
	should_connect_pending: HashMap<MixnetId, (usize, bool)>,
}

/// Current published view of an routing peer routing table.
/// TODO rename RoutingTable
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RoutingTable<V> {
	pub public_key: MixPublicKey,
	pub version: V,
	// TODO could replace MixnetId by index in list of allowed routing peers for compactness.
	pub connected_to: BTreeSet<MixnetId>,
	pub receive_from: BTreeSet<MixnetId>,
}

impl<C: Configuration> Topology for TopologyHashTable<C> {
	fn changed_route(&mut self) -> Option<BTreeSet<MixnetId>> {
		(!self.changed_routing.is_empty()).then(|| std::mem::take(&mut self.changed_routing))
	}

	fn try_connect(&mut self) -> Option<BTreeMap<MixnetId, Option<NetworkId>>> {
		(!self.try_connect.is_empty()).then(|| std::mem::take(&mut self.try_connect))
	}

	fn first_hop_nodes_external(
		&self,
		from: &MixnetId,
		to: &MixnetId,
	) -> Vec<(MixnetId, MixPublicKey)> {
		// allow for all
		self.routing_peers
			.iter()
			.filter(|(id, _key)| from != *id)
			.filter(|(id, _key)| to != *id)
			.filter(|(id, _key)| &self.local_id != *id)
			.filter(|(id, _key)| self.connected_nodes.contains(*id))
			.map(|(k, table)| (*k, table.public_key))
			.collect()
	}

	fn is_first_node(&self, id: &MixnetId) -> bool {
		// allow for all
		self.can_route(id)
	}

	// TODO make random_recipient return path directly.
	fn random_recipient(
		&mut self,
		from: &MixnetId,
		send_options: &crate::SendOptions,
	) -> Option<(MixnetId, MixPublicKey)> {
		if !self.has_enough_nodes_to_send() {
			debug!(target: "mixnet", "Not enough routing nodes for path.");
			return None
		}
		let mut bad = HashSet::new();
		loop {
			debug!(target: "mixnet", "rdest {:?}", (&from, &bad));
			if let Some(peer) = self.random_dest(|p| p == from || bad.contains(p)) {
				debug!(target: "mixnet", "Trying random dest {:?}.", peer);
				let nb_hop = send_options.num_hop.unwrap_or(self.default_num_hop);
				Self::fill_paths(
					&self.local_id,
					&self.routing_table,
					&mut self.paths,
					&mut self.paths_depth,
					&self.routing_peers,
					nb_hop,
				);
				let from_count = if !self.can_route(from) {
					debug!(target: "mixnet", "external {:?}", from);
					// TODO should return path directly rather than random here that could be
					// different that path one -> then the check on count could be part of path
					// building
					let firsts = self.first_hop_nodes_external(from, &peer);
					if firsts.is_empty() {
						return None
					}
					firsts[0].0
				} else {
					*from
				};
				// TODO also count surbs??
				let nb_path = count_paths(&self.paths, &from_count, &peer, nb_hop);
				debug!(target: "mixnet", "Number path for dest {:?}.", nb_path);
				debug!(target: "mixnet", "{:?} to {:?}", from_count, peer);
				if nb_path >= C::LOW_MIXNET_PATHS {
					return self.routing_peers.get(&peer).map(|keys| (peer, keys.public_key))
				} else {
					bad.insert(peer);
				}
			} else {
				debug!(target: "mixnet", "No random dest.");
				return None
			}
		}
	}

	fn routing_to(&self, from: &MixnetId, to: &MixnetId) -> bool {
		if &self.local_id == from {
			if self.routing {
				self.routing_table.connected_to.contains(to)
			} else {
				false
			}
		} else {
			self.routing_peers
				.get(from)
				.map(|table| table.connected_to.contains(to))
				.unwrap_or(false)
		}
	}

	fn random_path(
		&mut self,
		start_node: (&MixnetId, Option<&MixPublicKey>),
		recipient_node: (&MixnetId, Option<&MixPublicKey>),
		nb_chunk: usize,
		num_hops: usize,
		max_hops: usize,
		last_query_if_surb: Option<&Vec<(MixnetId, MixPublicKey)>>,
	) -> Result<Vec<Vec<(MixnetId, MixPublicKey)>>, Error> {
		// Diverging from default implementation (random from all possible paths), as `neighbor`
		// return same result for all routing peer building all possible path is not usefull.
		let mut add_start = None;
		let mut add_end = None;
		let start = if self.is_first_node(start_node.0) {
			*start_node.0
		} else {
			trace!(target: "mixnet", "External node");
			if num_hops + 1 > max_hops {
				return Err(Error::TooManyHops)
			}

			let firsts = self.first_hop_nodes_external(start_node.0, recipient_node.0);
			if firsts.is_empty() {
				return Err(Error::NoPath(Some(*recipient_node.0)))
			}
			let mut rng = rand::thread_rng();
			use rand::Rng;
			let n: usize = rng.gen_range(0..firsts.len());
			add_start = Some(firsts[n]);
			firsts[n].0
		};

		let recipient = if self.can_route(recipient_node.0) {
			*recipient_node.0
		} else {
			trace!(target: "mixnet", "Non routing recipient");
			if num_hops + 1 > max_hops {
				return Err(Error::TooManyHops)
			}

			if let Some(query) = last_query_if_surb {
				// use again a node that was recently connected.
				if let Some(rec) = query.get(0) {
					trace!(target: "mixnet", "Surbs last: {:?}", rec);
					add_end = Some(recipient_node);
					rec.0
				} else {
					return Err(Error::NoPath(Some(*recipient_node.0)))
				}
			} else {
				return Err(Error::NoPath(Some(*recipient_node.0)))
			}
		};
		trace!(target: "mixnet", "number hop: {:?}", num_hops);
		Self::fill_paths(
			&self.local_id,
			&self.routing_table,
			&mut self.paths,
			&mut self.paths_depth,
			&self.routing_peers,
			num_hops,
		);
		let nb_path = count_paths(&self.paths, &start, &recipient, num_hops);
		debug!(target: "mixnet", "Number path for dest {:?}.", nb_path);
		debug!(target: "mixnet", "{:?} to {:?}", start, recipient);
		if nb_path < C::LOW_MIXNET_PATHS {
			error!(target: "mixnet", "not enough paths: {:?}", nb_path);
			trace!(target: "mixnet", "not enough paths: {:?}", &self.paths);
			// TODO NotEnoughPath error
			return Err(Error::NoPath(Some(recipient)))
		};
		trace!(target: "mixnet", "enough paths: {:?}", nb_path);

		let mut result = Vec::with_capacity(nb_chunk);
		while result.len() < nb_chunk {
			let path_ids =
				if let Some(path) = random_path(&self.paths, &start, &recipient, num_hops) {
					trace!(target: "mixnet", "Got path: {:?}", &path);
					path
				} else {
					return Err(Error::NoPath(Some(recipient)))
				};
			let mut path = Vec::with_capacity(num_hops + 1);
			if let Some((peer, key)) = add_start {
				debug!(target: "mixnet", "Add first, nexts {:?}.", path_ids.len());
				path.push((peer, key));
			}

			for peer_id in path_ids.into_iter() {
				if let Some(table) = self.routing_peers.get(&peer_id) {
					path.push((peer_id, table.public_key));
				} else {
					error!(target: "mixnet", "node in routing_nodes must also be in connected_nodes");
					unreachable!("node in routing_nodes must also be in connected_nodes");
				}
			}
			if let Some(table) = self.routing_peers.get(&recipient) {
				path.push((recipient, table.public_key));
			} else if self.local_id == recipient {
				// surb reply
				path.push((self.local_id, self.routing_table.public_key));
			} else {
				error!(target: "mixnet", "Unknown recipient {:?}", recipient);
				return Err(Error::NotEnoughRoutingPeers)
			}

			if let Some((peer, key)) = add_end {
				if let Some(key) = key {
					path.push((*peer, *key));
				} else {
					return Err(Error::NoPath(Some(*recipient_node.0)))
				}
			}
			result.push(path);
		}
		debug!(target: "mixnet", "Path: {:?}", result);
		Ok(result)
	}

	fn can_route(&self, id: &MixnetId) -> bool {
		if &self.local_id == id {
			self.routing
		} else {
			self.allowed_routing.contains(id)
		}
	}

	fn connected(&mut self, peer_id: MixnetId, _key: MixPublicKey) {
		debug!(target: "mixnet", "Connected from internal");
		self.add_connected_peer(peer_id);
		self.distributed_try_connect();
	}

	fn disconnected(&mut self, peer_id: &MixnetId) {
		debug!(target: "mixnet", "Disconnected from internal");
		self.add_disconnected_peer(peer_id);
		self.distributed_try_connect();
	}

	fn bandwidth_external(&self, id: &MixnetId, peers: &PeerCount) -> Option<(usize, usize)> {
		if !self.routing && self.can_route(id) {
			// expect surbs: TODO make it optional??
			return Some((1, 1))
		}
		// TODO can cache this result (Option<Option<(usize, usize))

		let nb_external = peers.nb_connected_external + 1;

		let forward_bandwidth = ((C::EXTERNAL_BANDWIDTH.0 + C::EXTERNAL_BANDWIDTH.1) *
			peers.nb_connected_forward_routing *
			self.target_bytes_per_seconds) /
			C::EXTERNAL_BANDWIDTH.1;
		let receive_bandwidth = peers.nb_connected_receive_routing * self.target_bytes_per_seconds;

		let available_bandwidth = if forward_bandwidth > receive_bandwidth {
			forward_bandwidth - receive_bandwidth
		} else {
			0
		};
		let available_per_external = available_bandwidth / nb_external;

		Some((available_per_external, self.target_bytes_per_seconds))
	}

	fn accept_peer(&self, peer_id: &MixnetId, peers: &PeerCount) -> bool {
		if C::DISTRIBUTE_ROUTES {
			// Allow any allowed routing peers as it can be any of the should_connect_to in case
			// there is many disconnected.
			if self.routing && self.can_route(&self.local_id) && self.can_route(peer_id) {
				return true
			}
		}
		if self.routing {
			self.routing_to(peer_id, &self.local_id) ||
				self.routing_to(&self.local_id, peer_id) ||
				(!self.can_route(peer_id) &&
					peers.nb_connected_external <
						self.params.max_external.unwrap_or(usize::MAX) &&
					self.bandwidth_external(peer_id, peers).is_some())
		} else {
			// connect as many routing node as possible
			self.can_route(peer_id) &&
				peers.nb_connected_external < self.params.max_external.unwrap_or(usize::MAX)
		}
	}

	fn should_connect_to(&self) -> ShouldConnectTo {
		let (number, is_static) = if self.routing {
			(C::NUMBER_CONNECTED_FORWARD, !C::DISTRIBUTE_ROUTES)
		} else {
			(self.params.number_consumer_connection.unwrap_or(usize::MAX), false)
		};
		ShouldConnectTo { peers: self.should_connect_to.as_slice(), number, is_static }
	}

	fn handle_new_routing_set(&mut self, set: NewRoutingSet) {
		if !C::DISTRIBUTE_ROUTES {
			assert!(!C::DISTRIBUTE_ROUTES);
			self.handle_new_routing_set_start(set.peers.iter().map(|k| &k.0), None);
			self.refresh_static_routing_tables(set.peers);
		} else {
			unimplemented!("TODO");
		}
	}
}

impl<C: Configuration> TopologyHashTable<C> {
	/// Instantiate a new topology.
	pub fn new(
		local_id: MixnetId,
		node_public_key: MixPublicKey,
		config: &crate::Config,
		params: Parameters,
		routing_table_version: C::Version,
	) -> Self {
		let routing_table = RoutingTable {
			public_key: node_public_key,
			version: routing_table_version,
			connected_to: BTreeSet::new(),
			receive_from: BTreeSet::new(),
		};
		TopologyHashTable {
			local_id,
			allowed_routing: BTreeSet::new(),
			connected_nodes: HashSet::new(),
			changed_routing: BTreeSet::new(),
			try_connect: BTreeMap::new(),
			routing: false,
			routing_peers: BTreeMap::new(),
			routing_table,
			paths: Default::default(),
			paths_depth: 0,
			//disconnected_in_routing: Default::default(),
			target_bytes_per_seconds: config.target_bytes_per_second as usize,
			params,
			default_num_hop: config.num_hops as usize,
			should_connect_to: Default::default(),
			should_connect_pending: Default::default(),
		}
	}

	/// Change ids.
	/// TODO this should be part of handle_new_routing_set on trait
	pub fn change_local(
		&mut self,
		local_id: Option<MixnetId>,
		node_public_key: Option<MixPublicKey>,
	) {
		if let Some(id) = local_id {
			self.local_id = id;
		}
		if let Some(key) = node_public_key {
			self.routing_table.public_key = key;
		}
	}

	fn has_enough_nodes_to_send(&self) -> bool {
		if C::DISTRIBUTE_ROUTES {
			self.routing_peers
				.iter()
				.filter(|(_, table)| table.connected_to.len() >= C::NUMBER_CONNECTED_FORWARD)
				.count() >= C::LOW_MIXNET_THRESHOLD
		} else {
			// all nodes are seen as live.
			self.allowed_routing.len() >= C::LOW_MIXNET_THRESHOLD
		}
	}

	/// Is peer able to proxy.
	pub fn has_enough_nodes_to_proxy(&self) -> bool {
		self.routing_peers.len() >= C::LOW_MIXNET_THRESHOLD
	}

	fn random_dest(&self, skip: impl Fn(&MixnetId) -> bool) -> Option<MixnetId> {
		use rand::RngCore;
		// Warning this assume that NetworkId is a randomly distributed value.
		let mut ix = [0u8; 32];
		rand::thread_rng().fill_bytes(&mut ix[..]);

		trace!(target: "mixnet", "routing {:?}, ix {:?}", self.routing_peers, ix);
		for (key, table) in self.routing_peers.range(ix..) {
			// TODO alert on low receive_from
			if !skip(key) && table.receive_from.len() >= C::NUMBER_CONNECTED_BACKWARD {
				debug!(target: "mixnet", "Random route node");
				return Some(*key)
			} else {
				debug!(target: "mixnet", "Skip {:?}, nb {:?}, {:?}", skip(key), table.receive_from.len(), C::NUMBER_CONNECTED_BACKWARD);
			}
		}
		for (key, table) in self.routing_peers.range(..ix).rev() {
			if !skip(key) && table.receive_from.len() >= C::NUMBER_CONNECTED_BACKWARD {
				debug!(target: "mixnet", "Random route node");
				return Some(*key)
			} else {
				debug!(target: "mixnet", "Skip {:?}, nb {:?}, {:?}", skip(key), table.receive_from.len(), C::NUMBER_CONNECTED_BACKWARD);
			}
		}
		None
	}

	// TODO Note that building this is rather brutal, could just make some
	// random selection already to reduce size (and refresh after x uses).
	fn fill_paths(
		local_id: &MixnetId,
		local_routing: &RoutingTable<C::Version>,
		paths: &mut BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
		paths_depth: &mut usize,
		routing_peers: &BTreeMap<MixnetId, RoutingTable<C::Version>>,
		depth: usize,
	) {
		if &depth <= paths_depth {
			return
		}
		// TODO not strictly needed
		let mut to_from = HashMap::<MixnetId, Vec<MixnetId>>::new();

		for (from, table) in routing_peers.iter().chain(std::iter::once((local_id, local_routing)))
		{
			// TODO change if limiting size of receive_from
			to_from.insert(*from, table.receive_from.iter().cloned().collect());
		}

		fill_paths_inner(to_from, paths, *paths_depth, depth);
		if *paths_depth < depth {
			*paths_depth = depth;
		}
	}

	pub fn add_connected_peer(&mut self, peer_id: MixnetId) {
		debug!(target: "mixnet", "Connected to mixnet {:?}", peer_id);
		if self.connected_nodes.contains(&peer_id) {
			return
		}
		self.connected_nodes.insert(peer_id);

		if C::DISTRIBUTE_ROUTES {
			if let Some(info) = self.should_connect_pending.get_mut(&peer_id) {
				if info.1 {
					info.1 = false;
					self.refresh_self_routing_table();
				}
			}
		}
	}

	fn add_disconnected_peer(&mut self, peer_id: &MixnetId) {
		debug!(target: "mixnet", "Disconnected from mixnet {:?}", peer_id);
		if self.connected_nodes.remove(peer_id) && C::DISTRIBUTE_ROUTES {
			if let Some(info) = self.should_connect_pending.get_mut(peer_id) {
				if !info.1 {
					info.1 = true;
					self.refresh_self_routing_table();
				}
			}
		}
	}

	fn handle_new_routing_set_start<'a>(
		&mut self,
		set: impl Iterator<Item = &'a MixnetId>,
		new_self: Option<(Option<MixnetId>, Option<MixPublicKey>)>,
	) {
		debug!(target: "mixnet", "Handle new routing set.");
		if let Some((id, pub_key)) = new_self {
			if let Some(id) = id {
				self.local_id = id;
			}
			if let Some(pub_key) = pub_key {
				self.routing_table.public_key = pub_key;
			}
		}

		// all previously allowed will see their routing change.
		let mut prev =
			std::mem::replace(&mut self.changed_routing, std::mem::take(&mut self.allowed_routing));
		self.changed_routing.append(&mut prev);
		self.routing_peers.clear();
		self.routing = false;

		for peer_id in set {
			self.allowed_routing.insert(*peer_id);
			if &self.local_id == peer_id {
				debug!(target: "mixnet", "In new routing set, routing.");
				self.routing = true;
			}
		}
	}

	pub fn distributed_try_connect(&mut self) {
		if C::DISTRIBUTE_ROUTES {
			let mut nb_try_connect = C::NUMBER_CONNECTED_FORWARD;
			for peer in self.should_connect_to.iter() {
				if let Some(_table) = self.routing_peers.get(peer) {
					if !self.routing_table.connected_to.contains(peer) {
						// TODO try_connect_pending with ttl to avoid getting stuck on
						// list start
						// enough) -> maybe up nb_try_connect.
						// TODO network_id in routing table??
						// self.try_connect.insert(*peer, table.network_id);
						self.try_connect.insert(*peer, None);
					}
				}
				nb_try_connect -= 1;
				if nb_try_connect == 0 {
					return
				}
			}
		}
	}

	pub fn handle_new_routing_distributed(
		&mut self,
		set: &[MixnetId],
		new_self: Option<(Option<MixnetId>, Option<MixPublicKey>)>,
		version: C::Version,
	) {
		assert!(C::DISTRIBUTE_ROUTES);
		self.handle_new_routing_set_start(set.iter(), new_self);
		self.should_connect_to =
			should_connect_to(&self.local_id, &self.allowed_routing, usize::MAX);
		for (index, id) in self.should_connect_to.iter().enumerate() {
			self.should_connect_pending.insert(*id, (index, true));
		}
		debug!(target: "mixnet", "should connect to {:?}", self.should_connect_to);
		self.routing_table.version = version;
		self.refresh_self_routing_table();

		// reinsert to update should_connect_pending: TODO just iterate here
		let connected = std::mem::take(&mut self.connected_nodes);
		for peer_id in connected.into_iter() {
			self.add_connected_peer(peer_id);
		}
		self.distributed_try_connect();
	}

	pub fn handle_new_self_key(&mut self) {
		unimplemented!("rotate key");
	}

	pub fn receive_new_routing_table(
		&mut self,
		with: MixnetId,
		new_table: RoutingTable<C::Version>,
	) {
		if with == self.local_id {
			// ignore
			return
		}
		let mut insert = true;
		if let Some(table) = self.routing_peers.get(&with) {
			if new_table.version <= table.version {
				log::debug!(target: "mixnet", "Not updated routes: {:?}", self.routing_peers);
				// TODO old tables receive a lot should lower dht peer prio.
				insert = false;
			}
		}
		if insert {
			// TODO sanity check of table (not connected to too many peers), ~ consistent with
			// peer neighbors (at least from the connected one we know)...
			// TODO number of non connected neighbor that should be.
			self.routing_peers.insert(with, new_table);
			self.changed_routing.insert(with);
			self.paths.clear();
			self.paths_depth = 0;
			log::debug!(target: "mixnet", "current routes: {:?}", self.routing_peers);
		}
	}

	fn refresh_self_routing_table(&mut self) {
		log::debug!(target: "mixnet", "Refresh self route: {:?}", self.routing_table);
		let past = self.routing_table.clone();
		self.routing_table.connected_to.clear(); // TODO update a bit more precise
		for peer in self.should_connect_to.iter() {
			if let Some(info) = self.should_connect_pending.get(peer) {
				if !info.1 {
					self.routing_table.connected_to.insert(*peer);
				}
			}
			if self.routing_table.connected_to.len() == C::NUMBER_CONNECTED_FORWARD {
				break
			}
		}
		self.routing_table.receive_from.clear(); // TODO update a bit more precise
		for (peer_id, table) in self.routing_peers.iter() {
			if table.connected_to.contains(&self.local_id) {
				self.routing_table.receive_from.insert(*peer_id);
			}
		}

		if past != self.routing_table {
			self.routing_table.version.register_change();
			self.paths.clear();
			self.paths_depth = 0;
			log::debug!(target: "mixnet", "Refreshed self route: {:?}", self.routing_table);
		}
	}

	fn refresh_static_routing_tables(&mut self, set: &[(MixnetId, MixPublicKey)]) {
		for (id, public_key) in set.iter() {
			if id == &self.local_id {
				if let Some(table) = Self::refresh_connection_table_to(
					id,
					public_key,
					Some(&self.routing_table),
					&self.allowed_routing,
					&mut self.should_connect_to,
				) {
					// TODO could also add receive_from.
					for peer_id in table.connected_to.iter() {
						if !self.routing_table.connected_to.contains(peer_id) {
							self.try_connect.insert(*peer_id, None);
						}
					}
					self.routing_table = table;
					self.paths.clear();
					self.paths_depth = 0;
				}
			} else {
				let past = self.routing_peers.get(id);
				if let Some(table) = Self::refresh_connection_table_to(
					id,
					public_key,
					past,
					&self.allowed_routing,
					&mut self.should_connect_to,
				) {
					self.routing_peers.insert(*id, table);
					self.paths.clear();
					self.paths_depth = 0;
				}
			}
		}

		for id in self.allowed_routing.iter() {
			if id == &self.local_id {
				if let Some(from) = Self::refresh_connection_table_from(
					id,
					&self.routing_table.receive_from,
					self.routing_peers.iter(),
				) {
					self.routing_table.receive_from = from;
				}
			} else if let Some(routing_table) = self.routing_peers.get(id) {
				if let Some(from) = Self::refresh_connection_table_from(
					id,
					&routing_table.receive_from,
					self.routing_peers
						.iter()
						.chain(std::iter::once((&self.local_id, &self.routing_table))),
				) {
					if let Some(routing_table) = self.routing_peers.get_mut(id) {
						routing_table.receive_from = from;
					}
				}
			}
		}
	}

	fn refresh_connection_table_to(
		from: &MixnetId,
		from_key: &MixPublicKey,
		past: Option<&RoutingTable<C::Version>>,
		allowed_routing: &BTreeSet<MixnetId>,
		should_connect_to_dest: &mut Vec<MixnetId>,
	) -> Option<RoutingTable<C::Version>> {
		*should_connect_to_dest =
			should_connect_to(from, allowed_routing, C::NUMBER_CONNECTED_FORWARD);
		let mut routing_table = RoutingTable {
			public_key: *from_key,
			version: Default::default(), // No version when refreshing from peer set only
			connected_to: Default::default(),
			receive_from: Default::default(),
		};
		for peer in should_connect_to_dest.iter() {
			// consider all connected
			routing_table.connected_to.insert(*peer);
			if routing_table.connected_to.len() == C::NUMBER_CONNECTED_FORWARD {
				break
			}
		}

		(past != Some(&routing_table)).then(|| routing_table)
	}

	fn refresh_connection_table_from<'a>(
		from: &MixnetId,
		past: &BTreeSet<MixnetId>,
		routing_peers: impl Iterator<Item = (&'a MixnetId, &'a RoutingTable<C::Version>)>,
	) -> Option<BTreeSet<MixnetId>> {
		let mut receive_from = BTreeSet::default();
		for (peer_id, table) in routing_peers {
			if table.connected_to.contains(from) {
				receive_from.insert(*peer_id);
			}
		}

		(past != &receive_from).then(|| receive_from)
	}

	/// Returns the mixnet peer id of our node.
	pub fn local_id(&self) -> &MixnetId {
		&self.local_id
	}

	/// Return our routing table.
	pub fn local_routing_table(&self) -> &RoutingTable<C::Version> {
		&self.routing_table
	}
}

fn fill_paths_inner(
	to_from: HashMap<MixnetId, Vec<MixnetId>>,
	paths: &mut BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
	paths_depth: usize,
	depth: usize,
) {
	let mut start_depth = std::cmp::max(2, paths_depth);
	while start_depth < depth {
		let depth = start_depth + 1;
		if start_depth == 2 {
			let at = paths.entry(depth).or_default();
			for (to, mid) in to_from.iter() {
				let depth_paths: &mut HashMap<MixnetId, Vec<MixnetId>> = at.entry(*to).or_default();
				for mid in mid {
					if let Some(parents) = to_from.get(mid) {
						for from in parents.iter() {
							// avoid two identical node locally (paths still contains
							// redundant node in some of its paths but being
							// distributed in a balanced way we will just avoid those
							// on each hop random calculation.
							if from == to {
								continue
							}
							depth_paths.entry(*from).or_default().push(*mid);
						}
					}
				}
			}
		} else {
			let at = paths.entry(start_depth).or_default();
			let mut dest_at = HashMap::<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>::new();
			for (to, paths_to) in at.iter() {
				let depth_paths = dest_at.entry(*to).or_default();
				for (mid, _) in paths_to.iter() {
					if let Some(parents) = to_from.get(mid) {
						for from in parents.iter() {
							if from == to {
								continue
							}
							depth_paths.entry(*from).or_default().push(*mid);
						}
					}
				}
			}
			paths.insert(depth, dest_at);
		}
		start_depth += 1;
	}
}

#[cfg(test)]
fn paths_mem_size(
	paths: &BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
) -> usize {
	// approximate and slow, just to get idea in test. TODO update when switching paths to use
	// indexes as ptr.
	let mut size = 0;
	for paths in paths.iter() {
		size += 8; // usize
		for paths in paths.1.iter() {
			size += 32;
			for paths in paths.1.iter() {
				size += 32;
				for _ in paths.1.iter() {
					size += 32;
				}
			}
		}
	}
	size
}

fn should_connect_to(
	from: &MixnetId,
	allowed_routing: &BTreeSet<MixnetId>,
	nb: usize,
) -> Vec<MixnetId> {
	// TODO cache common seed when all got init
	// or/and have something faster
	let mut common_seed = [0u8; 32];
	for id in allowed_routing.iter() {
		let hash = crate::core::hash(id);
		for i in 0..32 {
			common_seed[i] ^= hash[i];
		}
	}
	let mut hash = crate::core::hash(from);
	for i in 0..32 {
		hash[i] ^= common_seed[i];
	}

	let mut allowed: Vec<_> = allowed_routing.iter().filter(|a| a != &from).collect();
	let mut nb_allowed = allowed.len();
	let mut result = Vec::with_capacity(std::cmp::min(nb, nb_allowed));
	let mut cursor = 0;
	while result.len() < nb && nb_allowed > 0 {
		// TODO bit arith
		let mut nb_bytes = match nb_allowed {
			nb_allowed if nb_allowed <= u8::MAX as usize => 1,
			nb_allowed if nb_allowed <= u16::MAX as usize => 2,
			nb_allowed if nb_allowed < 1usize << 24 => 3,
			nb_allowed if nb_allowed < u32::MAX as usize => 4,
			_ => unimplemented!(),
		};
		let mut at = 0usize;
		loop {
			if let Some(next) = hash.get(cursor) {
				nb_bytes -= 1;
				at += (*next as usize) * (1usize << (8 * nb_bytes));
				cursor += 1;
				if nb_bytes == 0 {
					break
				}
			} else {
				cursor = 0;
				hash = crate::core::hash(&hash);
			}
		}
		at %= nb_allowed;
		result.push(*allowed.remove(at));
		nb_allowed = allowed.len();
	}
	result
}

fn random_path_inner(
	rng: &mut rand::rngs::ThreadRng,
	routes: &Vec<MixnetId>,
	skip: impl Fn(&MixnetId) -> bool,
) -> Option<MixnetId> {
	use rand::Rng;
	// Warning this assume that PeerId is a randomly distributed value.
	let ix: usize = match routes.len() {
		l if l <= u8::MAX as usize => rng.gen::<u8>() as usize,
		l if l <= u16::MAX as usize => rng.gen::<u16>() as usize,
		l if l <= u32::MAX as usize => rng.gen::<u32>() as usize,
		_ => rng.gen::<usize>(),
	};
	let ix = ix % routes.len();

	for key in routes[ix..].iter() {
		if !skip(key) {
			debug!(target: "mixnet", "Random route node");
			return Some(*key)
		}
	}
	for key in routes[..ix].iter() {
		if !skip(key) {
			debug!(target: "mixnet", "Random route node");
			return Some(*key)
		}
	}
	None
}

fn random_path(
	paths: &BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
	from: &MixnetId,
	to: &MixnetId,
	size_path: usize,
) -> Option<Vec<MixnetId>> {
	trace!(target: "mixnet", "routing from {:?}, to {:?}, path size {:?}", from, to, size_path);
	// TODO some minimal length??
	if size_path < 3 {
		return None
	}
	let mut rng = rand::thread_rng();
	let mut at = size_path;
	let mut exclude = HashSet::new();
	exclude.insert(*from);
	exclude.insert(*to);
	let mut result = Vec::<MixnetId>::with_capacity(size_path); // allocate two extra for case where a node is
															// appended front or/and back.
	result.push(*from);
	// TODO consider Vec instead of hashset (small nb elt)
	let mut touched = Vec::<HashSet<MixnetId>>::with_capacity(size_path - 2);
	touched.push(HashSet::new());
	while at > 2 {
		if let Some(paths) = result.last().and_then(|from| {
			paths.get(&at).and_then(|paths| paths.get(to)).and_then(|paths| paths.get(from))
		}) {
			if let Some(next) = random_path_inner(&mut rng, paths, |p| {
				exclude.contains(p) ||
					touched.last().map(|touched| touched.contains(p)).unwrap_or(false)
			}) {
				result.push(next);
				if let Some(touched) = touched.last_mut() {
					touched.insert(next);
				}
				touched.push(HashSet::new());
				exclude.insert(next);
				at -= 1;
				continue
			}
		}
		// dead end path
		if result.len() == 1 {
			return None
		}
		if let Some(child) = result.pop() {
			exclude.remove(&child);
			touched.pop();
			at += 1;
		}
	}
	result.remove(0); // TODO rewrite to avoid it.
	Some(result)
}

fn count_paths(
	paths: &BTreeMap<usize, HashMap<MixnetId, HashMap<MixnetId, Vec<MixnetId>>>>,
	from: &MixnetId,
	to: &MixnetId,
	size_path: usize,
) -> usize {
	let mut total = 0;
	let mut at = size_path;
	let mut exclude = HashSet::new();
	exclude.insert(*from);
	exclude.insert(*to);
	let mut result = Vec::<(MixnetId, usize)>::with_capacity(size_path); // allocate two extra for case where a node is
																	 // appended front or/and back.
	result.push((*from, 0));
	let mut touched = Vec::<HashSet<MixnetId>>::with_capacity(size_path - 2);
	touched.push(HashSet::new());
	loop {
		if let Some((paths, at_ix)) = result.last().and_then(|(from, at_ix)| {
			paths
				.get(&at)
				.and_then(|paths| paths.get(to))
				.and_then(|paths| paths.get(from))
				.map(|p| (p, *at_ix))
		}) {
			if let Some(next) = paths.get(at_ix).cloned() {
				if let Some((_, at_ix)) = result.last_mut() {
					*at_ix += 1;
				}
				if !exclude.contains(&next) &&
					!touched.last().map(|touched| touched.contains(&next)).unwrap_or(false)
				{
					if at == 3 {
						total += 1;
					} else {
						result.push((next, 0));
						if let Some(touched) = touched.last_mut() {
							touched.insert(next);
						};
						touched.push(HashSet::new());
						exclude.insert(next);
						at -= 1;
					}
					continue
				} else {
					continue
				}
			}
		}
		if result.len() == 1 {
			break
		}
		if let Some((child, _)) = result.pop() {
			exclude.remove(&child);
			touched.pop();
			at += 1;
		}
	}
	total
}

#[test]
fn test_fill_paths() {
	/*let nb_peers: u16 = 1000;
	let nb_forward = 10;
	let depth = 5;*/
	let nb_peers: u16 = 5;
	let nb_forward = 3;
	let depth = 4;

	let peers: Vec<[u8; 32]> = (0..nb_peers)
		.map(|i| {
			let mut id = [0u8; 32];
			id[0] = (i % 8) as u8;
			id[1] = (i / 8) as u8;
			id
		})
		.collect();
	let local_id = [255u8; 32];
	let allowed_routing: BTreeSet<_> =
		peers.iter().chain(std::iter::once(&local_id)).cloned().collect();

	let mut from_to: HashMap<MixnetId, Vec<MixnetId>> = Default::default();
	for p in peers.iter().chain(std::iter::once(&local_id)) {
		let tos = should_connect_to(p, &allowed_routing, nb_forward);
		from_to.insert(*p, tos);
	}
	let mut to_from: HashMap<MixnetId, Vec<MixnetId>> = Default::default();
	//	let from_to2: BTreeMap<_, _> = from_to.iter().map(|(k, v)|(k.clone(), v.clone())).collect();
	for (from, tos) in from_to.iter() {
		for to in tos.iter() {
			to_from.entry(*to).or_default().push(*from);
		}
	}
	//		let from_to = from_to.clone();
	//		let to_from = to_from.clone();
	let mut paths = BTreeMap::new();
	let paths_depth = 0;
	fill_paths_inner(to_from, &mut paths, paths_depth, depth);
	//	println!("{:?}", paths);
	println!("size {:?}", paths_mem_size(&paths));

	// there is a path but cycle on 0 (depth 4)
	//	assert!(random_path(&paths, &peers[0], &peers[1], depth).is_none());
	let nb_path = count_paths(&paths, &local_id, &peers[1], depth);
	println!("nb_path {:?}", nb_path);
	let path = random_path(&paths, &local_id, &peers[1], depth);
	if path.is_none() {
		assert_eq!(nb_path, 0);
	}
	println!("{:?}", path);
	let mut nb_reachable = 0;
	let mut med_nb_con = 0;
	for i in 1..nb_peers as usize {
		let path = random_path(&paths, &peers[0], &peers[i], depth);
		if path.is_some() {
			nb_reachable += 1;
		}
		let nb_path = count_paths(&paths, &peers[0], &peers[i], depth);
		med_nb_con += nb_path;
	}
	let med_nb_con = med_nb_con as f64 / (nb_peers as f64 - 1.0);
	let reachable = nb_reachable as f64 / (nb_peers as f64 - 1.0);
	println!("Reachable {:?}, Med nb {:?}", reachable, med_nb_con);
	//	panic!("to print");
}
