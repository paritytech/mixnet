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

use crate::{traits::Topology, Error, MixPeerId, MixPublicKey};
use log::{debug, error, trace};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

// TODO make private or remove when all related stat in mixnet crate
pub enum ConnectedKind {
	External,
	RoutingForward,
	RoutingReceive,
	RoutingReceiveForward,
}

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
	// TODO encode/decode
}

/// Configuration parameters for topology.
#[derive(Clone)]
pub struct Parameters {
	// limit to external connection
	pub max_external: Option<usize>,
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
	pub local_id: MixPeerId,

	// true when we are in routing set.
	routing: bool,

	// TODO put this stats in mixnet stats directly
	pub nb_connected_forward_routing: usize,
	pub nb_connected_receive_routing: usize,
	pub nb_connected_external: usize,

	// TODO put in authorities_tables??
	// TODO priv
	pub routing_table: AuthorityTable<C::Version>,

	// The connected nodes (for first hop use `authorities` joined `connected_nodes`).
	pub connected_nodes: HashMap<MixPeerId, ConnectedKind>,

	// All rooting peers are considered connected (when building message except first hop).
	// TODO rename potential_routing_peers_set
	authorities: BTreeSet<MixPeerId>,

	// TODO rename routing_peers
	// This is only routing authorities we got info for.
	authorities_tables: BTreeMap<MixPeerId, AuthorityTable<C::Version>>,

	default_num_hop: usize,

	target_bytes_per_seconds: usize,

	params: Parameters,

	// all path of a given size.
	// on every change to auth table this is cleared TODO make change synchronously to
	// avoid full calc every time.
	//
	// This assume topology is balanced, so we can just run random selection at each hop.
	// TODO check topology balancing and balance if needed (keeping only peers with right incoming
	// and outgoing?)
	// TODO find something better
	// TODO could replace HashMap by vec and use indices as ptr
	paths: BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
	paths_depth: usize,

	// Connection to peer that are more prioritary: attempt connect.
	// This is only used when `DISTRIBUTE_ROUTE` is true.
	should_connect_to: Vec<MixPeerId>,

	// Connection to peer that are more prioritary: attempt connect.
	// This is only used when `DISTRIBUTE_ROUTE` is true.
	should_connect_pending: HashMap<MixPeerId, (usize, bool)>, /* TODO audit usage of
	                                                            * should_connect,
	                                                            * TODO for stats.
	                                                            * does not looks very smart
	                                                            * peers not connected to other
	                                                            * peer when they should (may not
	                                                            * be their fault
	                                                            * but if number get big it is
	                                                            * still fishy).
	                                                            * disconnected_in_routing:
	                                                            * HashMap<MixPeerId,
	                                                            * Vec<MixPeerId>>, */
}

/// Current published view of an authority routing table.
///
/// Table is currently signed by ImOnline key.
/// TODO rename RoutingTable
/// TODO parametric version and is updated function
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AuthorityTable<V> {
	pub public_key: MixPublicKey,
	pub version: V,
	// TODO could put revision but change will be more costy to converge.
	// TODO or put revision in dht key, then on handshake you also pass revision and then crawl
	// over updates -> I kinda like that.
	// Actually would be easier with a `known_latest_revision` field with all known latest revision
	// so peers can easilly resolve dht key and next dht key (if none found, can still query from
	// 0). -> requires outside a Map MixPeerId to latest received revision, so we query other key.
	// Interesting in the sense we have one key on value, but would need to change a bit the dht
	// logic. -> actually may not be proper idea, one key and subsequent update, just need to
	// ensure we are using the latest version which for signed info is easy: ord (sessionid,
	// revision).
	// TODO could replace MixPeerId by index in list of authorities for compactness.
	pub connected_to: BTreeSet<MixPeerId>,
	pub receive_from: BTreeSet<MixPeerId>, /* incoming peer needed to check if published
	                                        * information
	                                        * is fresh. */
}

impl<C: Configuration> Topology for TopologyHashTable<C> {
	fn first_hop_nodes_external(
		&self,
		from: &MixPeerId,
		to: &MixPeerId,
	) -> Vec<(MixPeerId, MixPublicKey)> {
		// allow for all
		self.authorities_tables
			.iter()
			.filter(|(id, _key)| from != *id)
			.filter(|(id, _key)| to != *id)
			.filter(|(id, _key)| &self.local_id != *id)
			.filter(|(id, _key)| self.connected_nodes.contains_key(*id))
			.map(|(k, table)| (k.clone(), table.public_key.clone()))
			.collect()
	}

	fn is_first_node(&self, id: &MixPeerId) -> bool {
		// allow for all
		self.is_routing(id)
	}

	// TODO make random_recipient return path directly.
	fn random_recipient(
		&mut self,
		from: &MixPeerId,
		send_options: &crate::SendOptions,
	) -> Option<(MixPeerId, MixPublicKey)> {
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
					&self.authorities_tables,
					nb_hop,
				);
				let from_count = if !self.is_routing(from) {
					debug!(target: "mixnet", "external {:?}", from);
					// TODO should return path directly rather than random here that could be
					// different that path one -> then the check on count could be part of path
					// building
					let firsts = self.first_hop_nodes_external(from, &peer);
					if firsts.len() == 0 {
						return None
					}
					firsts[0].0.clone()
				} else {
					from.clone()
				};
				// TODO also count surbs??
				let nb_path = count_paths(&self.paths, &from_count, &peer, nb_hop);
				debug!(target: "mixnet", "Number path for dest {:?}.", nb_path);
				debug!(target: "mixnet", "{:?} to {:?}", from_count, peer);
				if nb_path >= C::LOW_MIXNET_PATHS {
					return self.authorities_tables.get(&peer).map(|keys| (peer, keys.public_key))
				} else {
					bad.insert(peer);
				}
			} else {
				debug!(target: "mixnet", "No random dest.");
				return None
			}
		}
	}

	/// For a given peer return a list of peers it is supposed to be connected to.
	/// Return `None` if peer is unknown to the topology.
	fn neighbors(&self, from: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>> {
		if !self.is_routing(from) {
			return None
		}
		if from == &self.local_id {
			Some(
				self.routing_table
					.connected_to
					.iter()
					.filter_map(|k| {
						self.authorities_tables
							.get(k)
							.map(|table| (k.clone(), table.public_key.clone()))
					})
					.collect(),
			)
		} else {
			// unused, random_paths directly implemented.
			unimplemented!()
		}
	}

	fn routing_to(&self, from: &MixPeerId, to: &MixPeerId) -> bool {
		if &self.local_id == from {
			if self.routing {
				self.routing_table.connected_to.contains(to)
			} else {
				false
			}
		} else {
			self.authorities_tables
				.get(from)
				.map(|table| table.connected_to.contains(to))
				.unwrap_or(false)
		}
	}

	fn random_path(
		&mut self,
		start_node: (&MixPeerId, Option<&MixPublicKey>),
		recipient_node: (&MixPeerId, Option<&MixPublicKey>),
		nb_chunk: usize,
		num_hops: usize,
		max_hops: usize,
		last_query_if_surb: Option<&Vec<(MixPeerId, MixPublicKey)>>,
	) -> Result<Vec<Vec<(MixPeerId, MixPublicKey)>>, Error> {
		// Diverging from default implementation (random from all possible paths), as `neighbor`
		// return same result for all routing peer building all possible path is not usefull.
		let mut add_start = None;
		let mut add_end = None;
		let start = if self.is_first_node(start_node.0) {
			start_node.0.clone()
		} else {
			trace!(target: "mixnet", "External node");
			if num_hops + 1 > max_hops {
				return Err(Error::TooManyHops)
			}

			let firsts = self.first_hop_nodes_external(start_node.0, recipient_node.0);
			if firsts.len() == 0 {
				return Err(Error::NoPath(Some(recipient_node.0.clone())))
			}
			let mut rng = rand::thread_rng();
			use rand::Rng;
			let n: usize = rng.gen_range(0..firsts.len());
			add_start = Some(firsts[n].clone());
			firsts[n].0.clone()
		};

		let recipient = if self.is_routing(recipient_node.0) {
			recipient_node.0.clone()
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
					rec.0.clone()
				} else {
					return Err(Error::NoPath(Some(recipient_node.0.clone())))
				}
			} else {
				return Err(Error::NoPath(Some(recipient_node.0.clone())))
			}
		};
		trace!(target: "mixnet", "number hop: {:?}", num_hops);
		Self::fill_paths(
			&self.local_id,
			&self.routing_table,
			&mut self.paths,
			&mut self.paths_depth,
			&self.authorities_tables,
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
				path.push((peer.clone(), key.clone()));
			}

			for peer_id in path_ids.into_iter() {
				if let Some(table) = self.authorities_tables.get(&peer_id) {
					path.push((peer_id, table.public_key.clone()));
				} else {
					error!(target: "mixnet", "node in routing_nodes must also be in connected_nodes");
					unreachable!("node in routing_nodes must also be in connected_nodes");
				}
			}
			if let Some(table) = self.authorities_tables.get(&recipient) {
				path.push((recipient.clone(), table.public_key.clone()));
			} else {
				if self.local_id == recipient {
					// surb reply
					path.push((self.local_id.clone(), self.routing_table.public_key.clone()));
				} else {
					error!(target: "mixnet", "Unknown recipient {:?}", recipient);
					return Err(Error::NotEnoughRoutingPeers)
				}
			}

			if let Some((peer, key)) = add_end {
				if let Some(key) = key {
					path.push((peer.clone(), key.clone()));
				} else {
					return Err(Error::NoPath(Some(recipient_node.0.clone())))
				}
			}
			result.push(path);
		}
		debug!(target: "mixnet", "Path: {:?}", result);
		Ok(result)
	}

	fn is_routing(&self, id: &MixPeerId) -> bool {
		if &self.local_id == id {
			self.routing
		} else {
			self.authorities.contains(id)
		}
	}

	fn connected(&mut self, peer_id: MixPeerId, _key: MixPublicKey) {
		// TODO extend in branch with a
		/*
				self.copy_connected_info_to_metrics();
				if let Some(info) = self.should_connect_pending.get_mut(&peer_id) {
					if info.1 == true {
						info.1 = false;
						self.refresh_connection_table();
					}
				}
		*/
		debug!(target: "mixnet", "Connected from internal");
		self.add_connected_peer(peer_id)
	}

	fn disconnected(&mut self, peer_id: &MixPeerId) {
		// TODO extedn in branch with
		/*
			self.copy_connected_info_to_metrics();
		if let Some(info) = self.should_connect_pending.get_mut(peer_id) {
			if info.1 == false {
				info.1 = true;
				self.refresh_connection_table();
			}
		}
		*/
		debug!(target: "mixnet", "Disconnected from internal");
		self.add_disconnected_peer(&peer_id);
	}

	fn bandwidth_external(&self, id: &MixPeerId) -> Option<(usize, usize)> {
		if !self.routing {
			if self.is_routing(id) {
				// expect surbs: TODO make it optional??
				return Some((1, 1))
			}
		}
		// TODO can cache this result (Option<Option<(usize, usize))

		// Equal bandwidth amongst connected peers.
		let nb_forward = self.nb_connected_forward_routing;
		let nb_receive = self.nb_connected_receive_routing;
		// TODO add parameter to indicate if for a new peer or an existing one.
		let nb_external = self.nb_connected_external + 1;

		let forward_bandwidth = ((C::EXTERNAL_BANDWIDTH.0 + C::EXTERNAL_BANDWIDTH.1) *
			nb_forward * self.target_bytes_per_seconds) /
			C::EXTERNAL_BANDWIDTH.1;
		let receive_bandwidth = nb_receive * self.target_bytes_per_seconds;

		let available_bandwidth = forward_bandwidth - receive_bandwidth;
		let available_per_external = available_bandwidth / nb_external;

		Some((available_per_external, self.target_bytes_per_seconds))
	}

	fn accept_peer(&self, local_id: &MixPeerId, peer_id: &MixPeerId) -> bool {
		if self.routing {
			self.routing_to(peer_id, local_id) ||
				self.routing_to(local_id, peer_id) ||
				(!self.is_routing(peer_id) &&
					self.nb_connected_external <
						self.params.max_external.unwrap_or(usize::MAX) &&
					self.bandwidth_external(peer_id).is_some())
		} else {
			// connect as many routing node as possible
			// TODO could use a different counter than nb_connected_external
			self.is_routing(peer_id) &&
				self.nb_connected_external < self.params.max_external.unwrap_or(usize::MAX)
		}
	}
}

impl<C: Configuration> TopologyHashTable<C> {
	/// Instantiate a new topology.
	pub fn new(
		local_id: MixPeerId,
		node_public_key: MixPublicKey,
		config: &crate::Config,
		params: Parameters,
		routing_table_version: C::Version,
	) -> Self {
		let routing_table = AuthorityTable {
			public_key: node_public_key,
			version: routing_table_version,
			connected_to: BTreeSet::new(),
			receive_from: BTreeSet::new(),
		};
		TopologyHashTable {
			local_id,
			authorities: BTreeSet::new(),
			connected_nodes: HashMap::new(),
			routing: false,
			authorities_tables: BTreeMap::new(),
			routing_table,
			paths: Default::default(),
			paths_depth: 0,
			//disconnected_in_routing: Default::default(),
			nb_connected_forward_routing: 0,
			nb_connected_receive_routing: 0,
			nb_connected_external: 0,
			target_bytes_per_seconds: config.target_bytes_per_second as usize,
			params,
			default_num_hop: config.num_hops as usize,
			should_connect_to: Default::default(),
			should_connect_pending: Default::default(),
		}
	}

	fn has_enough_nodes_to_send(&self) -> bool {
		if C::DISTRIBUTE_ROUTES {
			self.authorities_tables
				.iter()
				.filter(|(_, table)| table.connected_to.len() >= C::NUMBER_CONNECTED_FORWARD)
				.count() >= C::LOW_MIXNET_THRESHOLD
		} else {
			// all nodes are seen as live.
			self.authorities.len() >= C::LOW_MIXNET_THRESHOLD
		}
	}

	/// Is peer able to proxy.
	pub fn has_enough_nodes_to_proxy(&self) -> bool {
		self.authorities_tables.len() >= C::LOW_MIXNET_THRESHOLD
	}

	fn random_dest(&self, skip: impl Fn(&MixPeerId) -> bool) -> Option<MixPeerId> {
		use rand::RngCore;
		// Warning this assume that NetworkPeerId is a randomly distributed value.
		let mut ix = [0u8; 32];
		rand::thread_rng().fill_bytes(&mut ix[..]);

		trace!(target: "mixnet", "routing {:?}, ix {:?}", self.authorities_tables, ix);
		for (key, table) in self.authorities_tables.range(ix..) {
			// TODO alert on low receive_from
			if !skip(&key) && !(table.receive_from.len() < C::NUMBER_CONNECTED_BACKWARD) {
				debug!(target: "mixnet", "Random route node");
				return Some(key.clone())
			} else {
				debug!(target: "mixnet", "Skip {:?}, nb {:?}, {:?}", skip(&key), table.receive_from.len(), C::NUMBER_CONNECTED_BACKWARD);
			}
		}
		for (key, table) in self.authorities_tables.range(..ix).rev() {
			if !skip(&key) && !(table.receive_from.len() < C::NUMBER_CONNECTED_BACKWARD) {
				debug!(target: "mixnet", "Random route node");
				return Some(key.clone())
			} else {
				debug!(target: "mixnet", "Skip {:?}, nb {:?}, {:?}", skip(&key), table.receive_from.len(), C::NUMBER_CONNECTED_BACKWARD);
			}
		}
		None
	}

	// TODO Note that building this is rather brutal, could just make some
	// random selection already to reduce size (and refresh after x uses).
	fn fill_paths(
		local_id: &MixPeerId,
		local_routing: &AuthorityTable<C::Version>,
		paths: &mut BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
		paths_depth: &mut usize,
		authorities_tables: &BTreeMap<MixPeerId, AuthorityTable<C::Version>>,
		depth: usize,
	) {
		if &depth <= paths_depth {
			return
		}
		// TODO not strictly needed (all in authorities_tables), convenient to exclude local id..
		//		let mut from_to = HashMap::<MixPeerId, Vec<MixPeerId>>::new();
		// TODO not strictly needed (all in authorities_tables), convenient to exclude local id.
		let mut to_from = HashMap::<MixPeerId, Vec<MixPeerId>>::new();

		for (from, table) in
			authorities_tables.iter().chain(std::iter::once((local_id, local_routing)))
		{
			// TODO change if limitting size of receive_from
			to_from.insert(from.clone(), table.receive_from.iter().cloned().collect());
		}

		fill_paths_inner(to_from, paths, *paths_depth, depth);
		if *paths_depth < depth {
			*paths_depth = depth;
		}
	}

	pub fn add_connected_peer(&mut self, peer_id: MixPeerId) {
		debug!(target: "mixnet", "Connected to mixnet {:?}", peer_id);
		if let Some(_) = self.connected_nodes.get_mut(&peer_id) {
			return
		}
		let kind = if self.is_routing(&peer_id) {
			if !self.routing {
				self.nb_connected_external += 1;
				ConnectedKind::External
			} else if self.routing_to(&self.local_id, &peer_id) {
				self.nb_connected_forward_routing += 1;
				if self.routing_to(&peer_id, &self.local_id) {
					self.nb_connected_receive_routing += 1;
					ConnectedKind::RoutingReceiveForward
				} else {
					ConnectedKind::RoutingForward
				}
			} else if self.routing_to(&peer_id, &self.local_id) {
				self.nb_connected_receive_routing += 1;
				ConnectedKind::RoutingReceive
			} else {
				self.nb_connected_external += 1;
				ConnectedKind::External
			}
		} else {
			self.nb_connected_external += 1;
			ConnectedKind::External
		};
		self.connected_nodes.insert(peer_id, kind);

		if C::DISTRIBUTE_ROUTES {
			if let Some(info) = self.should_connect_pending.get_mut(&peer_id) {
				if info.1 == true {
					info.1 = false;
					self.refresh_self_routing_table();
				}
			}
		}
	}

	fn add_disconnected_peer(&mut self, peer_id: &MixPeerId) {
		debug!(target: "mixnet", "Disconnected from mixnet {:?}", peer_id);
		if let Some(kind) = self.connected_nodes.remove(peer_id) {
			match kind {
				ConnectedKind::External => {
					self.nb_connected_external -= 1;
				},
				ConnectedKind::RoutingReceive => {
					self.nb_connected_receive_routing -= 1;
				},
				ConnectedKind::RoutingForward => {
					self.nb_connected_forward_routing -= 1;
				},
				ConnectedKind::RoutingReceiveForward => {
					self.nb_connected_forward_routing -= 1;
					self.nb_connected_receive_routing -= 1;
				},
			}

			if C::DISTRIBUTE_ROUTES {
				if let Some(info) = self.should_connect_pending.get_mut(peer_id) {
					if info.1 == false {
						info.1 = true;
						self.refresh_self_routing_table();
					}
				}
			}
		}
	}

	fn handle_new_routing_set_start<'a>(
		&mut self,
		set: impl Iterator<Item = &'a MixPeerId>,
		new_self: Option<(Option<MixPeerId>, Option<MixPublicKey>)>,
	) {
		debug!(target: "mixnet", "Handle new routing set.");
		if let Some((id, pub_key)) = new_self {
			id.map(|id| {
				self.local_id = id;
			});
			pub_key.map(|pub_key| {
				self.routing_table.public_key = pub_key;
			});
		}

		self.authorities.clear();
		self.authorities_tables.clear();
		self.routing = false;

		for peer_id in set {
			self.authorities.insert(peer_id.clone());
			if &self.local_id == peer_id {
				debug!(target: "mixnet", "In new routing set, routing.");
				self.routing = true;
			}
		}
	}

	fn handle_new_routing_set_end(&mut self) {
		let connected = std::mem::take(&mut self.connected_nodes);
		self.nb_connected_forward_routing = 0;
		self.nb_connected_receive_routing = 0;
		self.nb_connected_external = 0;
		// TODO	extend branch with		self.copy_connected_info_to_metrics();
		for peer_id in connected.into_iter() {
			self.add_connected_peer(peer_id.0);
		}
	}

	pub fn handle_new_routing_distributed(
		&mut self,
		set: &[MixPeerId],
		new_self: Option<(Option<MixPeerId>, Option<MixPublicKey>)>,
		version: C::Version,
	) {
		assert!(C::DISTRIBUTE_ROUTES);
		self.handle_new_routing_set_start(set.iter(), new_self);
		self.should_connect_to = should_connect_to(&self.local_id, &self.authorities, usize::MAX);
		for (index, id) in self.should_connect_to.iter().enumerate() {
			self.should_connect_pending.insert(id.clone(), (index, true));
		}
		debug!(target: "mixnet", "should connect to {:?}", self.should_connect_to);
		self.routing_table.version = version;
		self.refresh_self_routing_table();
		self.handle_new_routing_set_end();
	}

	pub fn handle_new_routing_set(
		&mut self,
		set: &[(MixPeerId, MixPublicKey)],
		new_self: Option<(Option<MixPeerId>, Option<MixPublicKey>)>,
	) {
		assert!(!C::DISTRIBUTE_ROUTES);
		self.handle_new_routing_set_start(set.iter().map(|k| &k.0), new_self);
		self.refresh_static_routing_tables(set);
		self.handle_new_routing_set_end();
	}

	pub fn handle_new_self_key(&mut self) {
		unimplemented!("rotate key");
	}

	pub fn receive_new_routing_table(
		&mut self,
		with: MixPeerId,
		new_table: AuthorityTable<C::Version>,
	) {
		if with == self.local_id {
			// ignore
			return
		}
		let mut insert = true;
		if let Some(table) = self.authorities_tables.get(&with) {
			if new_table.version <= table.version {
				log::debug!(target: "mixnet", "Not updated routes: {:?}", self.authorities_tables);
				// TODO old tables should lower dht peer prio.
				insert = false;
			}
		}
		if insert {
			// TODO sanity check of table (not connected to too many peers), ~ consistent with
			// peer neighbors (at least from the connected one we know)...
			// TODO number of non connected neighbor that should be.
			self.authorities_tables.insert(with, new_table);
			self.paths.clear();
			self.paths_depth = 0;
			log::debug!(target: "mixnet", "current routes: {:?}", self.authorities_tables);
		}
	}

	fn refresh_self_routing_table(&mut self) {
		let past = self.routing_table.clone();
		self.routing_table.connected_to.clear(); // TODO update a bit more precise
		for peer in self.should_connect_to.iter() {
			if let Some(info) = self.should_connect_pending.get(peer) {
				if info.1 == false {
					self.routing_table.connected_to.insert(peer.clone());
				}
			}
			if self.routing_table.connected_to.len() == C::NUMBER_CONNECTED_FORWARD {
				break
			}
		}
		self.routing_table.receive_from.clear(); // TODO update a bit more precise
		for (peer_id, table) in self.authorities_tables.iter() {
			if table.connected_to.contains(&self.local_id) {
				self.routing_table.receive_from.insert(peer_id.clone());
			}
		}

		if past != self.routing_table {
			self.routing_table.version.register_change();
			self.paths.clear();
			self.paths_depth = 0;
		}
	}

	fn refresh_static_routing_tables(&mut self, set: &[(MixPeerId, MixPublicKey)]) {
		for (auth, public_key) in set.iter() {
			if auth == &self.local_id {
				if let Some(table) = Self::refresh_connection_table_to(
					auth,
					public_key,
					Some(&self.routing_table),
					&self.authorities,
				) {
					self.routing_table = table;
					self.paths.clear();
					self.paths_depth = 0;
				}
			} else {
				let past = self.authorities_tables.get(auth);
				if let Some(table) =
					Self::refresh_connection_table_to(auth, public_key, past, &self.authorities)
				{
					self.authorities_tables.insert(auth.clone(), table);
					self.paths.clear();
					self.paths_depth = 0;
				}
			}
		}

		for auth in self.authorities.iter() {
			if auth == &self.local_id {
				if let Some(from) = Self::refresh_connection_table_from(
					auth,
					&self.routing_table.receive_from,
					self.authorities_tables.iter(),
				) {
					self.routing_table.receive_from = from;
				}
			} else {
				if let Some(routing_table) = self.authorities_tables.get(auth) {
					if let Some(from) = Self::refresh_connection_table_from(
						auth,
						&routing_table.receive_from,
						self.authorities_tables
							.iter()
							.chain(std::iter::once((&self.local_id, &self.routing_table))),
					) {
						if let Some(routing_table) = self.authorities_tables.get_mut(auth) {
							routing_table.receive_from = from;
						}
					}
				}
			}
		}
	}

	fn refresh_connection_table_to(
		from: &MixPeerId,
		from_key: &MixPublicKey,
		past: Option<&AuthorityTable<C::Version>>,
		authorities: &BTreeSet<MixPeerId>,
	) -> Option<AuthorityTable<C::Version>> {
		let tos = should_connect_to(from, authorities, C::NUMBER_CONNECTED_FORWARD);
		let mut routing_table = AuthorityTable {
			public_key: from_key.clone(),
			version: Default::default(), // No version when refreshing from peer set only
			connected_to: Default::default(),
			receive_from: Default::default(),
		};
		for peer in tos.into_iter() {
			// consider all connected
			routing_table.connected_to.insert(peer);
			if routing_table.connected_to.len() == C::NUMBER_CONNECTED_FORWARD {
				break
			}
		}

		(past != Some(&routing_table)).then(|| routing_table)
	}

	fn refresh_connection_table_from<'a>(
		from: &MixPeerId,
		past: &BTreeSet<MixPeerId>,
		authorities_tables: impl Iterator<Item = (&'a MixPeerId, &'a AuthorityTable<C::Version>)>,
	) -> Option<BTreeSet<MixPeerId>> {
		let mut receive_from = BTreeSet::default();
		for (peer_id, table) in authorities_tables {
			if table.connected_to.contains(from) {
				receive_from.insert(peer_id.clone());
			}
		}

		(past != &receive_from).then(|| receive_from)
	}
}

fn fill_paths_inner(
	to_from: HashMap<MixPeerId, Vec<MixPeerId>>,
	paths: &mut BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
	paths_depth: usize,
	depth: usize,
) {
	let mut start_depth = std::cmp::max(2, paths_depth);
	while start_depth < depth {
		let depth = start_depth + 1;
		if start_depth == 2 {
			let at = paths.entry(depth).or_default();
			for (to, mid) in to_from.iter() {
				let depth_paths: &mut HashMap<MixPeerId, Vec<MixPeerId>> =
					at.entry(to.clone()).or_default();
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
							depth_paths.entry(from.clone()).or_default().push(mid.clone());
						}
					}
				}
			}
		} else {
			let at = paths.entry(start_depth).or_default();
			let mut dest_at = HashMap::<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>::new();
			for (to, paths_to) in at.iter() {
				let depth_paths = dest_at.entry(to.clone()).or_default();
				for (mid, _) in paths_to.iter() {
					if let Some(parents) = to_from.get(mid) {
						for from in parents.iter() {
							if from == to {
								continue
							}
							depth_paths.entry(from.clone()).or_default().push(mid.clone());
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
	paths: &BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
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
	from: &MixPeerId,
	authorities: &BTreeSet<MixPeerId>,
	nb: usize,
) -> Vec<MixPeerId> {
	// TODO cache common seed when all_auth got init
	let mut common_seed = [0u8; 32];
	for auth in authorities.iter() {
		let hash = crate::core::hash(auth);
		for i in 0..32 {
			common_seed[i] ^= hash[i];
		}
	}
	let mut hash = crate::core::hash(from);
	for i in 0..32 {
		hash[i] ^= common_seed[i];
	}

	let mut auths: Vec<_> = authorities
		.iter()
		.filter_map(|a| if a != from { Some(a) } else { None })
		.collect();
	let mut nb_auth = auths.len();
	let mut result = Vec::with_capacity(std::cmp::min(nb, nb_auth));
	let mut cursor = 0;
	while result.len() < nb && nb_auth > 0 {
		// TODO bit arith
		let mut nb_bytes = match nb_auth {
			nb_auth if nb_auth <= u8::MAX as usize => 1,
			nb_auth if nb_auth <= u16::MAX as usize => 2,
			nb_auth if nb_auth < 1usize << 24 => 3,
			nb_auth if nb_auth < u32::MAX as usize => 4,
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
		at = at % nb_auth;
		result.push(auths.remove(at).clone());
		nb_auth = auths.len();
	}
	result
}

fn random_path_inner(
	rng: &mut rand::rngs::ThreadRng,
	routes: &Vec<MixPeerId>,
	skip: impl Fn(&MixPeerId) -> bool,
) -> Option<MixPeerId> {
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
		if !skip(&key) {
			debug!(target: "mixnet", "Random route node");
			return Some(key.clone())
		}
	}
	for key in routes[..ix].iter() {
		if !skip(key) {
			debug!(target: "mixnet", "Random route node");
			return Some(key.clone())
		}
	}
	None
}

fn random_path(
	paths: &BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
	from: &MixPeerId,
	to: &MixPeerId,
	size_path: usize,
) -> Option<Vec<MixPeerId>> {
	trace!(target: "mixnet", "routing from {:?}, to {:?}, path size {:?}", from, to, size_path);
	// TODO some minimal length??
	if size_path < 3 {
		return None
	}
	let mut rng = rand::thread_rng();
	let mut at = size_path;
	let mut exclude = HashSet::new();
	exclude.insert(from.clone());
	exclude.insert(to.clone());
	let mut result = Vec::<MixPeerId>::with_capacity(size_path); // allocate two extra for case where a node is
															 // appended front or/and back.
	result.push(from.clone());
	// TODO consider Vec instead of hashset (small nb elt)
	let mut touched = Vec::<HashSet<MixPeerId>>::with_capacity(size_path - 2);
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
				touched.last_mut().map(|touched| {
					touched.insert(next);
				});
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
	paths: &BTreeMap<usize, HashMap<MixPeerId, HashMap<MixPeerId, Vec<MixPeerId>>>>,
	from: &MixPeerId,
	to: &MixPeerId,
	size_path: usize,
) -> usize {
	let mut total = 0;
	let mut at = size_path;
	let mut exclude = HashSet::new();
	exclude.insert(from.clone());
	exclude.insert(to.clone());
	let mut result = Vec::<(MixPeerId, usize)>::with_capacity(size_path); // allocate two extra for case where a node is
																	  // appended front or/and back.
	result.push((from.clone(), 0));
	let mut touched = Vec::<HashSet<MixPeerId>>::with_capacity(size_path - 2);
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
				result.last_mut().map(|(_, at_ix)| {
					*at_ix += 1;
				});
				if !exclude.contains(&next) &&
					!touched.last().map(|touched| touched.contains(&next)).unwrap_or(false)
				{
					if at == 3 {
						total += 1;
					} else {
						result.push((next, 0));
						touched.last_mut().map(|touched| {
							touched.insert(next);
						});
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
	let authorities: BTreeSet<_> =
		peers.iter().chain(std::iter::once(&local_id)).cloned().collect();

	/*	let from_to: HashMap<MixPeerId, Vec<MixPeerId>> = vec![
		(peers[0].clone(), vec![peers[1].clone(), peers[2].clone()]),
		(peers[1].clone(), vec![peers[3].clone(), peers[4].clone()]),
		(peers[2].clone(), vec![peers[0].clone(), peers[4].clone()]),
	]
	.into_iter()
	.collect();*/

	let mut from_to: HashMap<MixPeerId, Vec<MixPeerId>> = Default::default();
	for p in peers.iter().chain(std::iter::once(&local_id)) {
		let tos = should_connect_to(p, &authorities, nb_forward);
		from_to.insert(p.clone(), tos);
	}
	let mut to_from: HashMap<MixPeerId, Vec<MixPeerId>> = Default::default();
	//	let from_to2: BTreeMap<_, _> = from_to.iter().map(|(k, v)|(k.clone(), v.clone())).collect();
	for (from, tos) in from_to.iter() {
		for to in tos.iter() {
			to_from.entry(to.clone()).or_default().push(from.clone());
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
