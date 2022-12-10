// Copyright 2022 Parity Technologia (UK) Ltd.
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

//! All connected star tests.

mod common;

use common::{
	send_messages, wait_on_connections, wait_on_messages, SendConf, SimpleHandshake, TestConfig,
};
use libp2p_core::PeerId;
use rand::{prelude::IteratorRandom, Rng, RngCore};
use std::{
	collections::{BTreeMap, BTreeSet, HashMap},
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc,
	},
};

use ambassador::Delegate;
use mixnet::{
	ambassador_impl_Topology,
	traits::{NewRoutingSet, ShouldConnectTo, Topology},
	Error, MixPublicKey, MixSecretKey, MixnetId, NetworkId, PeerCount,
};

#[derive(Delegate)]
#[delegate(Topology)]
#[derive(Clone)]
struct ConfigGraph {
	inner: SimpleHandshake<TopologyGraph>,
}

#[derive(Clone)]
struct TopologyGraph {
	connections: HashMap<MixnetId, Vec<(MixnetId, MixPublicKey)>>,
	peers: Vec<(MixnetId, MixPublicKey)>,
	// allow single external
	external: Option<MixnetId>,
	nb_connected: Arc<AtomicUsize>,
	local_id: Option<MixnetId>,
	local_network_id: Option<PeerId>,
}

impl TopologyGraph {
	fn new_star(nodes: &[(MixnetId, MixPublicKey)]) -> Self {
		let mut connections = HashMap::new();
		for i in 0..nodes.len() {
			let (node, _node_key) = nodes[i];
			let mut neighbors = Vec::new();
			for (j, node) in nodes.iter().enumerate() {
				if i != j {
					neighbors.push(*node)
				}
			}
			connections.insert(node, neighbors);
		}

		Self {
			connections,
			peers: nodes.iter().map(Clone::clone).collect(),
			external: Default::default(),
			nb_connected: Arc::new(0.into()),
			local_id: None,
			local_network_id: None,
		}
	}
}

impl mixnet::traits::Configuration for ConfigGraph {
	fn collect_windows_stats(&self) -> bool {
		true
	}

	fn window_stats(&self, _stats: &mixnet::WindowStats, _: &PeerCount) {}

	fn peer_stats(&self, _: &PeerCount) {}
}

impl mixnet::traits::Handshake for ConfigGraph {
	fn handshake_size(&self) -> usize {
		self.inner.handshake_size()
	}

	fn check_handshake(&self, payload: &[u8], from: &PeerId) -> Option<(MixnetId, MixPublicKey)> {
		self.inner.check_handshake(payload, from)
	}

	fn handshake(&self, with: &PeerId, public_key: &MixPublicKey) -> Option<Vec<u8>> {
		self.inner.handshake(with, public_key)
	}
}

impl Topology for TopologyGraph {
	fn changed_route(&mut self) -> Option<BTreeSet<MixnetId>> {
		// no support for peer set change
		None
	}

	fn try_connect(&mut self) -> Option<BTreeMap<MixnetId, Option<NetworkId>>> {
		None
	}

	fn can_route(&self, id: &MixnetId) -> bool {
		self.connections.contains_key(id)
	}

	fn first_hop_nodes_external(
		&self,
		_from: &MixnetId,
		_to: Option<&MixnetId>,
		_num_hop: usize,
	) -> Vec<(MixnetId, MixPublicKey)> {
		// allow only with peer 0
		vec![self.peers[0]]
	}

	fn random_path(
		&mut self,
		start_node: (&MixnetId, Option<&MixPublicKey>),
		recipient_node: Option<(&MixnetId, Option<&MixPublicKey>)>,
		count: usize,
		num_hops: usize,
	) -> Result<Vec<Vec<(MixnetId, MixPublicKey)>>, Error> {
		let mut rng = rand::thread_rng();
		let start = &start_node.0;
		let recipient = if let Some(recipient_node) = recipient_node {
			if self.can_route(recipient_node.0) {
				*recipient_node.0
			} else {
				return Err(Error::NoPath(Some(*recipient_node.0)))
			}
		} else {
			self.peers
				.iter()
				.filter(|(k, _v)| k != start_node.0)
				.choose(&mut rand::thread_rng())
				.map(|(k, _)| *k)
				.ok_or(Error::NoPath(None))?
		};
		// Generate all possible paths and select one at random
		let mut partial = Vec::new();
		let mut paths = Vec::new();
		gen_paths(self, &mut partial, &mut paths, &start, &recipient, num_hops);

		if paths.is_empty() {
			return Err(Error::NoPath(Some(recipient)))
		}

		let mut result = Vec::with_capacity(count);
		while result.len() < count {
			let n: usize = rng.gen_range(0..paths.len());
			let mut path = paths[n].clone();
			result.push(path);
		}
		log::trace!(target: "mixnet", "Random path {:?}", result);
		Ok(result)
	}
	fn routing_to(&self, from: &MixnetId, to: &MixnetId) -> bool {
		if self.external.as_ref() == Some(to) {
			// this is partly incorrect as we also need to check that from is self.
			return self.local_id.as_ref() == Some(from)
		}
		self.connections
			.get(from)
			.and_then(|n| n.iter().find(|(p, _)| p == to))
			.is_some()
	}

	fn connected(&mut self, _: MixnetId, _: MixPublicKey) {
		self.nb_connected.fetch_add(1, Ordering::Relaxed);

		if self.nb_connected.load(Ordering::Relaxed) == self.connections.len() - 1 {
			log::info!("All connected");
		}
	}

	fn disconnected(&mut self, id: &MixnetId) {
		self.nb_connected.fetch_sub(1, Ordering::Relaxed);
		if self.external.as_ref() == Some(id) {
			self.external = None;
		}
	}

	fn accept_peer(&self, _peer_id: &MixnetId, _peers: &PeerCount) -> bool {
		self.local_id.is_some()
	}

	fn should_connect_to(&self) -> ShouldConnectTo {
		// no reco hanling in these tests
		ShouldConnectTo::empty()
	}

	fn handle_new_routing_set(&mut self, _set: NewRoutingSet) {
		// static set in these tests
	}
}

fn gen_paths(
	topology: &TopologyGraph,
	partial: &mut Vec<(MixnetId, MixPublicKey)>,
	paths: &mut Vec<Vec<(MixnetId, MixPublicKey)>>,
	last: &MixnetId,
	target: &MixnetId,
	num_hops: usize,
) {
	let neighbors = topology.connections.get(last).cloned().unwrap_or_default();
	for (id, key) in neighbors {
		if partial.len() < num_hops - 1 {
			partial.push((id, key));
			gen_paths(topology, partial, paths, &id, target, num_hops);
			partial.pop();
		}

		if partial.len() == num_hops - 1 {
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

fn test_messages(conf: TestConfig) {
	let TestConfig { num_peers, message_size, from_external, .. } = conf;

	let seed: u64 = 0;
	let single_thread = false;
	let (public_key, secret_key) = mixnet::generate_new_keys();
	let config_proto = mixnet::Config {
		secret_key,
		public_key,
		local_id: Default::default(),
		target_bytes_per_second: 16 * 1024, // 64 for release is fine
		no_yield_budget: 128,               // not needed for low bandwidth
		timeout_ms: 10000,
		num_hops: conf.num_hops,
		average_message_delay_ms: 50,
		persist_surb_query: false,
		replay_ttl_ms: 100_000,
		surb_ttl_ms: 100_000,
		window_size_ms: 2_000,
		graceful_topology_change_period_ms: 0,
		keep_handshaken_disconnected_address: true,
		queue_message_unconnected_ms: 0,
		queue_message_unconnected_number: 0,
		receive_margin_ms: None,
	};
	let mut source_message = Vec::new();
	use rand::SeedableRng;
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	source_message.resize(message_size, 0);
	rng.fill_bytes(&mut source_message);
	let source_message = &source_message;

	let executor = futures::executor::ThreadPool::new().unwrap();
	let expect_all_connected = true;

	let make_topo = move |p: usize,
	                      network_id: PeerId,
	                      nodes: &[(MixnetId, MixPublicKey)],
	                      secrets: &[(MixSecretKey, ed25519_zebra::SigningKey)],
	                      config: &mixnet::Config| {
		let mut topo = TopologyGraph::new_star(&nodes[..num_peers]);
		topo.local_id = Some(config.local_id);
		topo.local_network_id = Some(network_id);
		let mix_secret_key = secrets[p].1;
		let mix_public_key: ed25519_zebra::VerificationKey = (&mix_secret_key).into();
		let handshake = SimpleHandshake {
			local_id: Some(config.local_id),
			local_network_id: Some(network_id),
			topo,
			mix_secret_key: Some(Arc::new((mix_secret_key, mix_public_key))),
		};
		ConfigGraph { inner: handshake }
	};

	let (handles, _) = common::spawn_swarms(
		num_peers,
		from_external,
		&executor,
		&mut rng,
		&config_proto,
		make_topo,
	);

	let (nodes, mut with_swarm_channels) = common::spawn_workers::<ConfigGraph>(
		num_peers,
		from_external,
		expect_all_connected,
		handles,
		&executor,
		single_thread,
	);

	wait_on_connections(&conf, with_swarm_channels.as_mut());

	let send = if from_external {
		// ext 1 can route through peer 0 (only peer accepting ext)
		vec![SendConf { from: num_peers, to: Some(1), message: source_message.clone() }]
	} else {
		(1..num_peers)
			.map(|to| SendConf { from: 0, to: Some(to), message: source_message.clone() })
			.collect()
	};
	send_messages(&conf, send.clone().into_iter(), &nodes, &mut with_swarm_channels);
	wait_on_messages(&conf, send.into_iter(), &mut with_swarm_channels, b"pong");
}

#[test]
fn message_exchange_no_surb() {
	test_messages(TestConfig {
		num_peers: 5,
		num_hops: 3,
		message_count: 10,
		message_size: 1,
		with_surb: false,
		from_external: false,
		random_dest: false,
	})
}

#[test]
fn fragmented_messages_no_surb() {
	test_messages(TestConfig {
		num_peers: 2,
		num_hops: 3,
		message_count: 1,
		message_size: 8 * 1024,
		with_surb: false,
		from_external: false,
		random_dest: false,
	})
}

#[test]
fn message_exchange_with_surb() {
	test_messages(TestConfig {
		num_peers: 5,
		num_hops: 3,
		message_count: 10,
		message_size: 1,
		with_surb: true,
		from_external: false,
		random_dest: false,
	})
}

#[test]
fn fragmented_messages_with_surb() {
	test_messages(TestConfig {
		num_peers: 2,
		num_hops: 3,
		message_count: 1,
		message_size: 8 * 1024,
		with_surb: true,
		from_external: false,
		random_dest: false,
	})
}

#[test]
fn ext_fragmented_surbs() {
	test_messages(TestConfig {
		num_peers: 2,
		num_hops: 3,
		message_count: 1,
		message_size: 8 * 1024,
		with_surb: false,
		//with_surb: false, TODO -> true
		from_external: true,
		random_dest: false,
	})
}

//#[test]
fn from_external_with_surb() {
	test_messages(TestConfig {
		num_peers: 5,
		num_hops: 3,
		message_count: 1,
		message_size: 100,
		with_surb: true,
		from_external: true,
		random_dest: false,
	})
}

#[test]
fn from_external_no_surb() {
	test_messages(TestConfig {
		num_peers: 5,
		num_hops: 3,
		message_count: 1,
		message_size: 4 * 1024,
		with_surb: false,
		from_external: true,
		random_dest: false,
	})
}
