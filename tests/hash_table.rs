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

//! TopologyHashTable tests.

mod common;

use ambassador::Delegate;
use common::{
	new_routing_set, send_messages, wait_on_connections, wait_on_messages, PublishConf, SendConf,
	SimpleHandshake, TestConfig,
};
use libp2p_core::PeerId;
use mixnet::{
	ambassador_impl_Topology,
	traits::{
		hash_table::{
			Configuration as TopologyConfig, Parameters, RoutingTable, TopologyHashTable,
		},
		NewRoutingSet, ShouldConnectTo, Topology,
	},
	Error, MixPublicKey, MixSecretKey, MixnetId, NetworkId, PeerCount, SendOptions,
};
use rand::RngCore;
use std::{
	collections::{BTreeMap, BTreeSet},
	sync::Arc,
	time::Duration,
};

impl TopologyConfig for NotDistributed {
	type Version = common::Version;

	const DISTRIBUTE_ROUTES: bool = false;

	const LOW_MIXNET_THRESHOLD: usize = 4;

	const LOW_MIXNET_PATHS: usize = 2;

	const NUMBER_CONNECTED_FORWARD: usize = 4;

	const NUMBER_LAYER: u8 = 3;

	const MIN_LAYER_SIZE: usize = 6;

	const NUMBER_CONNECTED_BACKWARD: usize = Self::NUMBER_CONNECTED_FORWARD - 2;

	const EXTERNAL_BANDWIDTH: (usize, usize) = (1, 10);

	// TODO debug for number_consumer_connection only 1
	const DEFAULT_PARAMETERS: Parameters =
		Parameters { max_external: Some(1), number_consumer_connection: Some(3) };

	fn encode_infos(infos: &RoutingTable<Self::Version>) -> Vec<u8> {
		Vec::new()
	}

	fn decode_infos(_: &[u8]) -> Option<RoutingTable<Self::Version>> {
		None
	}
}

impl TopologyConfig for Distributed {
	type Version = common::Version;

	const DISTRIBUTE_ROUTES: bool = true;

	const LOW_MIXNET_THRESHOLD: usize = 4;

	const LOW_MIXNET_PATHS: usize = 2;

	const NUMBER_CONNECTED_FORWARD: usize = 4;

	const NUMBER_LAYER: u8 = 3;

	const MIN_LAYER_SIZE: usize = 6;

	const NUMBER_CONNECTED_BACKWARD: usize = Self::NUMBER_CONNECTED_FORWARD - 2;

	const EXTERNAL_BANDWIDTH: (usize, usize) = (1, 10);

	// TODO debug for number_consumer_connection only 1
	const DEFAULT_PARAMETERS: Parameters =
		Parameters { max_external: Some(1), number_consumer_connection: Some(3) };

	fn encode_infos(infos: &RoutingTable<Self::Version>) -> Vec<u8> {
		use codec::Encode;
		common::EncodableAuthorityTable(infos).encode()
	}

	fn decode_infos(mut encoded: &[u8]) -> Option<RoutingTable<Self::Version>> {
		use codec::Decode;
		common::DecodableAuthorityTable::decode(&mut encoded).ok().map(|t| t.0)
	}
}

#[derive(Delegate)]
#[delegate(Topology)]
struct NotDistributed {
	inner: SimpleHandshake<TopologyHashTable<Self>>,
}

impl From<SimpleHandshake<TopologyHashTable<NotDistributed>>> for NotDistributed {
	fn from(inner: SimpleHandshake<TopologyHashTable<NotDistributed>>) -> Self {
		NotDistributed { inner }
	}
}

impl mixnet::traits::Configuration for NotDistributed {
	fn collect_windows_stats(&self) -> bool {
		true
	}

	fn window_stats(&self, _stats: &mixnet::WindowStats, _: &PeerCount) {}

	fn peer_stats(&self, _: &PeerCount) {}
}

impl mixnet::traits::Handshake for NotDistributed {
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

#[derive(Delegate)]
#[delegate(Topology)]
struct Distributed {
	inner: SimpleHandshake<TopologyHashTable<Self>>,
}

impl From<SimpleHandshake<TopologyHashTable<Distributed>>> for Distributed {
	fn from(inner: SimpleHandshake<TopologyHashTable<Distributed>>) -> Self {
		Distributed { inner }
	}
}

impl mixnet::traits::Configuration for Distributed {
	fn collect_windows_stats(&self) -> bool {
		true
	}

	fn window_stats(&self, _stats: &mixnet::WindowStats, _: &PeerCount) {}

	fn peer_stats(&self, _: &PeerCount) {}
}

impl mixnet::traits::Handshake for Distributed {
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

fn test_messages<
	C: TopologyConfig + mixnet::traits::Configuration + From<SimpleHandshake<TopologyHashTable<C>>>,
>(
	conf: TestConfig,
) {
	let TestConfig { num_peers, message_size, from_external, random_dest, publish, .. } = conf;

	let seed: u64 = 0;
	let single_thread = true;
	let (public_key, secret_key) = mixnet::generate_new_keys();
	let average_message_delay_ms = 50;
	let target_bytes_per_second = 16 * 1024; // for release 64 * 1024
	let packet_duration_ms = mixnet::PACKET_SIZE as u64 * 1_000 / target_bytes_per_second as u64;
	let graceful_topology_change_period_ms =
		(conf.num_hops + 1) as u64 * (average_message_delay_ms as u64 + packet_duration_ms) * 2;
	let config_proto = mixnet::Config {
		secret_key,
		public_key,
		local_id: Default::default(),
		target_bytes_per_second,
		// usually only need to be low value for high bandwidth in debug mode and not in single
		// thread
		no_yield_budget: 32,
		timeout_ms: 10000,
		num_hops: conf.num_hops,
		average_message_delay_ms,
		graceful_topology_change_period_ms,
		queue_message_unconnected_ms: 0,
		queue_message_unconnected_number: 0,
		persist_surb_query: false,
		replay_ttl_ms: 100_000,
		surb_ttl_ms: 100_000,
		window_size_ms: 2_000,
		keep_handshaken_disconnected_address: true,
		receive_margin_ms: None,
	};
	let mut source_message = Vec::new();
	use rand::SeedableRng;
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	source_message.resize(message_size, 0);
	rng.fill_bytes(&mut source_message);
	let source_message = &source_message;

	let executor = log_unwrap!(futures::executor::ThreadPool::new());
	let expect_all_connected = false;
	let make_topo = move |p: usize,
	                      network_id: PeerId,
	                      nodes: &[(MixnetId, MixPublicKey)],
	                      secrets: &[(MixSecretKey, ed25519_zebra::SigningKey)],
	                      config: &mixnet::Config| {
		let mut topo = TopologyHashTable::new(
			nodes[p].0,
			nodes[p].1,
			C::DEFAULT_PARAMETERS.clone(),
			Default::default(),
		);
		topo.handle_new_routing_set(NewRoutingSet { peers: &nodes[..num_peers] });
		let mix_secret_key = secrets[p].1;
		let mix_public_key: ed25519_zebra::VerificationKey = (&mix_secret_key).into();

		let inner = SimpleHandshake {
			local_id: Some(config.local_id),
			local_network_id: Some(network_id),
			topo,
			mix_secret_key: Some(Arc::new((mix_secret_key, mix_public_key))),
		};
		inner.into()
	};

	let (handles, _) = common::spawn_swarms(
		num_peers,
		from_external,
		&executor,
		&mut rng,
		&config_proto,
		publish,
		make_topo,
	);

	let (nodes, mut with_swarm_channels) = common::spawn_workers::<C>(
		num_peers,
		from_external,
		expect_all_connected,
		handles,
		&executor,
		single_thread,
	);

	log::trace!(target: "mixnet_test", "before waiting connections");
	wait_on_connections(&conf, with_swarm_channels.as_mut());
	if C::DISTRIBUTE_ROUTES {
		// wait a bit on sync to get full path TODO should just wait on sends
		// returning no NoPath error
		std::thread::sleep(Duration::from_millis(1_000));
	}

	log::trace!(target: "mixnet_test", "after waiting connections");
	let send = if from_external {
		// ext 1 can route through peer 0 (only peer accepting ext)
		vec![SendConf { from: num_peers, to: Some(1), message: source_message.clone() }]
	} else if random_dest {
		vec![SendConf { from: 0, to: None, message: source_message.clone() }]
	} else {
		(1..num_peers)
			.map(|to| SendConf { from: 0, to: Some(to), message: source_message.clone() })
			.collect()
	};
	log::trace!(target: "mixnet_test", "before sending messages");
	send_messages(&conf, send.clone().into_iter(), &nodes, &mut with_swarm_channels);
	log::trace!(target: "mixnet_test", "after sending messages");
	wait_on_messages(&conf, send.into_iter(), &mut with_swarm_channels, b"pong");
}

#[test]
fn message_exchange_no_surb() {
	test_messages::<NotDistributed>(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 10,
		message_size: 1,
		with_surb: false,
		from_external: false,
		random_dest: false,
		publish: None,
	})
}

#[test]
fn fragmented_messages_no_surb() {
	test_messages::<NotDistributed>(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 1,
		message_size: 8 * 1024,
		with_surb: false,
		from_external: false,
		random_dest: false,
		publish: None,
	})
}

#[test]
fn message_exchange_with_surb() {
	test_messages::<NotDistributed>(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 10,
		message_size: 1,
		with_surb: true,
		from_external: false,
		random_dest: false,
		publish: None,
	})
}

#[test]
fn message_publish_with_surb() {
	test_messages::<Distributed>(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 10,
		message_size: 1,
		with_surb: true,
		from_external: false,
		random_dest: false,
		publish: Some(PublishConf {
			publish: Duration::from_millis(1000),
			publish_if_change: Duration::from_millis(100),
			query: Duration::from_millis(50),
		}),
	})
}

#[test]
fn fragmented_messages_with_surb() {
	test_messages::<NotDistributed>(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 1,
		message_size: 8 * 1024,
		with_surb: true,
		from_external: false,
		random_dest: false,
		publish: None,
	})
}

// #[test]
fn from_external_with_surb() {
	test_messages::<NotDistributed>(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 1,
		message_size: 100,
		with_surb: true,
		from_external: true,
		random_dest: false,
		publish: None,
	})
}

#[test]
fn from_external_no_surb2() {
	test_messages::<NotDistributed>(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 1,
		message_size: 4 * 1024,
		with_surb: false,
		from_external: true,
		random_dest: false,
		publish: None,
	})
}

#[test]
fn surb_and_layer_local() {
	for num_hops in 3..4 {
		test_messages::<NotDistributed>(TestConfig {
			num_peers: 15,
			num_hops,
			message_count: 1,
			message_size: 1,
			with_surb: true,
			from_external: false,
			random_dest: true,
			publish: None,
		})
	}
}

//#[test]
fn surb_and_layer_external() {
	test_messages::<NotDistributed>(TestConfig {
		num_peers: 20,
		num_hops: 4,
		message_count: 1,
		message_size: 1,
		with_surb: true,
		from_external: true,
		random_dest: true,
		publish: None,
	})
}

fn test_change_routing_set(conf: TestConfig) {
	let TestConfig { num_peers, message_size, from_external, random_dest, publish, .. } = conf;

	let set_1 = 0..num_peers;
	let half_set = num_peers / 2;
	// we change half the set, so raising numpeers by half
	let num_peers = num_peers + half_set;
	let set_2 = half_set..num_peers;

	let seed: u64 = 0;
	let single_thread = false;
	let (public_key, secret_key) = mixnet::generate_new_keys();
	let average_message_delay_ms = 50;
	let target_bytes_per_second = 16 * 1024; // for release 64 * 1024
	let packet_duration_ms = mixnet::PACKET_SIZE as u64 * 1_000 / target_bytes_per_second as u64;
	let graceful_topology_change_period_ms =
		(conf.num_hops + 1) as u64 * (average_message_delay_ms as u64 + packet_duration_ms) * 2;
	let config_proto = mixnet::Config {
		secret_key,
		public_key,
		local_id: Default::default(),
		target_bytes_per_second: 16 * 1024, // for release 64 * 1024
		// usually only need to be low value for high bandwidth in debug mode and not in single
		// thread
		no_yield_budget: 32,
		timeout_ms: 10000,
		num_hops: conf.num_hops,
		average_message_delay_ms,
		queue_message_unconnected_ms: 30_000, // just allow send before connecting
		queue_message_unconnected_number: 100,
		graceful_topology_change_period_ms,
		persist_surb_query: false,
		replay_ttl_ms: 100_000,
		surb_ttl_ms: 100_000,
		window_size_ms: 2_000,
		keep_handshaken_disconnected_address: true,
		receive_margin_ms: None,
	};
	let mut source_message = Vec::new();
	use rand::SeedableRng;
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	source_message.resize(message_size, 0);
	rng.fill_bytes(&mut source_message);
	let source_message = &source_message;

	let executor = log_unwrap!(futures::executor::ThreadPool::new());
	let expect_all_connected = false;

	let set_topo = set_1.clone();

	let disp = std::sync::atomic::AtomicBool::new(true);
	let make_topo = move |p: usize,
	                      network_id: PeerId,
	                      nodes: &[(MixnetId, MixPublicKey)],
	                      secrets: &[(MixSecretKey, ed25519_zebra::SigningKey)],
	                      config: &mixnet::Config| {
		if disp.swap(false, std::sync::atomic::Ordering::Relaxed) {
			log::trace!(target: "mixnet_test", "Topo_peers:");
			for p in nodes {
				log::trace!(target: "mixnet_test", "\t {:?}", p.0);
			}
		}
		let mut topo = TopologyHashTable::new(
			nodes[p].0,
			nodes[p].1,
			NotDistributed::DEFAULT_PARAMETERS.clone(),
			Default::default(),
		);
		topo.handle_new_routing_set(NewRoutingSet { peers: &nodes[set_topo.clone()] });
		let mix_secret_key = secrets[p].1;
		let mix_public_key: ed25519_zebra::VerificationKey = (&mix_secret_key).into();

		let inner = SimpleHandshake {
			local_id: Some(config.local_id),
			local_network_id: Some(network_id),
			topo,
			mix_secret_key: Some(Arc::new((mix_secret_key, mix_public_key))),
		};
		NotDistributed { inner }
	};

	let (handles, initial_con) = common::spawn_swarms(
		num_peers,
		from_external,
		&executor,
		&mut rng,
		&config_proto,
		publish,
		make_topo,
	);

	let nodes_ids: Vec<_> = handles
		.iter()
		.map(|worker| (*worker.0.mixnet().local_id(), *worker.0.mixnet().public_key()))
		.collect();

	let (nodes, mut with_swarm_channels) = common::spawn_workers::<NotDistributed>(
		num_peers,
		from_external,
		expect_all_connected,
		handles,
		&executor,
		single_thread,
	);
	log::trace!(target: "mixnet_test", "set_1: {:?}", set_1);
	log::trace!(target: "mixnet_test", "set_2: {:?}", set_2);
	log::trace!(target: "mixnet_test", "before waiting connections");
	wait_on_connections(&conf, with_swarm_channels.as_mut());

	initial_con.store(true, std::sync::atomic::Ordering::Relaxed);

	log::trace!(target: "mixnet_test", "after waiting connections");
	let send = if from_external {
		// ext 1 can route through peer 0 (only peer accepting ext)
		vec![SendConf { from: num_peers, to: Some(1), message: source_message.clone() }]
	} else if random_dest {
		vec![SendConf { from: set_1.start, to: None, message: source_message.clone() }]
	} else {
		let start = set_1.start;
		let end = set_1.end;
		(set_1)
			.map(|from| SendConf {
				from,
				to: Some(if from + 1 == end { start } else { from + 1 }),
				message: source_message.clone(),
			})
			.collect()
	};
	log::trace!(target: "mixnet_test", "before sending messages");
	send_messages(&conf, send.clone().into_iter(), &nodes, &mut with_swarm_channels);
	log::trace!(target: "mixnet_test", "after sending messages");
	wait_on_messages(&conf, send.into_iter(), &mut with_swarm_channels, b"pong");
	log::trace!(target: "mixnet_test", "success with first set, switching set");

	new_routing_set(&nodes_ids[set_2.clone()], &mut with_swarm_channels);

	log::trace!(target: "mixnet_test", "set switched");

	let send: Vec<_> = if from_external {
		// ext 1 can route through peer 0 (only peer accepting ext)
		// TODO implement connect for external on demand
		// vec![SendConf { from: num_peers, to: 1, message: source_message.clone() }]
		return
	} else if random_dest {
		vec![SendConf { from: set_2.start, to: None, message: source_message.clone() }]
	} else {
		let start = set_2.start;
		let end = set_2.end;
		(set_2)
			.map(|from| SendConf {
				from,
				to: Some(if from + 1 == end { start } else { from + 1 }),
				message: source_message.clone(),
			})
			.collect()
	};
	log::trace!(target: "mixnet_test", "before sending messages");
	send_messages(&conf, send.clone().into_iter(), &nodes, &mut with_swarm_channels);
	log::trace!(target: "mixnet_test", "after sending messages");
	wait_on_messages(&conf, send.into_iter(), &mut with_swarm_channels, b"pong");
}

#[test]
fn testing_mess() {
	test_change_routing_set(TestConfig {
		num_peers: 4,
		num_hops: 3,
		message_count: 2,
		message_size: 1, // max 256 * 1024
		with_surb: false,
		from_external: false,
		random_dest: false,
		publish: None,
	})
}
