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
	send_messages, wait_on_connections, wait_on_messages, SendConf, SimpleHandshake, TestConfig,
};
use libp2p_core::PeerId;
use mixnet::ambassador_impl_Topology;
use parking_lot::RwLock;
use rand::RngCore;
use std::sync::Arc;

use mixnet::{
	traits::{
		hash_table::{Configuration as TopologyConfig, Parameters, TopologyHashTable},
		Topology,
	},
	Error, MixPeerId, MixPublicKey, MixSecretKey, PeerCount, SendOptions,
};

impl TopologyConfig for NotDistributed {
	type Version = ();

	const DISTRIBUTE_ROUTES: bool = false;

	const LOW_MIXNET_THRESHOLD: usize = 5;

	const LOW_MIXNET_PATHS: usize = 2;

	const NUMBER_CONNECTED_FORWARD: usize = 4;

	const NUMBER_CONNECTED_BACKWARD: usize = Self::NUMBER_CONNECTED_FORWARD - 2;

	const EXTERNAL_BANDWIDTH: (usize, usize) = (1, 10);

	const DEFAULT_PARAMETERS: Parameters = Parameters { max_external: Some(10) };
}

#[derive(Delegate)]
#[delegate(Topology)]
struct NotDistributed {
	inner: SimpleHandshake<TopologyHashTable<Self>>,
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

	fn check_handshake(
		&mut self,
		payload: &[u8],
		from: &PeerId,
		peers: &PeerCount,
	) -> Option<(MixPeerId, MixPublicKey)> {
		self.inner.check_handshake(payload, from, peers)
	}

	fn handshake(&mut self, with: &PeerId, public_key: &MixPublicKey) -> Option<Vec<u8>> {
		self.inner.handshake(with, public_key)
	}
}

#[derive(Clone)]
struct NotDistributedShared {
	inner: Arc<RwLock<SimpleHandshake<TopologyHashTable<NotDistributed>>>>,
}

impl mixnet::traits::Topology for NotDistributedShared {
	fn changed_routing(&mut self, with: &MixPeerId) -> bool {
		self.inner.write().changed_routing(with)
	}

	fn first_hop_nodes_external(
		&self,
		from: &MixPeerId,
		to: &MixPeerId,
	) -> Vec<(MixPeerId, MixPublicKey)> {
		self.inner.read().first_hop_nodes_external(from, to)
	}

	fn is_first_node(&self, id: &MixPeerId) -> bool {
		self.inner.read().is_first_node(id)
	}

	fn random_recipient(
		&mut self,
		from: &MixPeerId,
		send_options: &crate::SendOptions,
	) -> Option<(MixPeerId, MixPublicKey)> {
		self.inner.write().random_recipient(from, send_options)
	}

	fn routing_to(&self, from: &MixPeerId, to: &MixPeerId) -> bool {
		self.inner.read().routing_to(from, to)
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
		self.inner.write().random_path(
			start_node,
			recipient_node,
			nb_chunk,
			num_hops,
			max_hops,
			last_query_if_surb,
		)
	}

	fn can_route(&self, id: &MixPeerId) -> bool {
		self.inner.read().can_route(id)
	}

	fn connected(&mut self, peer_id: MixPeerId, key: MixPublicKey) {
		self.inner.write().connected(peer_id, key)
	}

	fn disconnected(&mut self, peer_id: &MixPeerId) {
		self.inner.write().disconnected(peer_id)
	}

	fn bandwidth_external(&self, id: &MixPeerId, peers: &PeerCount) -> Option<(usize, usize)> {
		self.inner.read().bandwidth_external(id, peers)
	}

	fn accept_peer(&self, peer_id: &MixPeerId, peers: &PeerCount) -> bool {
		self.inner.read().accept_peer(peer_id, peers)
	}
}

impl mixnet::traits::Configuration for NotDistributedShared {
	fn collect_windows_stats(&self) -> bool {
		true
	}

	fn window_stats(&self, _stats: &mixnet::WindowStats, _: &PeerCount) {}

	fn peer_stats(&self, _: &PeerCount) {}
}

impl mixnet::traits::Handshake for NotDistributedShared {
	fn handshake_size(&self) -> usize {
		self.inner.read().handshake_size()
	}

	fn check_handshake(
		&mut self,
		payload: &[u8],
		from: &PeerId,
		peers: &PeerCount,
	) -> Option<(MixPeerId, MixPublicKey)> {
		self.inner.write().check_handshake(payload, from, peers)
	}

	fn handshake(&mut self, with: &PeerId, public_key: &MixPublicKey) -> Option<Vec<u8>> {
		self.inner.write().handshake(with, public_key)
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
		target_bytes_per_second: 16 * 1024, // for release 64 * 1024
		// usually only need to be low value for high bandwidth in debug mode and not in single
		// thread
		no_yield_budget: 32,
		timeout_ms: 10000,
		num_hops: conf.num_hops,
		average_message_delay_ms: 50,
		persist_surb_query: false,
		replay_ttl_ms: 100_000,
		surb_ttl_ms: 100_000,
		window_size_ms: 2_000,
	};
	let mut source_message = Vec::new();
	use rand::SeedableRng;
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	source_message.resize(message_size, 0);
	rng.fill_bytes(&mut source_message);
	let source_message = &source_message;

	let executor = futures::executor::ThreadPool::new().unwrap();
	// 	mut make_topo: impl FnMut(&[(MixPeerId, MixPublicKey)], &Config) -> T,
	let (handles, mut with_swarm_channels) =
		common::spawn_swarms(num_peers, from_external, &executor, false);

	let make_topo = move |p: usize,
	                      network_id: PeerId,
	                      nodes: &[(MixPeerId, MixPublicKey)],
	                      secrets: &[(MixSecretKey, ed25519_zebra::SigningKey)],
	                      config: &mixnet::Config| {
		let mut topo = TopologyHashTable::new(
			nodes[p].0,
			nodes[p].1,
			config,
			NotDistributed::DEFAULT_PARAMETERS.clone(),
			(),
		);
		topo.handle_new_routing_set(&nodes[..num_peers], None);
		let mix_secret_key = secrets[p].1;
		let mix_public_key: ed25519_zebra::VerificationKey = (&mix_secret_key).into();

		let inner = SimpleHandshake {
			local_id: Some(config.local_id),
			local_network_id: Some(network_id),
			nb_external: 0,
			max_external: 1,
			topo,
			mix_secret_key: Some(Arc::new((mix_secret_key, mix_public_key))),
		};
		NotDistributed { inner }
	};
	let nodes = common::spawn_workers::<NotDistributed>(
		handles,
		&mut rng,
		&config_proto,
		make_topo,
		&executor,
		single_thread,
	);

	log::trace!(target: "mixnet_test", "before waiting connections");
	wait_on_connections(&conf, with_swarm_channels.as_mut());

	log::trace!(target: "mixnet_test", "after waiting connections");
	let send = if from_external {
		// ext 1 can route through peer 0 (only peer accepting ext)
		vec![SendConf { from: num_peers, to: 1, message: source_message.clone() }]
	} else {
		(1..num_peers)
			.map(|to| SendConf { from: 0, to, message: source_message.clone() })
			.collect()
	};
	log::trace!(target: "mixnet_test", "before sending messages");
	send_messages(&conf, send.clone().into_iter(), &nodes, &mut with_swarm_channels);
	log::trace!(target: "mixnet_test", "after sending messages");
	wait_on_messages(&conf, send.into_iter(), &mut with_swarm_channels, b"pong");
}

#[test]
fn message_exchange_no_surb() {
	test_messages(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 10,
		message_size: 1,
		with_surb: false,
		from_external: false,
	})
}

#[test]
fn fragmented_messages_no_surb() {
	test_messages(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 1,
		message_size: 8 * 1024,
		with_surb: false,
		from_external: false,
	})
}

#[test]
fn message_exchange_with_surb() {
	test_messages(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 10,
		message_size: 1,
		with_surb: true,
		from_external: false,
	})
}

#[test]
fn fragmented_messages_with_surb() {
	test_messages(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 1,
		message_size: 8 * 1024,
		with_surb: true,
		from_external: false,
	})
}

#[test]
fn from_external_with_surb() {
	test_messages(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 1,
		message_size: 100,
		with_surb: true,
		from_external: true,
	})
}

#[test]
fn from_external_no_surb() {
	test_messages(TestConfig {
		num_peers: 6,
		num_hops: 3,
		message_count: 1,
		message_size: 4 * 1024,
		with_surb: false,
		from_external: true,
	})
}

fn test_change_routing_set(conf: TestConfig) {
	let TestConfig { num_peers, message_size, from_external, .. } = conf;

	let set_1 = 0..num_peers;
	let half_set = num_peers / 2;
	// we change half the set, so raising numpeers by half
	let num_peers = num_peers + half_set;
	let set_2 = half_set..num_peers;

	let seed: u64 = 0;
	let single_thread = false;
	let (public_key, secret_key) = mixnet::generate_new_keys();
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
		average_message_delay_ms: 50,
		persist_surb_query: false,
		replay_ttl_ms: 100_000,
		surb_ttl_ms: 100_000,
		window_size_ms: 2_000,
	};
	let mut source_message = Vec::new();
	use rand::SeedableRng;
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	source_message.resize(message_size, 0);
	rng.fill_bytes(&mut source_message);
	let source_message = &source_message;

	let executor = futures::executor::ThreadPool::new().unwrap();
	let (handles, mut with_swarm_channels) =
		common::spawn_swarms(num_peers, from_external, &executor, false);

	let set_topo = set_1.clone();
	let mut handle_topos = Vec::new();
	let handle_topos_ptr = &mut handle_topos;

	let make_topo = move |p: usize,
	                      network_id: PeerId,
	                      nodes: &[(MixPeerId, MixPublicKey)],
	                      secrets: &[(MixSecretKey, ed25519_zebra::SigningKey)],
	                      config: &mixnet::Config| {
		let mut topo = TopologyHashTable::new(
			nodes[p].0,
			nodes[p].1,
			config,
			NotDistributed::DEFAULT_PARAMETERS.clone(),
			(),
		);
		topo.handle_new_routing_set(&nodes[set_topo.clone()], None);
		let mix_secret_key = secrets[p].1;
		let mix_public_key: ed25519_zebra::VerificationKey = (&mix_secret_key).into();

		let inner = SimpleHandshake {
			local_id: Some(config.local_id),
			local_network_id: Some(network_id),
			nb_external: 0,
			max_external: 1,
			topo,
			mix_secret_key: Some(Arc::new((mix_secret_key, mix_public_key))),
		};
		let inner = Arc::new(RwLock::new(inner));
		handle_topos_ptr.push(inner.clone());
		NotDistributedShared { inner }
	};
	let nodes = common::spawn_workers::<NotDistributedShared>(
		handles,
		&mut rng,
		&config_proto,
		make_topo,
		&executor,
		single_thread,
	);

	log::trace!(target: "mixnet_test", "before waiting connections");
	wait_on_connections(&conf, with_swarm_channels.as_mut());

	log::trace!(target: "mixnet_test", "after waiting connections");
	let send = if from_external {
		// ext 1 can route through peer 0 (only peer accepting ext)
		vec![SendConf { from: num_peers, to: 1, message: source_message.clone() }]
	} else {
		let start = set_1.start;
		let end = set_1.end;
		(set_1)
			.map(|from| SendConf {
				from,
				to: if from + 1 == end { start } else { from + 1 },
				message: source_message.clone(),
			})
			.collect()
	};
	log::trace!(target: "mixnet_test", "before sending messages");
	send_messages(&conf, send.clone().into_iter(), &nodes, &mut with_swarm_channels);
	log::trace!(target: "mixnet_test", "after sending messages");
	wait_on_messages(&conf, send.into_iter(), &mut with_swarm_channels, b"pong");
	log::trace!(target: "mixnet_test", "success with first set, switching set");
	let nodes_ids: Vec<_> = handle_topos
		.iter()
		.map(|topo| {
			let topo = topo.read();
			(*topo.topo.local_id(), topo.topo.local_routing_table().public_key)
		})
		.collect();
	for topo in handle_topos.iter() {
		// TODO also test switching mix public key of node or even mix public and mix id.
		// should be different test case where we change all even nodes.
		// This need to change SimpleConnection fields too.
		// TODO test wih switch before wait on connection (need to keep connections open
		// a while).
		topo.write().topo.handle_new_routing_set(&nodes_ids[set_2.clone()], None);
	}

	log::trace!(target: "mixnet_test", "set switched");

	let send: Vec<_> = if from_external {
		// ext 1 can route through peer 0 (only peer accepting ext)
		// TODO implement connect for external on demand
		// vec![SendConf { from: num_peers, to: 1, message: source_message.clone() }]
		return
	} else {
		let start = set_2.start;
		let end = set_2.end;
		(set_2)
			.map(|from| SendConf {
				from,
				to: if from + 1 == end { start } else { from + 1 },
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
	})
}
