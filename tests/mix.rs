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

use futures::{channel::mpsc, future::Either, prelude::*, task::SpawnExt};
use libp2p_core::{
	identity::{self},
	muxing::StreamMuxerBox,
	transport::{self, Transport},
	upgrade, Multiaddr, PeerId,
};
use libp2p_mplex as mplex;
use libp2p_noise as noise;
use libp2p_swarm::{Swarm, SwarmEvent};
use libp2p_tcp::TcpConfig;
use rand::{prelude::IteratorRandom, RngCore};
use std::{
	collections::HashMap,
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc, Mutex,
	},
	task::Poll,
};

use mixnet::{Error, MixPublicKey, SendOptions};

#[derive(Clone)]
struct TopologyGraph {
	connections: HashMap<PeerId, Vec<(PeerId, MixPublicKey)>>, /* TODO remove field, peers is
	                                                            * enough? */
	peers: Vec<(PeerId, MixPublicKey)>,
	// allow single external
	external: Option<PeerId>,
	nb_connected: Arc<AtomicUsize>,
}

impl TopologyGraph {
	fn new_star(nodes: &[(PeerId, MixPublicKey)]) -> Self {
		let mut connections = HashMap::new();
		for i in 0..nodes.len() {
			let (node, _node_key) = nodes[i];
			let mut neighbors = Vec::new();
			for j in 0..nodes.len() {
				if i != j {
					neighbors.push(nodes[j].clone())
				}
			}
			connections.insert(node.clone(), neighbors);
		}

		Self {
			connections,
			peers: nodes.iter().map(Clone::clone).collect(),
			external: Default::default(),
			nb_connected: Arc::new(0.into()),
		}
	}
}

impl mixnet::Topology for TopologyGraph {
	fn neighbors(&self, id: &PeerId) -> Option<Vec<(PeerId, MixPublicKey)>> {
		self.connections.get(id).cloned()
	}

	fn first_hop_nodes(&self) -> Vec<(PeerId, MixPublicKey)> {
		self.peers.clone()
	}

	fn first_hop_nodes_external(&self, _from: &PeerId) -> Vec<(PeerId, MixPublicKey)> {
		// allow only with peer 0
		vec![self.peers[0].clone()]
	}

	fn is_first_node(&self, id: &PeerId) -> bool {
		self.peers.iter().find(|(p, _)| p == id).is_some()
	}

	fn random_recipient(&self, local_id: &PeerId) -> Option<(PeerId, MixPublicKey)> {
		self.peers
			.iter()
			.filter(|(k, _v)| k != local_id)
			.choose(&mut rand::thread_rng())
			.map(|(k, v)| (k.clone(), v.clone()))
	}

	fn routing_to(&self, from: &PeerId, to: &PeerId) -> bool {
		self.connections
			.get(from)
			.map(|n| n.iter().find(|(p, _)| p == to))
			.flatten()
			.is_some()
	}

	fn connected(&mut self, _: PeerId, _: MixPublicKey) {
		self.nb_connected.fetch_add(1, Ordering::Relaxed);

		if self.nb_connected.load(Ordering::Relaxed) == self.connections.len() - 1 {
			log::info!("All connected");
		}
	}

	fn disconnect(&mut self, id: &PeerId) {
		self.nb_connected.fetch_sub(1, Ordering::Relaxed);
		if self.external.as_ref() == Some(id) {
			self.external = None;
		}
	}

	fn allow_external(&mut self, id: &PeerId) -> Option<(usize, usize)> {
		if self.external.as_ref() == Some(id) {
			return Some((1, 1))
		}
		if self.external.is_some() {
			return None
		}
		self.external = Some(id.clone());
		Some((1, 1))
	}
}

fn test_messages(
	num_peers: usize,
	message_count: usize,
	message_size: usize,
	with_surb: bool,
	from_external: bool,
) {
	let _ = env_logger::try_init();
	let mut source_message = Vec::new();
	source_message.resize(message_size, 0);
	rand::thread_rng().fill_bytes(&mut source_message);

	let executor = futures::executor::ThreadPool::new().unwrap();
	let extra_external = if from_external {
		2 // 2 external node at ix num_peers and num_peers + 1
	} else {
		0
	};
	let mut nodes = Vec::new();
	let mut secrets = Vec::new();
	let mut transports = Vec::new();
	for _ in 0..num_peers + extra_external {
		let (peer_id, peer_key, trans) = mk_transport();
		let peer_key_montgomery = mixnet::public_from_ed25519(&peer_key.public());
		let peer_secret_key = mixnet::secret_from_ed25519(&peer_key.secret());
		nodes.push((peer_id.clone(), peer_key_montgomery.clone()));
		secrets.push(peer_secret_key);
		transports.push(trans);
	}

	let topology = TopologyGraph::new_star(&nodes[..num_peers]);

	let mut to_behavior_external_1 = None;
	let mut to_behavior_external_2 = None;
	let mut to_worker_external_1 = None;
	let mut to_worker_external_2 = None;
	let mut swarms = Vec::new();
	let mut count_connection = Vec::new();
	let mut workers = Vec::new();
	for (i, trans) in transports.into_iter().enumerate() {
		let (id, pub_key) = nodes[i];
		let cfg = mixnet::Config {
			secret_key: secrets[i].clone(),
			public_key: pub_key.clone(),
			local_id: id.clone(),
			target_bits_per_second: 512 * 1024,
			timeout_ms: 10000,
			num_hops: 3,
			average_message_delay_ms: 50,
			limit_per_window: None,
			persist_surb_query: false,
			replay_ttl_ms: 100_000,
			surb_ttl_ms: 100_000,
		};

		let (to_worker_sink, to_worker_stream) = mpsc::channel(1000);
		if i == num_peers {
			to_worker_external_1 = Some(to_worker_sink.clone());
		}
		if i == num_peers + 1 {
			to_worker_external_2 = Some(to_worker_sink.clone());
		}

		let (from_worker_sink, from_worker_stream) = mpsc::channel(1000);
		if i == num_peers {
			to_behavior_external_1 = Some(from_worker_sink.clone());
		}
		if i == num_peers + 1 {
			to_behavior_external_2 = Some(from_worker_sink.clone());
		}

		let mixnet =
			mixnet::MixnetBehaviour::new(Box::new(to_worker_sink), Box::new(from_worker_stream));
		let mut topo = topology.clone();
		let mut counter = Arc::new(AtomicUsize::new(0));
		topo.nb_connected = counter.clone();
		count_connection.push(counter);
		let mut worker = Arc::new(Mutex::new(mixnet::MixnetWorker::new(
			cfg,
			topo,
			(Box::new(from_worker_sink), Box::new(to_worker_stream)),
		)));
		workers.push(worker.clone());
		let worker = future::poll_fn(move |cx| loop {
			match worker.lock().unwrap().poll(cx) {
				Poll::Ready(false) => {
					log::error!(target: "mixnet", "Shutting worker");
					return Poll::Ready(())
				},
				Poll::Pending => return Poll::Pending,
				Poll::Ready(true) => (),
			}
		});
		executor.spawn(worker).unwrap();
		let mut swarm = Swarm::new(trans, mixnet, id.clone());

		let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
		swarm.listen_on(addr).unwrap();
		swarms.push(swarm);
	}

	let mut to_notify = (0..num_peers + extra_external).map(|_| Vec::new()).collect::<Vec<_>>();
	let mut to_wait = (0..num_peers + extra_external).map(|_| Vec::new()).collect::<Vec<_>>();

	for p1 in 0..num_peers {
		for p2 in p1 + 1..num_peers {
			let (tx, rx) = mpsc::channel::<Multiaddr>(1);
			to_notify[p1].push(tx);
			to_wait[p2].push(rx);
		}
		if from_external {
			let (tx, rx) = mpsc::channel::<Multiaddr>(1);
			// 0 with ext 1
			to_notify[num_peers].push(tx);
			to_wait[0].push(rx);
		}
	}

	let mut connect_futures = Vec::new();
	for (p, (mut swarm, (mut to_notify, mut to_wait))) in swarms
		.into_iter()
		.zip(to_notify.into_iter().zip(to_wait.into_iter()))
		.enumerate()
	{
		let external_1 = from_external && p == num_peers;
		let external_2 = from_external && p > num_peers;
		let num_peers = if from_external && p == 0 {
			num_peers + 1
		} else if external_1 {
			2 // one connection is enough for external one
		} else {
			num_peers
		};
		let peer_future = async move {
			let mut num_connected = 0;

			if external_2 {
				// Do not attempt connection for external 2.
				return (swarm, p)
			}
			// connect as topology
			loop {
				match swarm.select_next_some().await {
					SwarmEvent::NewListenAddr { address, .. } => {
						for mut tx in to_notify.drain(..) {
							tx.send(address.clone()).await.unwrap()
						}
						for mut rx in to_wait.drain(..) {
							swarm.dial(rx.next().await.unwrap()).unwrap();
						}
					},
					SwarmEvent::Behaviour(mixnet::NetworkEvent::Connected(_, _)) => {
						num_connected += 1;
						log::trace!(target: "mixnet", "{} Connected  {}/{}", p, num_connected, num_peers - 1);
						if num_connected == num_peers - 1 {
							return (swarm, p)
						}
					},
					_ => {},
				}
			}
		};
		connect_futures.push(Box::pin(peer_future));
	}

	let mut swarms = Vec::new();
	while !connect_futures.is_empty() {
		let result = futures::future::select_all(connect_futures);
		let ((swarm, p), _, rest) = async_std::task::block_on(result);
		log::trace!(target: "mixnet", "Connecting {} completed", p);
		connect_futures = rest;
		swarms.push((p, swarm));
	}

	for i in 0..num_peers {
		if from_external && i == 0 {
			assert_eq!(count_connection[i].load(Ordering::Relaxed), num_peers);
		} else {
			assert_eq!(count_connection[i].load(Ordering::Relaxed), num_peers - 1);
		}
	}

	if from_external {
		let index_dest = swarms.iter().position(|(p, _)| *p == 0).unwrap();
		let index_external_1 = swarms.iter().position(|(p, _)| *p == num_peers).unwrap();
		let index_external_2 = swarms.iter().position(|(p, _)| *p == num_peers + 1).unwrap();
		assert_eq!(count_connection[num_peers].load(Ordering::Relaxed), 1);
		assert_eq!(count_connection[num_peers + 1].load(Ordering::Relaxed), 0);
		assert!(
			workers[num_peers].lock().unwrap().mixnet_mut().register_message(
				Some(nodes[1].0.clone()), // we are connected to 0, sending to 1
				None,
				source_message.to_vec(),
				SendOptions { num_hop: None, with_surb },
			).is_ok()
		);
		assert!(matches!(
			workers[num_peers + 1].lock().unwrap().mixnet_mut().register_message(
				Some(nodes[0].0.clone()),
				None,
				source_message.to_vec(),
				SendOptions { num_hop: None, with_surb },
			),
			Err(Error::Unreachable(_))
		));

		// surb is		NoPath(Some(PeerId("12D3KooWM9iUfQbeZ1vpLqwkngrGznRNkFzU9MJ97MUiNjoGQ31J")))
		return
	}

	let index = swarms.iter().position(|(p, _)| *p == 0).unwrap();
	let (_, mut peer0_swarm) = swarms.remove(index);
	for np in 1..num_peers {
		let (recipient, _) = nodes[np];
		log::trace!(target: "mixnet", "0: Sending {} messages to {}", message_count, recipient);
		for _ in 0..message_count {
			peer0_swarm
				.behaviour_mut()
				.send(
					recipient.clone(),
					source_message.to_vec(),
					SendOptions { num_hop: None, with_surb },
				)
				.unwrap();
		}
	}

	let mut futures = Vec::new();
	for (p, mut swarm) in swarms {
		let source_message = &source_message;
		let peer_future = async move {
			let mut received = 0;
			loop {
				match swarm.select_next_some().await {
					SwarmEvent::Behaviour(mixnet::NetworkEvent::Message(
						mixnet::DecodedMessage { peer, message, kind },
					)) => {
						received += 1;
						log::trace!(target: "mixnet", "{} Decoded message {} bytes, from {:?}, received={}", p, message.len(), peer, received);
						assert_eq!(source_message.as_slice(), message.as_slice());
						if let Some(reply) = kind.surb() {
							swarm.behaviour_mut().send_surb(b"pong".to_vec(), reply).unwrap();
						}
						if received == message_count {
							return swarm
						}
					},
					_ => {},
				}
			}
		};
		futures.push(Box::pin(peer_future.boxed()));
	}

	let mut done_futures = Vec::new();
	let spin_future =
		async move {
			let mut expected_surb = if with_surb { Some(num_peers - 1) } else { None };
			loop {
				match peer0_swarm.select_next_some().await {
					// TODO have surb original message (can be small vec id: make it an input
					// param) attached.
					SwarmEvent::Behaviour(mixnet::NetworkEvent::Message(
						mixnet::DecodedMessage { peer: _, message, kind: _ },
					)) => {
						assert!(message.as_slice() == b"pong");
						expected_surb.as_mut().map(|nb| *nb -= 1);
						if expected_surb == Some(0) {
							return peer0_swarm
						}
					},
					_ => {},
				}
			}
		};
	done_futures.push(Box::pin(spin_future.boxed()));

	while done_futures.len() < num_peers {
		let result1 = futures::future::select_all(futures.drain(..));
		let result2 = futures::future::select_all(&mut done_futures);
		match async_std::task::block_on(futures::future::select(result1, result2)) {
			Either::Left((t, _)) => {
				let (mut swarm, index, rest) = t;
				log::trace!(target: "mixnet", "{} Completed", index);
				futures = rest;
				let spin_future = async move {
					loop {
						swarm.select_next_some().await;
					}
				};
				done_futures.push(Box::pin(spin_future.boxed()));
			},
			Either::Right((t, _)) => {
				// can only be with surb of first
				assert!(with_surb);
				let (_swarm, index, _rest) = t;
				assert_eq!(index, 0);
				return
			},
		}
	}
	while with_surb {
		// TODO just if?
		let result2 = futures::future::select_all(&mut done_futures);
		match async_std::task::block_on(result2) {
			(_swarm, index, _rest) => {
				assert_eq!(index, 0);
				return
			},
		}
	}
}

#[test]
fn message_exchange_no_surb() {
	test_messages(5, 10, 1, false, false);
}

#[test]
fn fragmented_messages_no_surb() {
	test_messages(2, 1, 8 * 1024, false, false);
}

#[test]
fn message_exchange_with_surb() {
	test_messages(5, 10, 1, true, false);
}

#[test]
fn fragmented_messages_with_surb() {
	test_messages(2, 1, 8 * 1024, true, false);
}

#[test]
fn from_external_with_surb() {
	test_messages(5, 1, 4 * 1024, true, true);
}

#[test]
fn from_external_no_surb() {
	test_messages(5, 1, 4 * 1024, false, true);
}

fn mk_transport() -> (PeerId, identity::ed25519::Keypair, transport::Boxed<(PeerId, StreamMuxerBox)>)
{
	let key = identity::ed25519::Keypair::generate();
	let id_keys = identity::Keypair::Ed25519(key.clone());
	let peer_id = id_keys.public().to_peer_id();
	let noise_keys = noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys).unwrap();
	(
		peer_id,
		key,
		TcpConfig::new()
			.nodelay(true)
			.upgrade(upgrade::Version::V1)
			.authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
			.multiplex(mplex::MplexConfig::default())
			.boxed(),
	)
}
