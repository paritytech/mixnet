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
use std::{collections::HashMap, task::Poll};

use mixnet::{MixPublicKey, SendOptions};

#[derive(Clone)]
struct TopologyGraph {
	connections: HashMap<PeerId, Vec<(PeerId, MixPublicKey)>>,
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

		Self { connections }
	}
}

impl mixnet::Topology for TopologyGraph {
	fn neighbors(&self, id: &PeerId) -> Option<Vec<(PeerId, MixPublicKey)>> {
		self.connections.get(id).cloned()
	}

	fn random_recipient(&self) -> Option<PeerId> {
		self.connections.keys().choose(&mut rand::thread_rng()).cloned()
	}

	fn routing(&self) -> bool {
		true
	}
	fn connected(&mut self, _: PeerId, _: MixPublicKey) {}

	fn disconnect(&mut self, _: &PeerId) {}
}

fn test_messages(num_peers: usize, message_count: usize, message_size: usize, with_surbs: bool) {
	let _ = env_logger::try_init();
	let mut source_message = Vec::new();
	source_message.resize(message_size, 0);
	rand::thread_rng().fill_bytes(&mut source_message);

	let executor = futures::executor::ThreadPool::new().unwrap();
	let mut nodes = Vec::new();
	let mut secrets = Vec::new();
	let mut transports = Vec::new();
	for _ in 0..num_peers {
		let (peer_id, peer_key, trans) = mk_transport();
		let peer_key_montgomery = mixnet::public_from_ed25519(&peer_key.public());
		let peer_secret_key = mixnet::secret_from_ed25519(&peer_key.secret());
		nodes.push((peer_id.clone(), peer_key_montgomery.clone()));
		secrets.push(peer_secret_key);
		transports.push(trans);
	}

	let topology = TopologyGraph::new_star(&nodes);

	let mut swarms = Vec::new();
	for (i, trans) in transports.into_iter().enumerate() {
		let (id, pub_key) = nodes[i];
		let cfg = mixnet::Config {
			secret_key: secrets[i].clone(),
			public_key: pub_key.clone(),
			local_id: id.clone(),
			target_bits_per_second: 1024 * 1024,
			timeout_ms: 10000,
			num_hops: 3,
			average_message_delay_ms: 50,
			limit_per_window: None,
			persist_surbs_query: false,
			replay_ttl_ms: 100_000,
			surbs_ttl_ms: 100_000,
		};

		let (to_worker_sink, to_worker_stream) = mpsc::channel(1000);
		let (from_worker_sink, from_worker_stream) = mpsc::channel(1000);
		let mixnet =
			mixnet::MixnetBehaviour::new(Box::new(to_worker_sink), Box::new(from_worker_stream));
		let mut worker = mixnet::MixnetWorker::new(
			cfg,
			topology.clone(),
			(Box::new(from_worker_sink), Box::new(to_worker_stream)),
		);
		let worker = future::poll_fn(move |cx| loop {
			match worker.poll(cx) {
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

	let mut to_notify = (0..num_peers).map(|_| Vec::new()).collect::<Vec<_>>();
	let mut to_wait = (0..num_peers).map(|_| Vec::new()).collect::<Vec<_>>();

	for p1 in 0..num_peers {
		for p2 in p1 + 1..num_peers {
			let (tx, rx) = mpsc::channel::<Multiaddr>(1);
			to_notify[p1].push(tx);
			to_wait[p2].push(rx);
		}
	}

	let mut connect_futures = Vec::new();

	for (p, (mut swarm, (mut to_notify, mut to_wait))) in swarms
		.into_iter()
		.zip(to_notify.into_iter().zip(to_wait.into_iter()))
		.enumerate()
	{
		let peer_future = async move {
			let mut num_connected = 0;

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
					SendOptions { num_hop: None, with_surbs },
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
						if let Some(reply) = kind.surbs() {
							swarm.behaviour_mut().send_surbs(b"pong".to_vec(), reply).unwrap();
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
			let mut expected_surbs = if with_surbs { Some(num_peers - 1) } else { None };
			loop {
				match peer0_swarm.select_next_some().await {
					// TODO have surbs original message (can be small vec id: make it an input
					// param) attached.
					SwarmEvent::Behaviour(mixnet::NetworkEvent::Message(
						mixnet::DecodedMessage { peer: _, message, kind: _ },
					)) => {
						assert!(message.as_slice() == b"pong");
						expected_surbs.as_mut().map(|nb| *nb -= 1);
						if expected_surbs == Some(0) {
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
				// can only be with surbs of first
				assert!(with_surbs);
				let (_swarm, index, _rest) = t;
				assert_eq!(index, 0);
				return
			},
		}
	}
	while with_surbs {
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
fn message_exchange_no_surbs() {
	test_messages(5, 10, 1, false);
}

#[test]
fn fragmented_messages_no_surbs() {
	test_messages(2, 1, 8 * 1024, false);
}

#[test]
fn message_exchange_with_surbs() {
	test_messages(5, 10, 1, true);
}

#[test]
fn fragmented_messages_with_surbs() {
	test_messages(2, 1, 8 * 1024, true);
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
