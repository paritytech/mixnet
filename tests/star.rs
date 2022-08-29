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

use common::PeerTestReply;
use futures::prelude::*;
use libp2p_core::PeerId;
use rand::{prelude::IteratorRandom, RngCore};
use std::{
	collections::HashMap,
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc,
	},
	task::Poll,
};

use mixnet::{MixPeerId, MixPublicKey, MixSecretKey, SendOptions, WorkerCommand};

#[derive(Clone)]
struct TopologyGraph {
	connections: HashMap<MixPeerId, Vec<(MixPeerId, MixPublicKey)>>, /* TODO remove field, peers
	                                                                  * is
	                                                                  * enough? */
	peers: Vec<(MixPeerId, MixPublicKey)>,
	// allow single external
	external: Option<MixPeerId>,
	nb_connected: Arc<AtomicUsize>,
	local_id: Option<MixPeerId>,
	local_network_id: Option<PeerId>,
	// key for signing handshake (assert mix_pub_key, MixPeerId is related to
	// MixPublicKey by signing it (and also dest MixPublicKey to avoid replay).
	mix_secret_key: Option<Arc<(ed25519_zebra::SigningKey, ed25519_zebra::VerificationKey)>>,
}

impl TopologyGraph {
	fn new_star(nodes: &[(MixPeerId, MixPublicKey)]) -> Self {
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
			local_id: None,
			local_network_id: None,
			mix_secret_key: None,
		}
	}
}

impl mixnet::Topology for TopologyGraph {
	fn neighbors(&self, id: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>> {
		self.connections.get(id).cloned()
	}

	fn first_hop_nodes_external(
		&self,
		_from: &MixPeerId,
		_to: &MixPeerId,
	) -> Vec<(MixPeerId, MixPublicKey)> {
		// allow only with peer 0
		vec![self.peers[0].clone()]
	}

	fn is_first_node(&self, id: &MixPeerId) -> bool {
		self.peers.iter().find(|(p, _)| p == id).is_some()
	}

	fn random_recipient(
		&mut self,
		local_id: &MixPeerId,
		_: &SendOptions,
	) -> Option<(MixPeerId, MixPublicKey)> {
		self.peers
			.iter()
			.filter(|(k, _v)| k != local_id)
			.choose(&mut rand::thread_rng())
			.map(|(k, v)| (k.clone(), v.clone()))
	}

	fn routing_to(&self, from: &MixPeerId, to: &MixPeerId) -> bool {
		if self.external.as_ref() == Some(to) {
			// this is partly incorrect as we also need to check that from is self.
			return self.local_id.as_ref() == Some(from)
		}
		self.connections
			.get(from)
			.map(|n| n.iter().find(|(p, _)| p == to))
			.flatten()
			.is_some()
	}

	fn connected(&mut self, _: MixPeerId, _: MixPublicKey) {
		self.nb_connected.fetch_add(1, Ordering::Relaxed);

		if self.nb_connected.load(Ordering::Relaxed) == self.connections.len() - 1 {
			log::info!("All connected");
		}
	}

	fn disconnect(&mut self, id: &MixPeerId) {
		self.nb_connected.fetch_sub(1, Ordering::Relaxed);
		if self.external.as_ref() == Some(id) {
			self.external = None;
		}
	}

	fn bandwidth_external(&self, id: &MixPeerId) -> Option<(usize, usize)> {
		if self.external.as_ref() == Some(id) {
			return Some((1, 1))
		}
		if self.external.is_some() {
			return None
		}
		Some((1, 1))
	}

	fn handshake_size(&self) -> usize {
		32 + 32 + 64
	}

	fn check_handshake(
		&mut self,
		payload: &[u8],
		_from: &PeerId,
	) -> Option<(MixPeerId, MixPublicKey)> {
		let mut peer_id = [0u8; 32];
		peer_id.copy_from_slice(&payload[0..32]);
		//		let peer_id = mixnet::to_sphinx_id(&payload[0..32]).ok()?;
		let mut pk = [0u8; 32];
		pk.copy_from_slice(&payload[32..64]);
		let mut signature = [0u8; 64];
		signature.copy_from_slice(&payload[64..]);
		let signature = ed25519_zebra::Signature::try_from(&signature[..]).unwrap();
		let pub_key = ed25519_zebra::VerificationKey::try_from(&peer_id[..]).unwrap();
		let mut message = self.local_network_id.unwrap().to_bytes().to_vec();
		message.extend_from_slice(&pk[..]);
		if pub_key.verify(&signature, &message[..]).is_ok() {
			let pk = MixPublicKey::from(pk);
			if !self.accept_peer(self.local_id.as_ref().unwrap(), &peer_id) {
				return None
			}
			if !self.is_routing(&peer_id) {
				debug_assert!(self.external.is_none());
				self.external = Some(peer_id.clone());
			}
			Some((peer_id, pk))
		} else {
			None
		}
	}

	fn handshake(&mut self, with: &PeerId, public_key: &MixPublicKey) -> Option<Vec<u8>> {
		let mut result = self.local_id.as_ref().unwrap().to_vec();
		result.extend_from_slice(&public_key.as_bytes()[..]);
		if let Some(keypair) = &self.mix_secret_key {
			let mut message = with.to_bytes().to_vec();
			message.extend_from_slice(&public_key.as_bytes()[..]);
			let signature = keypair.0.sign(&message[..]);
			let signature: [u8; 64] = signature.into();
			result.extend_from_slice(&signature[..]);
		} else {
			return None
		}
		Some(result)
	}

	fn collect_windows_stats(&self) -> bool {
		true
	}

	fn window_stats(&self, _stats: &mixnet::WindowStats) {}
}

fn test_messages(
	num_peers: usize,
	message_count: usize,
	message_size: usize,
	with_surb: bool,
	from_external: bool,
) {
	let seed: u64 = 0;
	let single_thread = false;
	let (public_key, secret_key) = mixnet::generate_new_keys();
	let config_proto = mixnet::Config {
		secret_key,
		public_key,
		local_id: Default::default(),
		target_bytes_per_second: 512 * 1024,
		timeout_ms: 10000,
		num_hops: 3,
		average_message_delay_ms: 50,
		persist_surb_query: false,
		replay_ttl_ms: 100_000,
		surb_ttl_ms: 100_000,
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
		common::spawn_swarms(num_peers, from_external, &executor);

	let make_topo = move |p: usize,
	                      network_id: PeerId,
	                      nodes: &[(MixPeerId, MixPublicKey)],
	                      secrets: &[(MixSecretKey, ed25519_zebra::SigningKey)],
	                      config: &mixnet::Config| {
		let mut topo = TopologyGraph::new_star(&nodes[..num_peers]);
		topo.local_id = Some(config.local_id.clone());
		topo.local_network_id = Some(network_id);
		let mix_secret_key = secrets[p].1.clone();
		let mix_public_key: ed25519_zebra::VerificationKey = (&mix_secret_key).into();
		topo.mix_secret_key = Some(Arc::new((mix_secret_key, mix_public_key)));
		topo
	};
	let nodes = common::spawn_workers::<TopologyGraph>(
		handles,
		num_peers,
		&mut rng,
		&config_proto,
		make_topo,
		&executor,
		single_thread,
	);
	let nb_conn = if from_external { num_peers + 1 } else { num_peers };
	let mut connected_futures: Vec<_> = with_swarm_channels[..nb_conn]
		.iter_mut()
		.map(|(receiver, _)| {
			future::poll_fn(move |cx| loop {
				match receiver.poll_next_unpin(cx) {
					Poll::Ready(Some(PeerTestReply::InitialConnectionsCompleted)) =>
						return Poll::Ready(()),
					Poll::Ready(Some(PeerTestReply::ReceiveMessage(_))) => (),
					Poll::Ready(None) => (),
					Poll::Pending => return Poll::Pending,
				}
			})
		})
		.collect();
	while !connected_futures.is_empty() {
		let (_, p, remaining) =
			async_std::task::block_on(futures::future::select_all(connected_futures));
		log::trace!(target: "mixnet", "Connecting {} completed", p);
		connected_futures = remaining;
	}

	if from_external {
		// ext 1 can route through peer 0 (only peer acceptiong)
		assert!(async_std::task::block_on(with_swarm_channels[num_peers].1.send(
			WorkerCommand::RegisterMessage(
				Some(nodes[1].clone()), // we are connected to 0, sending to 1
				source_message.to_vec(),
				SendOptions { num_hop: None, with_surb },
			)
		))
		.is_ok());
		// ext 2 cannot
		assert!(async_std::task::block_on(with_swarm_channels[num_peers].1.send(
			WorkerCommand::RegisterMessage(
				Some(nodes[1].clone()), // we are connected to 0, sending to 1
				source_message.to_vec(),
				SendOptions { num_hop: None, with_surb },
			)
		))
		.is_ok());
	} else {
		for np in 1..num_peers {
			let recipient = nodes[np];
			log::trace!(target: "mixnet", "0: Sending {} messages to {:?}", message_count, recipient);
			for _ in 0..message_count {
				assert!(async_std::task::block_on(with_swarm_channels[0].1.send(
					WorkerCommand::RegisterMessage(
						Some(recipient.clone()), // we are connected to 0, sending to 1
						source_message.to_vec(),
						SendOptions { num_hop: None, with_surb },
					)
				))
				.is_ok());
			}
		}
	}

	let range = if from_external { 1..2 } else { 1..num_peers };
	let mut received_messages: Vec<_> =
		with_swarm_channels[range]
			.iter_mut()
			.map(|(receiver, sender)| {
				future::poll_fn(move |cx| loop {
					match receiver.poll_next_unpin(cx) {
						Poll::Ready(Some(PeerTestReply::InitialConnectionsCompleted)) => (),
						Poll::Ready(Some(PeerTestReply::ReceiveMessage(
							mixnet::DecodedMessage { peer, message, kind },
						))) => {
							log::trace!(target: "mixnet", "Decoded message {} bytes, from {:?}", message.len(), peer);
							assert_eq!(source_message.as_slice(), message.as_slice());
							if let Some(reply) = kind.surb() {
								sender
									.try_send(WorkerCommand::RegisterSurbs(b"pong".to_vec(), reply))
									.unwrap();
							}
							return Poll::Ready(())
						},
						Poll::Ready(None) => (),
						Poll::Pending => return Poll::Pending,
					}
				})
			})
			.collect();
	while !received_messages.is_empty() {
		let (_, p, remaining) =
			async_std::task::block_on(futures::future::select_all(received_messages));
		log::trace!(target: "mixnet", "Connecting {} completed", p);
		received_messages = remaining;
	}

	if !with_surb {
		return
	}

	let (from, mut expected_surb) = if from_external { (num_peers, 1) } else { (0, num_peers - 1) };
	let expected_surb = &mut expected_surb;

	let (receiver, _sender) = &mut with_swarm_channels[from];
	let poll_fn = future::poll_fn(move |cx| loop {
		match receiver.poll_next_unpin(cx) {
			Poll::Ready(Some(PeerTestReply::InitialConnectionsCompleted)) => (),
			Poll::Ready(Some(PeerTestReply::ReceiveMessage(mixnet::DecodedMessage {
				peer,
				message,
				kind,
			}))) => {
				log::trace!(target: "mixnet", "Decoded message {} bytes, from {:?}", message.len(), peer);
				assert_eq!(b"pong", message.as_slice());
				assert!(kind.surb().is_none());
				*expected_surb -= 1;
				if *expected_surb == 0 {
					return Poll::Ready(())
				}
			},
			Poll::Ready(None) => (),
			Poll::Pending => return Poll::Pending,
		}
	});
	async_std::task::block_on(poll_fn);
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
	test_messages(5, 1, 100, true, true);
}

#[test]
fn from_external_no_surb() {
	test_messages(5, 1, 4 * 1024, false, true);
}
