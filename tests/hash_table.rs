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
use common::{PeerTestReply, SimpleHandshake};
use futures::prelude::*;
use libp2p_core::PeerId;
use mixnet::ambassador_impl_Topology;
use rand::RngCore;
use std::{sync::Arc, task::Poll};

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

// TODO extract part of test_messages in common:
// - send message(from: usize, to: usize)
// - wait_on_message(expected: Vec<Messages>)
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
		with_swarm_channels[num_peers]
			.1
			.send(
				Some(nodes[1]), // we are connected to 0, sending to 1
				source_message.to_vec(),
				SendOptions { num_hop: None, with_surb },
			)
			.unwrap();
		// ext 2 cannot
		with_swarm_channels[num_peers]
			.1
			.send(
				Some(nodes[1]), // we are connected to 0, sending to 1
				source_message.to_vec(),
				SendOptions { num_hop: None, with_surb },
			)
			.unwrap();
	} else {
		for recipient in &nodes[1..num_peers] {
			log::trace!(target: "mixnet", "0: Sending {} messages to {:?}", message_count, recipient);
			for _ in 0..message_count {
				with_swarm_channels[0]
					.1
					.send(
						Some(*recipient), // we are connected to 0, sending to 1
						source_message.to_vec(),
						SendOptions { num_hop: None, with_surb },
					)
					.unwrap();
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
								sender.surb(b"pong".to_vec(), reply).unwrap();
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
	test_messages(6, 10, 1, false, false);
}

#[test]
fn fragmented_messages_no_surb() {
	test_messages(6, 1, 8 * 1024, false, false);
}

#[test]
fn message_exchange_with_surb() {
	test_messages(6, 10, 1, true, false);
}

#[test]
fn fragmented_messages_with_surb() {
	test_messages(6, 1, 8 * 1024, true, false);
}

#[test]
fn from_external_with_surb() {
	test_messages(6, 1, 100, true, true);
}

#[test]
fn from_external_no_surb() {
	test_messages(6, 1, 4 * 1024, false, true);
}
