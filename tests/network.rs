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

#[path = "util.rs"]
mod util;

use futures::{channel::mpsc, future::Either, prelude::*};
use libp2p_core::{
	identity,
	muxing::StreamMuxerBox,
	transport::{self, Transport},
	upgrade, Multiaddr, PeerId as NetworkId,
};
use libp2p_mplex as mplex;
use libp2p_noise as noise;
use libp2p_swarm::{Swarm, SwarmEvent};
use libp2p_tcp::{async_io::Transport as TcpTransport, Config as TcpConfig};
use mixnet::{
	core::{
		Config, KxPublicStore, Message, MixnodeId, RelSessionIndex, SessionPhase, SessionStatus,
		MESSAGE_ID_SIZE,
	},
	network::{MixnetBehaviour, MixnetEvent, Mixnode},
};
use rand::{Rng, RngCore};
use std::{sync::Arc, time::Duration};
use util::log_target;

#[macro_export]
macro_rules! log_unwrap {
	($code:expr) => {
		match $code {
			Err(e) => {
				log::error!(target: "mixnet_test", "Error in unwrap: {e:?}");
				panic!("{e:?}")
			},
			Ok(r) => r,
		}
	};
}

#[macro_export]
macro_rules! log_unwrap_opt {
	($code:expr) => {
		match $code {
			None => {
				log::error!(target: "mixnet_test", "Unwrap none");
				panic!("")
			},
			Some(r) => r,
		}
	};
}

fn test_messages(num_peers: usize, message_count: usize, message_size: usize, with_surb: bool) {
	let _ = env_logger::try_init();
	let mut source_message = Vec::new();
	source_message.resize(message_size, 0);
	rand::thread_rng().fill_bytes(&mut source_message);

	let mut mixnodes = Vec::new();
	let mut kx_public_stores = Vec::new();
	let mut transports = Vec::new();
	for _ in 0..num_peers {
		let (peer_id, trans) = mk_transport();
		let kx_public_store = KxPublicStore::new();
		let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
		mixnodes.push(Mixnode {
			kx_public: kx_public_store.public_for_session(0).unwrap(),
			peer_id,
			external_addresses: vec![addr],
		});
		kx_public_stores.push(kx_public_store);
		transports.push(trans);
	}

	let mut swarms = Vec::new();
	for (peer_index, ((mixnode, kx_public_store), trans)) in
		mixnodes.iter().zip(kx_public_stores).zip(transports).enumerate()
	{
		let mut config = Config {
			log_target: log_target(peer_index),
			mean_forwarding_delay: Duration::from_millis(50),
			num_hops: std::cmp::min(3, num_peers - 1),
			..Default::default()
		};
		config.mixnode_session.mean_authored_packet_period = Duration::from_millis(50);
		config.non_mixnode_session.as_mut().unwrap().mean_authored_packet_period =
			Duration::from_millis(50);
		let mut mixnet =
			MixnetBehaviour::new(&mixnode.peer_id, config, Arc::new(kx_public_store)).unwrap();
		mixnet.set_session_status(SessionStatus {
			current_index: 0,
			phase: SessionPhase::DisconnectFromPrev,
		});
		mixnet.maybe_set_mixnodes(RelSessionIndex::Current, &mut || Ok(mixnodes.iter().cloned()));

		let mut swarm = Swarm::with_threadpool_executor(trans, mixnet, mixnode.peer_id);
		swarm.listen_on(mixnode.external_addresses[0].clone()).unwrap();
		swarms.push(swarm);
	}

	let mut to_notify = (0..num_peers).map(|_| Vec::new()).collect::<Vec<_>>();
	let mut to_wait = (0..num_peers).map(|_| Vec::new()).collect::<Vec<_>>();

	for (p1, n) in to_notify.iter_mut().enumerate() {
		for w in to_wait.iter_mut().skip(p1 + 1) {
			let (tx, rx) = mpsc::channel::<Multiaddr>(1);
			n.push(tx);
			w.push(rx);
		}
	}

	let mut connect_futures = Vec::new();

	for (p, (mut swarm, (mut to_notify, mut to_wait))) in swarms
		.into_iter()
		.zip(to_notify.into_iter().zip(to_wait.into_iter()))
		.enumerate()
	{
		let log_target = log_target(p);
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
					SwarmEvent::Behaviour(MixnetEvent::Connected(_)) => {
						num_connected += 1;
						log::trace!(
							target: log_target,
							"Connected {num_connected}/{}",
							num_peers - 1
						);
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
		log::trace!(target: log_target(p), "Connecting completed");
		connect_futures = rest;
		swarms.push((p, swarm));
	}

	let index = swarms.iter().position(|(p, _)| *p == 0).unwrap();
	let (_, mut peer0_swarm) = swarms.remove(index);
	let log_target_0 = log_target(0);
	for np in 1..num_peers {
		log::trace!(target: log_target_0, "Sending {message_count} messages to mixnode {np}");
		let mut destination =
			Some(MixnodeId { session_index: 0, mixnode_index: np.try_into().unwrap() });
		for _ in 0..message_count {
			peer0_swarm
				.behaviour_mut()
				.post_request(
					&mut destination,
					&rand::thread_rng().gen(),
					source_message.as_slice().into(),
					if with_surb { 1 } else { 0 },
				)
				.unwrap();
		}
	}

	let mut futures = Vec::new();
	for (p, mut swarm) in swarms {
		let log_target = log_target(p);
		let source_message = &source_message;
		let peer_future = async move {
			let mut received = 0;
			loop {
				match swarm.select_next_some().await {
					SwarmEvent::Behaviour(MixnetEvent::Message(Message::Request {
						session_index,
						id: _,
						data,
						mut surbs,
					})) => {
						received += 1;
						log::trace!(target: log_target, "Decoded message {} bytes", data.len());
						assert_eq!(source_message, &data);
						assert_eq!(surbs.is_empty(), !with_surb);
						if !surbs.is_empty() {
							swarm
								.behaviour_mut()
								.post_reply(
									&mut surbs,
									session_index,
									&[0; MESSAGE_ID_SIZE],
									[42].as_slice().into(),
								)
								.unwrap();
						}
						if received == message_count {
							return swarm
						}
					},
					SwarmEvent::Behaviour(MixnetEvent::Message(Message::Reply { .. })) =>
						panic!("only peer 0 should receive this"),
					_ => {},
				}
			}
		};
		futures.push(Box::pin(peer_future));
	}

	let mut done_futures = Vec::new();
	let mut done_surbs = num_peers - 1;
	let spin_future = async move {
		loop {
			match peer0_swarm.select_next_some().await {
				SwarmEvent::Behaviour(MixnetEvent::Message(Message::Request { .. })) =>
					panic!("peer 0 expect a reply only"),
				SwarmEvent::Behaviour(MixnetEvent::Message(Message::Reply { id, data })) => {
					assert!(with_surb);
					done_surbs -= 1;
					assert_eq!(&id, &[0; MESSAGE_ID_SIZE]);
					assert_eq!(&data, &[42]);
				},
				_ => {},
			}
			if done_surbs == 0 {
				return
			}
		}
	};
	done_futures.push(Box::pin(spin_future.boxed()));

	while done_futures.len() < num_peers - 1 {
		let result1 = futures::future::select_all(futures.drain(..));
		let result2 = futures::future::select_all(&mut done_futures);
		match async_std::task::block_on(futures::future::select(result1, result2)) {
			Either::Left((t, _)) => {
				let (mut swarm, index, rest) = t;
				log::trace!(target: log_target(index), "Completed");
				futures = rest;
				let spin_future = async move {
					loop {
						swarm.select_next_some().await;
					}
				};
				done_futures.push(Box::pin(spin_future.boxed()));
			},

			Either::Right(_) => return,
		}
	}
}

fn mk_transport() -> (NetworkId, transport::Boxed<(NetworkId, StreamMuxerBox)>) {
	let key = identity::ed25519::Keypair::generate();
	let id_keys = identity::Keypair::Ed25519(key);
	let peer_id = id_keys.public().to_peer_id();
	let noise_keys =
		log_unwrap!(noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys));
	(
		peer_id,
		TcpTransport::new(TcpConfig::new().nodelay(true))
			.upgrade(upgrade::Version::V1)
			.authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
			.multiplex(mplex::MplexConfig::default())
			.boxed(),
	)
}

#[test]
fn message_exchange_no_surb() {
	test_messages(5, 10, 1, false);
}

#[test]
fn message_exchange_with_surb() {
	test_messages(5, 3, 1, true);
}

#[test]
fn fragmented_messages() {
	test_messages(2, 1, 8 * 1024, false);
}
