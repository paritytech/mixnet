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
use libp2p_tcp::{GenTcpConfig, TcpTransport};
use rand::RngCore;
use std::sync::Arc;

use mixnet::{MessageType, SendOptions, SessionTopology, PublicKeyStore};

#[macro_export]
macro_rules! log_unwrap {
	($code:expr) => {
		match $code {
			Err(e) => {
				log::error!(target: "mixnet_test", "Error in unwrap: {:?}", e);
				panic!("{:?}", e)
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

	let mut nodes = Vec::new();
	let mut secrets = Vec::new();
	let mut transports = Vec::new();
	for _ in 0..num_peers {
		let (peer_id, peer_key, trans) = mk_transport();
		let peer_key_montgomery = mixnet::public_from_ed25519(&peer_key.public());
		let peer_secret_key = mixnet::secret_from_ed25519(peer_key.secret().as_ref());
		let Ok(id) = mixnet::to_mix_peer_id(&peer_id) else {
			return
		};

		let addr = format!("/ip4/127.0.0.1/tcp/0").parse().unwrap();
		nodes.push((id, peer_key_montgomery.clone(), vec![addr]));
		secrets.push(peer_secret_key);
		transports.push((peer_id, trans));
	}

	let mut swarms = Vec::new();
	for (i, (network_id, trans)) in transports.into_iter().enumerate() {
		let (id, pub_key, addrs) = &nodes[i];
		let cfg = mixnet::Config {
			secret_key: secrets[i].clone(),
			public_key: pub_key.clone(),
			local_id: id.clone(),
			target_bits_per_second: 1024 * 1024,
			timeout_ms: 10000,
			num_hops: 3,
			average_message_delay_ms: 50,
			surb_ttl_ms: 100_000,
			replay_ttl_ms: 100_000,
		};

		let keystore = Arc::new(PublicKeyStore);
		let mut mixnet = mixnet::MixnetBehaviour::new(cfg, keystore);
		let topology = SessionTopology::new(nodes.clone());
		mixnet.set_session_topolgy(0, topology);
		let mut swarm = Swarm::new(trans, mixnet, network_id);
		swarm.listen_on(addrs[0].clone()).unwrap();
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
					SwarmEvent::Behaviour(mixnet::NetworkEvent::Connected(_)) => {
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
		let (recipient, _, _) = nodes[np];
		log::trace!(target: "mixnet", "0: Sending {} messages to {:?}", message_count, recipient);
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
		let message_count = if with_surb { message_count + 1 } else { message_count };
		let peer_future = async move {
			let mut received = 0;
			loop {
				match swarm.select_next_some().await {
					SwarmEvent::Behaviour(mixnet::NetworkEvent::Message(
						mixnet::DecodedMessage { peer, message, kind },
					)) => {
						received += 1;
						log::trace!(target: "mixnet", "{} Decoded message {} bytes, from {:?}, received={}", p, message.len(), peer, received);
						match kind {
							MessageType::StandAlone => {
								assert!(!with_surb);
								assert_eq!(source_message.as_slice(), message.as_slice());
							},
							MessageType::WithSurb(surb_reply_enveloppe) => {
								assert!(with_surb);
								assert_eq!(source_message.as_slice(), message.as_slice());
								swarm
									.behaviour_mut()
									.reply(vec![42], *surb_reply_enveloppe)
									.unwrap();
							},
							MessageType::FromSurb(..) => {
								panic!("only peer 0 should receive this");
							},
						}
						if received == message_count {
							return swarm
						}
					},
					_ => {},
				}
			}
		};
		futures.push(Box::pin(peer_future));
	}

	let mut done_futures = Vec::new();
	let mut done_surbs = num_peers - 1;
	let spin_future =
		async move {
			loop {
				match peer0_swarm.select_next_some().await {
					SwarmEvent::Behaviour(mixnet::NetworkEvent::Message(
						mixnet::DecodedMessage { peer: _, message, kind },
					)) => match kind {
						MessageType::WithSurb(..) | MessageType::StandAlone => {
							panic!("peer 0 expect a reply only")
						},
						MessageType::FromSurb(..) => {
							assert!(with_surb);
							done_surbs -= 1;
							assert_eq!(&[42], message.as_slice());
						},
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
				log::trace!(target: "mixnet", "{} Completed", index);
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

fn mk_transport(
) -> (NetworkId, identity::ed25519::Keypair, transport::Boxed<(NetworkId, StreamMuxerBox)>) {
	let key = identity::ed25519::Keypair::generate();
	let id_keys = identity::Keypair::Ed25519(key.clone());
	let peer_id = id_keys.public().to_peer_id();
	let noise_keys =
		log_unwrap!(noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys));
	(
		peer_id,
		key,
		TcpTransport::new(GenTcpConfig::new().nodelay(true))
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
