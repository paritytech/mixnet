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

//! Tests utility (simple implementation of mixnet around local libp2p transport).

use futures::{channel::mpsc, executor::ThreadPool, prelude::*, task::SpawnExt};
use libp2p_core::{
	identity,
	muxing::StreamMuxerBox,
	transport::{self, Transport},
	upgrade, Multiaddr, PeerId,
};
use libp2p_mplex as mplex;
use libp2p_noise as noise;
use libp2p_swarm::{Swarm, SwarmEvent};
use libp2p_tcp::{GenTcpConfig, TcpTransport};
use mixnet::{
	Config, MixPeerId, MixPublicKey, MixSecretKey, MixnetBehaviour, MixnetWorker, SinkToWorker,
	StreamFromWorker, Topology, WorkerChannels, WorkerCommand,
};
use rand::{rngs::SmallRng, RngCore};
use std::task::Poll;

/// Message that test peer replies with.
pub enum PeerTestReply {
	InitialConnectionsCompleted,
	ReceiveMessage(mixnet::DecodedMessage),
}

pub type TestChannels = (mpsc::Receiver<PeerTestReply>, mpsc::Sender<WorkerCommand>);

/// Spawn a lip2p local transport for tests.
fn mk_transport() -> (PeerId, identity::ed25519::Keypair, transport::Boxed<(PeerId, StreamMuxerBox)>)
{
	let key = identity::ed25519::Keypair::generate();
	let id_keys = identity::Keypair::Ed25519(key.clone());
	let peer_id = id_keys.public().to_peer_id();
	let noise_keys = noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys).unwrap();
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

fn mk_transports(
	num_peers: usize,
	extra_external: usize,
) -> (
	Vec<(
		PeerId,
		transport::Boxed<(PeerId, StreamMuxerBox)>,
		SinkToWorker,
		StreamFromWorker,
		mpsc::Sender<WorkerCommand>,
	)>,
	Vec<(PeerId, WorkerChannels)>,
) {
	let mut transports = Vec::<(_, _, SinkToWorker, StreamFromWorker, _)>::new();
	let mut handles = Vec::<(_, WorkerChannels)>::new();
	for _ in 0..num_peers + extra_external {
		let (to_worker_sink, to_worker_stream) = mpsc::channel(1000);
		let (from_worker_sink, from_worker_stream) = mpsc::channel(1000);
		let to_worker_from_test = to_worker_sink.clone();

		let (peer_id, _peer_key, trans) = mk_transport();
		transports.push((
			peer_id.clone(),
			trans,
			Box::new(to_worker_sink),
			Box::new(from_worker_stream),
			to_worker_from_test,
		));
		handles.push((peer_id.clone(), (Box::new(from_worker_sink), Box::new(to_worker_stream))));
	}
	(transports, handles)
}

fn mk_swarms(
	transports: Vec<(
		PeerId,
		transport::Boxed<(PeerId, StreamMuxerBox)>,
		SinkToWorker,
		StreamFromWorker,
		mpsc::Sender<WorkerCommand>,
	)>,
) -> Vec<(Swarm<MixnetBehaviour>, mpsc::Sender<WorkerCommand>)> {
	let mut swarms = Vec::with_capacity(transports.len());

	for (peer_id, trans, to_worker_sink, from_worker_stream, to_worker) in transports.into_iter() {
		let mixnet = mixnet::MixnetBehaviour::new(to_worker_sink, from_worker_stream);
		let mut swarm = Swarm::new(trans, mixnet, peer_id.clone());
		let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
		swarm.listen_on(addr).unwrap();
		swarms.push((swarm, to_worker));
	}
	swarms
}

/// Spawn a libp2p local swarm with all peers.
pub fn mk_workers<T: Topology>(
	handles: Vec<(PeerId, WorkerChannels)>,
	num_peers: usize,
	rng: &mut SmallRng,
	config_proto: &Config,
	mut make_topo: impl FnMut(
		usize,
		PeerId,
		&[(MixPeerId, MixPublicKey)],
		&[(MixSecretKey, ed25519_zebra::SigningKey)],
		&Config,
	) -> T,
) -> Vec<MixnetWorker<T>> {
	let _ = env_logger::try_init();

	let mut nodes = Vec::new();
	let mut secrets = Vec::new();
	for _ in handles.iter() {
		let (peer_public_key, peer_secret_key) = mixnet::generate_new_keys();
		let mut secret_mix = [0u8; 32];
		rng.fill_bytes(&mut secret_mix);
		let mix_secret_key: ed25519_zebra::SigningKey = secret_mix.into();
		let mix_public_key: ed25519_zebra::VerificationKey = (&mix_secret_key).into();
		let mix_id: [u8; 32] = mix_public_key.into();
		nodes.push((mix_id, peer_public_key.clone()));
		secrets.push((peer_secret_key, mix_secret_key));
	}

	let mut workers = Vec::new();
	for (i, (network_id, (from_worker_sink, to_worker_stream))) in handles.into_iter().enumerate() {
		let (id, pub_key) = nodes[i];
		let cfg = mixnet::Config {
			secret_key: secrets[i].0.clone(),
			public_key: pub_key.clone(),
			local_id: id.clone(),
			..config_proto.clone()
		};

		let topo = make_topo(i, network_id, &nodes[..num_peers], &secrets[..], &cfg);

		workers.push(mixnet::MixnetWorker::new(cfg, topo, (from_worker_sink, to_worker_stream)));
	}
	workers
}

/// Spawn a libp2p local swarm with all peers.
pub fn spawn_swarms(
	num_peers: usize,
	from_external: bool,
	executor: &ThreadPool,
) -> (Vec<(PeerId, WorkerChannels)>, Vec<TestChannels>) {
	let extra_external = if from_external {
		2 // 2 external node at ix num_peers and num_peers + 1
	} else {
		0
	};

	let (transports, handles) = mk_transports(num_peers, extra_external);
	let swarms = mk_swarms(transports);

	// to_wait and to_notify just synched the peer starting, so all dial are succesful.
	// This should be remove or optional if mixnet got non connected use case.
	// TODO just test dial (list of peers) and retry dial simple system (synch is complex for no
	// reason). TODO same for dht this is not needed (online offline is routing table dependant).
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

	let mut swarm_futures = Vec::with_capacity(swarms.len());
	let mut test_channels = Vec::with_capacity(swarms.len());

	for (p, (mut swarm, to_worker)) in swarms.into_iter().enumerate() {
		let (mut from_swarm_sink, from_swarm_stream) = mpsc::channel(1000);
		test_channels.push((from_swarm_stream, to_worker));
		let external_1 = from_external && p == num_peers;
		let external_2 = from_external && p > num_peers;
		let mut target_peers = if from_external && p == 0 {
			Some(num_peers)
		} else if external_1 {
			Some(1) // one connection is enough for external one
		} else if external_2 {
			None // no connection
		} else {
			Some(num_peers - 1)
		};

		let mut to_notify = std::mem::take(&mut to_notify[p]);
		let mut to_wait = std::mem::take(&mut to_wait[p]);
		let poll_fn = async move {
			let mut num_connected = 0;
			let mut num_connected_p2p = 0;
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
					SwarmEvent::Behaviour(mixnet::MixnetEvent::Connected(_, _)) => {
						num_connected += 1;
						log::trace!(target: "mixnet", "{} Connected  {}/{:?}", p, num_connected, target_peers);
						if Some(num_connected) == target_peers {
							from_swarm_sink
								.send(PeerTestReply::InitialConnectionsCompleted)
								.await
								.unwrap();
							target_peers = None;
						}
					},
					SwarmEvent::Behaviour(mixnet::MixnetEvent::Disconnected(_)) => {
						num_connected -= 1;
						log::trace!(target: "mixnet", "{} P2P connected  {}/{:?}", p, num_connected, target_peers);
					},
					SwarmEvent::Behaviour(mixnet::MixnetEvent::Message(message)) => {
						from_swarm_sink.send(PeerTestReply::ReceiveMessage(message)).await.unwrap();
					},
					SwarmEvent::Behaviour(mixnet::MixnetEvent::CloseStream) => {
						log::error!(target: "mixnet", "Stream close, no message incomming.");
						return
					},
					SwarmEvent::ConnectionEstablished { .. } => {
						num_connected_p2p += 1;
						log::trace!(target: "mixnet", "{} P2p connected  {}", p, num_connected_p2p);
					},
					SwarmEvent::ConnectionClosed { .. } => {
						num_connected_p2p -= 1;
						log::trace!(target: "mixnet", "{} P2p connected  {}", p, num_connected_p2p);
					},
					SwarmEvent::IncomingConnection { .. } |
					SwarmEvent::BannedPeer { .. } |
					SwarmEvent::ExpiredListenAddr { .. } |
					SwarmEvent::Dialing { .. } |
					SwarmEvent::ListenerClosed { .. } |
					SwarmEvent::ListenerError { .. } |
					SwarmEvent::OutgoingConnectionError { .. } |
					SwarmEvent::IncomingConnectionError { .. } => (),
				}
			}
		};
		swarm_futures.push(Box::pin(poll_fn));
	}
	let _ = executor
		.spawn(future::poll_fn(move |cx| {
			let mut swarm_futures = futures::future::select_all(&mut swarm_futures);
			loop {
				use std::pin::Pin;
				match Pin::new(&mut swarm_futures).poll(cx) {
					Poll::Ready((_swarm, p, remaining)) => {
						log::trace!(target: "mixnet", "Swarm {} exited", p);
						if remaining.len() == 0 {
							log::trace!(target: "mixnet", "All Swarms exited");
							return Poll::Ready(())
						}
						swarm_futures = futures::future::select_all(remaining);
					},
					Poll::Pending => return Poll::Pending,
				}
			}
		}))
		.unwrap();
	(handles, test_channels)
}

/// Spawn the mixnet workers workers
pub fn spawn_workers<T: Topology>(
	handles: Vec<(PeerId, WorkerChannels)>,
	num_peers: usize,
	rng: &mut SmallRng,
	config_proto: &Config,
	make_topo: impl FnMut(
		usize,
		PeerId,
		&[(MixPeerId, MixPublicKey)],
		&[(MixSecretKey, ed25519_zebra::SigningKey)],
		&Config,
	) -> T,
	executor: &ThreadPool,
	single_thread: bool,
) -> Vec<MixPeerId> {
	let mut nodes = Vec::with_capacity(handles.len());
	let workers = mk_workers(handles, num_peers, rng, config_proto, make_topo);

	let mut workers_futures = Vec::with_capacity(workers.len());
	for mut worker in workers.into_iter() {
		nodes.push(worker.local_id().clone());
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
		if single_thread {
			workers_futures.push(worker);
		} else {
			executor.spawn(worker).unwrap();
		}
	}
	if workers_futures.len() > 0 {
		let _ = executor
			.spawn(future::poll_fn(move |cx| {
				let mut workers_futures = futures::future::select_all(&mut workers_futures);
				loop {
					use std::pin::Pin;
					match Pin::new(&mut workers_futures).poll(cx) {
						Poll::Ready((_swarm, p, remaining)) => {
							log::trace!(target: "mixnet", "Workers {} exited", p);
							if remaining.len() == 0 {
								log::trace!(target: "mixnet", "All Workers exited");
								return Poll::Ready(())
							}
							workers_futures = futures::future::select_all(remaining);
						},
						Poll::Pending => return Poll::Pending,
					}
				}
			}))
			.unwrap();
	}
	nodes
}
