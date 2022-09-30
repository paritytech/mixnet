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

use ambassador::Delegate;
use futures::{channel::mpsc, executor::ThreadPool, prelude::*, task::SpawnExt};
use libp2p_core::{
	identity,
	muxing::StreamMuxerBox,
	transport::{self, Transport},
	upgrade, Multiaddr, PeerId as NetworkId,
};
use libp2p_mplex as mplex;
use libp2p_noise as noise;
use libp2p_swarm::{DialError, Swarm, SwarmEvent};
use libp2p_tcp::{GenTcpConfig, TcpTransport};
use mixnet::{
	ambassador_impl_Topology,
	traits::{Configuration, NewRoutingSet, ShouldConnectTo, Topology},
	Config, Error, MixPublicKey, MixSecretKey, MixnetBehaviour, MixnetCommandSink, MixnetEvent,
	MixnetId, MixnetWorker, PeerCount, SendOptions, SinkToWorker, StreamFromWorker, WorkerChannels,
	WorkerCommand,
};
use parking_lot::RwLock;
use rand::{rngs::SmallRng, RngCore};
use std::{
	collections::{BTreeMap, BTreeSet, HashMap, HashSet},
	sync::{atomic::AtomicBool, Arc},
	task::Poll,
};

/// Message that test peer replies with.
pub enum PeerTestReply {
	InitialConnectionsCompleted,
	ReceiveMessage(mixnet::DecodedMessage),
}

pub enum SwarmMessage {
	Dial(Option<MixnetId>, Option<NetworkId>),
}

pub type TestChannels = (mpsc::Receiver<PeerTestReply>, MixnetCommandSink);
pub type Worker<T> = (MixnetWorker<T>, mpsc::Sender<WorkerCommand>, mpsc::Sender<SwarmMessage>);

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

/// Spawn a lip2p local transport for tests.
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

/// New transport and associated elements.
pub type NewTransport = (
	NetworkId,
	transport::Boxed<(NetworkId, StreamMuxerBox)>,
	SinkToWorker,
	StreamFromWorker,
	mpsc::Receiver<SwarmMessage>,
);

fn mk_transports(
	num_peers: usize,
	extra_external: usize,
) -> (
	Vec<NewTransport>,
	Vec<(NetworkId, WorkerChannels, mpsc::Sender<WorkerCommand>, mpsc::Sender<SwarmMessage>)>,
) {
	let mut transports = Vec::<NewTransport>::new();
	let mut handles = Vec::<(_, WorkerChannels, _, _)>::new();
	for _ in 0..num_peers + extra_external {
		let (to_worker_sink, to_worker_stream) = mpsc::channel(1000);
		let (from_worker_sink, from_worker_stream) = mpsc::channel(1000);
		let to_worker_from_test = to_worker_sink.clone();
		let (to_swarm_sink, to_swarm_stream) = mpsc::channel(1000);

		let (peer_id, _peer_key, trans) = mk_transport();
		transports.push((
			peer_id,
			trans,
			Box::new(to_worker_sink),
			Box::new(from_worker_stream),
			to_swarm_stream,
		));
		handles.push((
			peer_id,
			(Box::new(from_worker_sink), Box::new(to_worker_stream)),
			to_worker_from_test,
			to_swarm_sink,
		));
	}
	(transports, handles)
}

fn mk_swarms(
	transports: Vec<NewTransport>,
) -> Vec<(Swarm<MixnetBehaviour>, mpsc::Receiver<SwarmMessage>)> {
	let mut swarms = Vec::with_capacity(transports.len());

	for (peer_id, trans, to_worker_sink, from_worker_stream, to_swarm_stream) in
		transports.into_iter()
	{
		let mixnet = mixnet::MixnetBehaviour::new(to_worker_sink, from_worker_stream);
		let mut swarm = Swarm::new(trans, mixnet, peer_id);
		let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
		log_unwrap!(swarm.listen_on(addr));
		swarms.push((swarm, to_swarm_stream));
	}
	swarms
}

/// Spawn a libp2p local swarm with all peers.
pub fn mk_workers<T: Configuration>(
	handles: Vec<(
		NetworkId,
		WorkerChannels,
		mpsc::Sender<WorkerCommand>,
		mpsc::Sender<SwarmMessage>,
	)>,
	rng: &mut SmallRng,
	config_proto: &Config,
	mut make_topo: impl FnMut(
		usize,
		NetworkId,
		&[(MixnetId, MixPublicKey)],
		&[(MixSecretKey, ed25519_zebra::SigningKey)],
		&Config,
	) -> T,
) -> Vec<Worker<T>> {
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
		nodes.push((mix_id, peer_public_key));
		secrets.push((peer_secret_key, mix_secret_key));
	}

	let mut workers = Vec::new();
	for (i, (network_id, (from_worker_sink, to_worker_stream), to_worker, to_swarm)) in
		handles.into_iter().enumerate()
	{
		let (id, pub_key) = nodes[i];
		let cfg = mixnet::Config {
			secret_key: secrets[i].0.clone(),
			public_key: pub_key,
			local_id: id,
			..config_proto.clone()
		};

		let topo = make_topo(i, network_id, &nodes[..], &secrets[..], &cfg);

		workers.push((
			mixnet::MixnetWorker::new(cfg, topo, (from_worker_sink, to_worker_stream)),
			to_worker,
			to_swarm,
		));
	}
	workers
}

/// Spawn a libp2p local swarm with all peers.
pub fn spawn_swarms<T: Configuration>(
	num_peers: usize,
	from_external: bool,
	executor: &ThreadPool,
	rng: &mut SmallRng,
	config_proto: &Config,
	make_topo: impl FnMut(
		usize,
		NetworkId,
		&[(MixnetId, MixPublicKey)],
		&[(MixSecretKey, ed25519_zebra::SigningKey)],
		&Config,
	) -> T,
) -> (Vec<Worker<T>>, Arc<AtomicBool>) {
	let extra_external = if from_external {
		2 // 2 external node at ix num_peers and num_peers + 1
	} else {
		0
	};

	let (transports, handles) = mk_transports(num_peers, extra_external);
	let swarms = mk_swarms(transports);

	let workers = mk_workers(handles, rng, config_proto, make_topo);

	let peer_ids: HashMap<_, _> = workers
		.iter()
		.zip(swarms.iter())
		.enumerate()
		.map(|(p, (worker, swarm))| (*worker.0.mixnet().local_id(), (*swarm.0.local_peer_id(), p)))
		.collect();
	let addresses: Vec<Option<Multiaddr>> = vec![None; swarms.len()];
	let peer_ids = Arc::new(peer_ids);
	let addresses = Arc::new(RwLock::new(addresses));
	// to_wait and to_notify just synched the peer starting, so all dial are succesful.
	// This should be remove or optional if mixnet got non connected use case.
	// TODO just test dial (list of peers) and retry dial simple system (synch is complex for no
	// reason). TODO same for dht this is not needed (online offline is routing table dependant).
	let mut to_notify = (0..num_peers + extra_external).map(|_| Vec::new()).collect::<Vec<_>>();
	let mut to_wait = (0..num_peers + extra_external).map(|_| Vec::new()).collect::<Vec<_>>();

	for p1 in 0..num_peers {
		for to_wait in &mut to_wait[p1 + 1..num_peers] {
			let (tx, rx) = mpsc::channel::<Multiaddr>(1);
			to_notify[p1].push(tx);
			to_wait.push(rx);
		}
		if from_external {
			let (tx, rx) = mpsc::channel::<Multiaddr>(1);
			// 0 with ext 1
			to_notify[num_peers].push(tx);
			to_wait[0].push(rx);
		}
	}

	let mut swarm_futures = Vec::with_capacity(swarms.len());

	let inital_connection = Arc::new(AtomicBool::new(false));
	for (p, (mut swarm, mut receiver_swarm)) in swarms.into_iter().enumerate() {
		let mut to_notify = std::mem::take(&mut to_notify[p]);
		let mut to_wait = std::mem::take(&mut to_wait[p]);
		let peer_ids = peer_ids.clone();
		let addresses = addresses.clone();
		let inital_connection = inital_connection.clone();
		let poll_fn = async move {
			let mut num_connected_p2p = 0isize;
			loop {
				futures::select!(
					a = receiver_swarm.select_next_some() => match a {
						SwarmMessage::Dial(mix_id, network_id) => {
						if let Some(network_id) = network_id {
							log::trace!(target: "mixnet_test", "Dialing to {:?}", mix_id);
							if let Err(e) = swarm.dial(network_id) {
								log::trace!(target: "mixnet_test", "Dialing fail with id only {:?}", e);
							} else {
								continue;
							}
						} if let Some((network_id, p)) = mix_id.as_ref().and_then(|m| peer_ids.get(m)) {
							if inital_connection.load(std::sync::atomic::Ordering::Relaxed) {
								log::trace!(target: "mixnet_test", "Dialing to {:?}", mix_id);
								let e = swarm.dial(*network_id);
								if let Err(DialError::NoAddresses) = e {
									if let Some(address) = addresses.read()[*p].as_ref() {
										let e = swarm.dial(address.clone());
										if e.is_err() {
											log::error!(target: "mixnet_test", "Dialing fail with {:?}", e);
										}
									}
								} else {
									log::error!(target: "mixnet_test", "Dialing fail with {:?}", e);
								}
							}
						} else {
							log::error!(target: "mixnet_test", "Could not try connect");
						}
						},
					},
					b = swarm.select_next_some() => match b {
					SwarmEvent::NewListenAddr { address, .. } => {
						addresses.write()[p] = Some(address.clone());
						for mut tx in to_notify.drain(..) {
							log_unwrap!(tx.send(address.clone()).await)
						}
						for mut rx in to_wait.drain(..) {
							log_unwrap!(swarm.dial(log_unwrap_opt!(rx.next().await)));
						}
					},
					SwarmEvent::Behaviour(mixnet::BehaviourEvent::None) => (),
					SwarmEvent::Behaviour(mixnet::BehaviourEvent::CloseStream) => {
						log::error!(target: "mixnet_test", "Stream close, no message incomming.");
						return
					},
					SwarmEvent::ConnectionEstablished { .. } => {
						num_connected_p2p += 1;
						log::trace!(target: "mixnet_test", "{} P2p connected  {}", p, num_connected_p2p);
					},
					SwarmEvent::ConnectionClosed { .. } => {
						num_connected_p2p -= 1;
						log::trace!(target: "mixnet_test", "{} P2p disconnected  {}", p, num_connected_p2p);
					},
					SwarmEvent::IncomingConnection { .. } |
					SwarmEvent::BannedPeer { .. } |
					SwarmEvent::ExpiredListenAddr { .. } |
					SwarmEvent::Dialing { .. } |
					SwarmEvent::ListenerClosed { .. } |
					SwarmEvent::ListenerError { .. } |
					SwarmEvent::OutgoingConnectionError { .. } |
					SwarmEvent::IncomingConnectionError { .. } => (),
				},
					)
			}
		};
		swarm_futures.push(Box::pin(poll_fn));
	}
	log_unwrap!(executor.spawn(future::poll_fn(move |cx| {
		let mut swarm_futures = futures::future::select_all(&mut swarm_futures);
		loop {
			use std::pin::Pin;
			match Pin::new(&mut swarm_futures).poll(cx) {
				Poll::Ready((_swarm, p, remaining)) => {
					log::trace!(target: "mixnet", "Swarm {} exited", p);
					if remaining.is_empty() {
						log::trace!(target: "mixnet", "All Swarms exited");
						return Poll::Ready(())
					}
					swarm_futures = futures::future::select_all(remaining);
				},
				Poll::Pending => return Poll::Pending,
			}
		}
	})));
	(workers, inital_connection)
}

/// Spawn the mixnet workers workers
pub fn spawn_workers<T: Configuration>(
	num_peers: usize, // TODO from workers.len()??
	from_external: bool,
	expect_all_connected: bool,
	workers: Vec<Worker<T>>,
	executor: &ThreadPool,
	single_thread: bool,
) -> (Vec<MixnetId>, Vec<TestChannels>) {
	let mut nodes = Vec::with_capacity(workers.len());
	let mut test_channels = Vec::with_capacity(workers.len());
	let mut workers_futures = Vec::with_capacity(workers.len());

	for (p, (mut worker, to_worker, mut to_swarm)) in workers.into_iter().enumerate() {
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
		let mut expect_all_connected = expect_all_connected;

		let (mut from_swarm_sink, from_swarm_stream) = mpsc::channel(1000);
		test_channels.push((from_swarm_stream, MixnetCommandSink(Box::new(to_worker))));

		nodes.push(*worker.mixnet().local_id());

		let mut count_connected = target_peers.is_some();
		let mut handshake_done = HashSet::new();
		let worker = future::poll_fn(move |cx| loop {
			match worker.poll(cx) {
				Poll::Ready(MixnetEvent::None) => (),
				Poll::Ready(MixnetEvent::Connected(peer, _network_id)) => {
					log::trace!(target: "mixnet_test", "{} Connected  {}/{:?}", p, handshake_done.len(), target_peers);
					if count_connected {
						handshake_done.insert(peer);
						log::trace!(target: "mixnet_test", "{} done {}", p, handshake_done.len());
						if Some(handshake_done.len()) == target_peers || target_peers.is_none() {
							expect_all_connected = false;
							count_connected = false;
							log_unwrap!(from_swarm_sink
								.start_send_unpin(PeerTestReply::InitialConnectionsCompleted));
							target_peers = None;
						}
					}
				},
				Poll::Ready(MixnetEvent::Disconnected(disconnected)) => {
					for (network_id, mix_id, try_reco) in disconnected {
						if try_reco {
							to_swarm
								.start_send_unpin(SwarmMessage::Dial(mix_id, Some(network_id)))
								.unwrap();
						}
						// when keep_connection_alive is true TODO factor the decrease and
						// increase code
						log::trace!(target: "mixnet_test", "{} Disconnected  {}/{:?}", p, handshake_done.len(), target_peers);
						if count_connected && !expect_all_connected {
							// non expected connection will disconnect peer, count it
							// as negotiated connection.
							handshake_done.insert(network_id);

							if Some(handshake_done.len()) == target_peers || target_peers.is_none()
							{
								expect_all_connected = false;
								count_connected = false;
								log_unwrap!(from_swarm_sink
									.start_send_unpin(PeerTestReply::InitialConnectionsCompleted));
								target_peers = None;
							}
						}
					}
				},
				Poll::Ready(MixnetEvent::TryConnect(try_connect)) =>
					for (mix_id, network_id) in try_connect {
						to_swarm
							.start_send_unpin(SwarmMessage::Dial(Some(mix_id), network_id))
							.unwrap();
					},
				Poll::Ready(MixnetEvent::Message(message)) => {
					log_unwrap!(
						from_swarm_sink.start_send_unpin(PeerTestReply::ReceiveMessage(message))
					);
				},
				Poll::Ready(MixnetEvent::Shutdown) => {
					log::error!(target: "mixnet", "Shutting worker");
					return Poll::Ready(())
				},
				Poll::Pending => return Poll::Pending,
			}
		});
		if single_thread {
			workers_futures.push(worker);
		} else {
			log_unwrap!(executor.spawn(worker));
		}
	}
	if !workers_futures.is_empty() {
		log_unwrap!(executor.spawn(future::poll_fn(move |cx| {
			let mut workers_futures = futures::future::select_all(&mut workers_futures);
			loop {
				use std::pin::Pin;
				match Pin::new(&mut workers_futures).poll(cx) {
					Poll::Ready((_swarm, p, remaining)) => {
						log::trace!(target: "mixnet", "Workers {} exited", p);
						if remaining.is_empty() {
							log::trace!(target: "mixnet", "All Workers exited");
							return Poll::Ready(())
						}
						workers_futures = futures::future::select_all(remaining);
					},
					Poll::Pending => return Poll::Pending,
				}
			}
		})));
	}
	(nodes, test_channels)
}

/// Simple key signing handshake.
/// Handshake is our MixnetId concatenated with
/// MixPublicKey and a signature of NetworkId peer
/// concatenated with the mix public key.
/// Signing key is MixnetId (we use the publickey as Mixpeerid).
#[derive(Clone, Delegate)]
#[delegate(Topology, target = "topo")]
pub struct SimpleHandshake<T> {
	pub local_id: Option<MixnetId>,
	pub local_network_id: Option<NetworkId>,
	pub topo: T,
	// key for signing handshake (assert mix_pub_key, MixnetId is related to
	// MixPublicKey by signing it (and also dest MixPublicKey to avoid replay).
	pub mix_secret_key: Option<Arc<(ed25519_zebra::SigningKey, ed25519_zebra::VerificationKey)>>,
}

impl<T: Topology> mixnet::traits::Handshake for SimpleHandshake<T> {
	fn handshake_size(&self) -> usize {
		32 + 32 + 64
	}

	fn check_handshake(
		&self,
		payload: &[u8],
		_from: &NetworkId,
	) -> Option<(MixnetId, MixPublicKey)> {
		let mut peer_id = [0u8; 32];
		peer_id.copy_from_slice(&payload[0..32]);
		//		let peer_id = mixnet::to_sphinx_id(&payload[0..32]).ok()?;
		let mut pk = [0u8; 32];
		pk.copy_from_slice(&payload[32..64]);
		let mut signature = [0u8; 64];
		signature.copy_from_slice(&payload[64..]);
		let signature = log_unwrap!(ed25519_zebra::Signature::try_from(&signature[..]));
		let pub_key = log_unwrap!(ed25519_zebra::VerificationKey::try_from(&peer_id[..]));
		let mut message = log_unwrap_opt!(self.local_network_id).to_bytes().to_vec();
		message.extend_from_slice(&pk[..]);
		if pub_key.verify(&signature, &message[..]).is_ok() {
			let pk = MixPublicKey::from(pk);
			Some((peer_id, pk))
		} else {
			None
		}
	}

	fn handshake(&self, with: &NetworkId, public_key: &MixPublicKey) -> Option<Vec<u8>> {
		let mut result = log_unwrap_opt!(self.local_id.as_ref()).to_vec();
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
}

#[derive(Clone, Copy)]
pub struct TestConfig {
	pub num_peers: usize,
	pub num_hops: u32,
	pub message_count: usize,
	pub message_size: usize,
	pub with_surb: bool,
	pub from_external: bool,
}

pub fn wait_on_connections(conf: &TestConfig, with_swarm_channels: &mut [TestChannels]) {
	let TestConfig { num_peers, from_external, .. } = *conf;

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
}

#[derive(Clone)]
pub struct SendConf {
	pub from: usize,
	pub to: usize,
	pub message: Vec<u8>,
}

pub fn send_messages(
	conf: &TestConfig,
	send: impl Iterator<Item = SendConf>,
	nodes: &[MixnetId],
	with_swarm_channels: &mut [TestChannels],
) {
	let TestConfig { message_count, with_surb, .. } = *conf;

	for send_conf in send {
		let recipient = &nodes[send_conf.to];
		log::trace!(target: "mixnet_test", "{}: Sending {} messages to {:?}", send_conf.from, message_count, recipient);
		for _ in 0..message_count {
			log_unwrap!(with_swarm_channels[send_conf.from].1.send(
				Some(*recipient),
				send_conf.message.clone(),
				SendOptions { num_hop: None, with_surb },
			));
		}
	}
}

pub fn new_routing_set(set: &[(MixnetId, MixPublicKey)], with_swarm_channels: &mut [TestChannels]) {
	for channel in with_swarm_channels.iter_mut() {
		log_unwrap!(channel.1.new_global_routing_set(set.to_vec()));
	}
}

pub fn wait_on_messages(
	conf: &TestConfig,
	sent: impl Iterator<Item = SendConf>,
	with_swarm_channels: &mut [TestChannels],
	surb_reply: &[u8],
) {
	let TestConfig { message_count, with_surb, .. } = *conf;

	let mut expect: HashMap<usize, HashMap<Vec<u8>, (usize, usize)>> = Default::default();

	for sent in sent {
		let nb = expect.entry(sent.to).or_default().entry(sent.message).or_default();
		nb.0 += message_count;
		if with_surb {
			let nb = expect.entry(sent.from).or_default().entry(surb_reply.to_vec()).or_default();
			nb.1 += message_count;
		}
	}

	let mut received_messages: Vec<_> = with_swarm_channels
		.iter_mut()
		.enumerate()
		.filter_map(|(at, (receiver, sender))| {
			expect.remove(&at).map(|mut messages| {
				future::poll_fn(move |cx| loop {
					match receiver.poll_next_unpin(cx) {
						Poll::Ready(Some(PeerTestReply::InitialConnectionsCompleted)) => (),
						Poll::Ready(Some(PeerTestReply::ReceiveMessage(
							mixnet::DecodedMessage { peer, message, mut kind },
						))) => {
							log::trace!(target: "mixnet_test", "Decoded message {} bytes, from {:?}", message.len(), peer);
							let nb = messages.remove(&message).map(|mut nb| {
								if let Some(_o_query) = kind.extract_surb_query() {
									nb.1 -= 1;
								} else {
									nb.0 -= 1;
								}
								nb
							});
							assert!(nb.is_some());
							if nb != Some((0, 0)) {
								messages.insert(message, log_unwrap_opt!(nb));
							}
							if let Some(reply) = kind.surb() {
								log_unwrap!(sender.surb(surb_reply.to_vec(), reply));
							}
							if messages.is_empty() {
								return Poll::Ready(messages.is_empty())
							}
						},
						Poll::Ready(None) => {
							// TODO restore?							log::error!("Loop on None, consider failure here");
						},
						Poll::Pending => return Poll::Pending,
					}
				})
			})
		})
		.collect();
	while !received_messages.is_empty() {
		let (_, p, remaining) =
			async_std::task::block_on(futures::future::select_all(received_messages));
		log::trace!(target: "mixnet", "Connecting {} completed", p);
		received_messages = remaining;
	}
}
