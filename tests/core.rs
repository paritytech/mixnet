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

//! Mixnet core tests.

use mixnet::core::{
	Config, Events, Message, MessageId, Mixnet, Mixnode, NetworkStatus, PeerId, RelSessionIndex,
	SessionIndex, SessionPhase, SessionStatus, MESSAGE_ID_SIZE,
};
use multiaddr::{multiaddr, multihash::Multihash, Multiaddr};
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use std::{
	collections::{HashMap, HashSet},
	sync::OnceLock,
};

fn log_target(peer_index: usize) -> &'static str {
	static LOG_TARGETS: OnceLock<Mutex<HashMap<usize, &'static str>>> = OnceLock::new();
	LOG_TARGETS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.entry(peer_index)
		.or_insert_with(|| Box::leak(format!("mixnet({peer_index})").into_boxed_str()))
}

fn multiaddr_from_peer_id(id: &PeerId) -> Multiaddr {
	multiaddr!(P2p(Multihash::wrap(0, id).unwrap()))
}

fn peer_id_from_multiaddr(multiaddr: &Multiaddr) -> PeerId {
	let mut protocols = multiaddr.into_iter();
	let multiaddr::Protocol::P2p(hash) = protocols.next().unwrap() else { unreachable!() };
	assert!(protocols.next().is_none());
	assert_eq!(hash.code(), 0);
	hash.digest().try_into().unwrap()
}

struct Peer {
	id: PeerId,
	mixnet: Mixnet,
}

struct PeerNetworkStatus<'id, 'connections> {
	id: &'id PeerId,
	connections: &'connections HashMap<PeerId, HashSet<PeerId>>,
}

impl<'id, 'connections> NetworkStatus for PeerNetworkStatus<'id, 'connections> {
	fn local_peer_id(&self) -> PeerId {
		*self.id
	}

	fn is_connected(&self, peer_id: &PeerId) -> bool {
		self.connections[self.id].contains(peer_id) || self.connections[peer_id].contains(self.id)
	}
}

struct Network {
	current_session_index: SessionIndex,
	peers: Vec<Peer>,
	connections: HashMap<PeerId, HashSet<PeerId>>,
}

impl Network {
	fn new(rng: &mut impl Rng, mut config: impl FnMut(usize) -> Config, num_peers: usize) -> Self {
		let peers = (0..num_peers)
			.map(|peer_index| Peer { id: rng.gen(), mixnet: Mixnet::new(config(peer_index)) })
			.collect();
		Self { current_session_index: 0, peers, connections: HashMap::new() }
	}

	fn set_session_status(&mut self, session_status: SessionStatus) {
		self.current_session_index = session_status.current_index;
		for peer in &mut self.peers {
			peer.mixnet.set_session_status(session_status);
		}
	}

	fn maybe_set_mixnodes(&mut self, rel_session_index: RelSessionIndex, mixnodes: &[Mixnode]) {
		for peer in &mut self.peers {
			peer.mixnet
				.maybe_set_mixnodes(rel_session_index, &mut || Ok(mixnodes.to_owned()));
		}
	}

	fn next_mixnodes(&mut self, peer_indices: impl Iterator<Item = usize>) -> Vec<Mixnode> {
		peer_indices
			.map(|index| {
				let peer = &mut self.peers[index];
				Mixnode {
					kx_public: *peer.mixnet.next_kx_public(),
					peer_id: peer.id,
					external_addresses: vec![multiaddr_from_peer_id(&peer.id)],
				}
			})
			.collect()
	}

	fn tick(&mut self, mut handle_message: impl FnMut(usize, &mut Peer, Message)) {
		let mut packets = Vec::new();
		for peer in &mut self.peers {
			let events = peer.mixnet.take_events();
			if events.contains(Events::RESERVED_PEERS_CHANGED) {
				self.connections.insert(
					peer.id,
					peer.mixnet
						.reserved_peer_addresses()
						.iter()
						.map(peer_id_from_multiaddr)
						.collect(),
				);
			}
			let ns = PeerNetworkStatus { id: &peer.id, connections: &self.connections };
			if events.contains(Events::NEXT_FORWARD_PACKET_DEADLINE_CHANGED) &&
				peer.mixnet.next_forward_packet_deadline().is_some()
			{
				if let Some(packet) = peer.mixnet.pop_next_forward_packet() {
					assert!(ns.is_connected(&packet.peer_id));
					packets.push(packet);
				}
			}
			if events.contains(Events::NEXT_AUTHORED_PACKET_DEADLINE_CHANGED) &&
				peer.mixnet.next_authored_packet_delay().is_some()
			{
				if let Some(packet) = peer.mixnet.pop_next_authored_packet(&ns) {
					assert!(ns.is_connected(&packet.peer_id));
					packets.push(packet);
				}
			}
		}

		for packet in packets {
			let (peer_index, peer) = self
				.peers
				.iter_mut()
				.enumerate()
				.find(|(_, peer)| peer.id == packet.peer_id)
				.unwrap();
			if let Some(message) = peer.mixnet.handle_packet(&packet.packet) {
				handle_message(peer_index, peer, message);
			}
		}
	}

	fn post_request(
		&mut self,
		from_peer_index: usize,
		session_index: SessionIndex,
		message_id: &MessageId,
		data: &[u8],
		num_surbs: usize,
	) {
		let from_peer = &mut self.peers[from_peer_index];
		let from_peer_ns = PeerNetworkStatus { id: &from_peer.id, connections: &self.connections };
		from_peer
			.mixnet
			.post_request(
				session_index,
				&mut None,
				message_id,
				data.into(),
				num_surbs,
				&from_peer_ns,
			)
			.unwrap();
	}
}

#[test]
fn basic_operation() {
	let _ = env_logger::try_init();

	let mut rng = rand::thread_rng();

	let mut network = Network::new(
		&mut rng,
		|peer_index| Config {
			log_target: log_target(peer_index),
			gen_cover_packets: false,
			..Default::default()
		},
		30,
	);
	network.set_session_status(SessionStatus {
		current_index: 0,
		phase: SessionPhase::DisconnectFromPrev,
	});
	let mixnodes = network.next_mixnodes(0..20);
	network.set_session_status(SessionStatus {
		current_index: 1,
		phase: SessionPhase::DisconnectFromPrev,
	});
	network.maybe_set_mixnodes(RelSessionIndex::Current, &mixnodes);

	let request_from_peer_index = 20;
	let mut request_message_id = [0; MESSAGE_ID_SIZE];
	rng.fill_bytes(&mut request_message_id);
	let mut request_data = vec![0; 9999];
	rng.fill_bytes(&mut request_data);
	let num_surbs = 3;
	let mut reply_data = vec![0; 4567];
	rng.fill_bytes(&mut reply_data);

	let mut step = 0;
	for i in 0..100 {
		network.tick(|peer_index, peer, message| {
			match step {
				0 => {
					let Message::Request(mut message) = message else {
						panic!("Expected request message")
					};
					assert_eq!(message.session_index, 1);
					assert_eq!(message.id, request_message_id);
					assert_eq!(message.data, request_data);
					assert_eq!(message.surbs.len(), num_surbs);
					let mut reply_id = [0; MESSAGE_ID_SIZE];
					rng.fill_bytes(&mut reply_id);
					peer.mixnet
						.post_reply(
							&mut message.surbs,
							message.session_index,
							&reply_id,
							reply_data.as_slice().into(),
						)
						.unwrap();
				},
				1 => {
					assert_eq!(peer_index, request_from_peer_index);
					let Message::Reply(message) = message else { panic!("Expected reply message") };
					assert_eq!(message.request_id, request_message_id);
					assert_eq!(message.data, reply_data);
				},
				_ => panic!("Unexpected message"),
			}
			step += 1;
		});
		if i == 0 {
			network.post_request(
				request_from_peer_index,
				1,
				&request_message_id,
				&request_data,
				num_surbs,
			);
		}
	}
	assert_eq!(step, 2);
}
