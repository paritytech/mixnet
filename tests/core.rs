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

#[path = "util.rs"]
mod util;

use mixnet::core::{
	Config, Invalidated, KxPublicStore, Message, MessageId, Mixnet, Mixnode, NetworkStatus, PeerId,
	RelSessionIndex, SessionIndex, SessionPhase, SessionStatus, MESSAGE_ID_SIZE,
};
use multiaddr::{multiaddr, multihash::Multihash, Multiaddr};
use rand::{Rng, RngCore};
use std::{
	collections::{HashMap, HashSet},
	sync::Arc,
};
use util::log_target;

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
	kx_public_store: Arc<KxPublicStore>,
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
			.map(|peer_index| {
				let id = rng.gen();
				let kx_public_store = Arc::new(KxPublicStore::new());
				let mixnet = Mixnet::new(config(peer_index), kx_public_store.clone());
				Peer { id, kx_public_store, mixnet }
			})
			.collect();
		Self { current_session_index: 0, peers, connections: HashMap::new() }
	}

	fn set_session_status(&mut self, session_status: SessionStatus) {
		self.current_session_index = session_status.current_index;
		for peer in &mut self.peers {
			peer.mixnet.set_session_status(session_status);
		}
	}

	fn maybe_set_mixnodes(
		&mut self,
		rel_session_index: RelSessionIndex,
		peer_indices: impl Iterator<Item = usize>,
	) {
		let session_index = rel_session_index + self.current_session_index;
		let mixnodes: Vec<_> = peer_indices
			.map(|index| {
				let peer = &self.peers[index];
				Mixnode {
					kx_public: peer.kx_public_store.public_for_session(session_index).unwrap(),
					peer_id: peer.id,
					external_addresses: vec![multiaddr_from_peer_id(&peer.id)],
				}
			})
			.collect();
		for peer in &mut self.peers {
			peer.mixnet.maybe_set_mixnodes(rel_session_index, || Ok(mixnodes.clone()));
		}
	}

	fn tick(&mut self, mut handle_message: impl FnMut(usize, &mut Peer, Message)) {
		let mut packets = Vec::new();
		for peer in &mut self.peers {
			let invalidated = peer.mixnet.take_invalidated();
			if invalidated.contains(Invalidated::RESERVED_PEERS) {
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
			if invalidated.contains(Invalidated::NEXT_FORWARD_PACKET_DEADLINE) &&
				peer.mixnet.next_forward_packet_deadline().is_some()
			{
				if let Some(packet) = peer.mixnet.pop_next_forward_packet() {
					assert!(ns.is_connected(&packet.peer_id));
					packets.push(packet);
				}
			}
			if invalidated.contains(Invalidated::NEXT_AUTHORED_PACKET_DEADLINE) &&
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
		message_id: &MessageId,
		data: &[u8],
		num_surbs: usize,
	) {
		let from_peer = &mut self.peers[from_peer_index];
		let from_peer_ns = PeerNetworkStatus { id: &from_peer.id, connections: &self.connections };
		from_peer
			.mixnet
			.post_request(&mut None, message_id, data, num_surbs, &from_peer_ns)
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
		current_index: 1,
		phase: SessionPhase::DisconnectFromPrev,
	});
	network.maybe_set_mixnodes(RelSessionIndex::Current, 0..20);

	let request_from_peer_index = 20;
	let mut request_message_id = [0; MESSAGE_ID_SIZE];
	rng.fill_bytes(&mut request_message_id);
	let mut request_data = vec![0; 9999];
	rng.fill_bytes(&mut request_data);
	let num_surbs = 3;
	let mut reply_message_id = [0; MESSAGE_ID_SIZE];
	rng.fill_bytes(&mut reply_message_id);
	let mut reply_data = vec![0; 4567];
	rng.fill_bytes(&mut reply_data);

	let mut step = 0;
	for i in 0..100 {
		network.tick(|peer_index, peer, message| {
			match step {
				0 => {
					let Message::Request { session_index, id, data, mut surbs } = message else {
						panic!("Expected request message")
					};
					assert_eq!(session_index, 1);
					assert_eq!(id, request_message_id);
					assert_eq!(data, request_data);
					assert_eq!(surbs.len(), num_surbs);
					peer.mixnet
						.post_reply(&mut surbs, session_index, &reply_message_id, &reply_data)
						.unwrap();
				},
				1 => {
					assert_eq!(peer_index, request_from_peer_index);
					assert_eq!(
						message,
						Message::Reply { id: reply_message_id, data: reply_data.clone() }
					);
				},
				_ => panic!("Unexpected message"),
			}
			step += 1;
		});
		if i == 0 {
			network.post_request(
				request_from_peer_index,
				&request_message_id,
				&request_data,
				num_surbs,
			);
		}
	}
	assert_eq!(step, 2);
}
