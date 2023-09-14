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

//! Mixnet request builder. This module simply plugs together the topology and Sphinx modules.

use super::{
	packet_queues::AddressedPacket,
	sphinx::{
		build_surb, complete_request_packet, mut_payload_data, Delay, MixnodeIndex, PayloadData,
		Surb, SurbId, SurbPayloadEncryptionKeys,
	},
	topology::{NetworkStatus, RouteGenerator, RouteKind, Topology, TopologyErr},
	util::default_boxed_array,
};
use arrayvec::ArrayVec;
use rand::{CryptoRng, Rng};

pub struct RouteMetrics {
	pub num_hops: usize,
	pub forwarding_delay: Delay,
}

pub struct RequestBuilder<'topology, X> {
	route_generator: RouteGenerator<'topology, X>,
	destination_index: MixnodeIndex,
}

impl<'topology, X> RequestBuilder<'topology, X> {
	pub fn new(
		rng: &mut (impl Rng + CryptoRng),
		topology: &'topology Topology<X>,
		ns: &dyn NetworkStatus,
		destination_index: Option<MixnodeIndex>,
	) -> Result<Self, TopologyErr> {
		let route_generator = RouteGenerator::new(topology, ns);
		let destination_index = match destination_index {
			Some(index) => index,
			None => route_generator.choose_destination_index(rng)?,
		};
		Ok(Self { route_generator, destination_index })
	}

	pub fn destination_index(&self) -> MixnodeIndex {
		self.destination_index
	}

	pub fn build_packet<R: Rng + CryptoRng>(
		&self,
		rng: &mut R,
		write_payload_data: impl FnOnce(&mut PayloadData, &mut R) -> Result<(), TopologyErr>,
		num_hops: usize,
	) -> Result<(AddressedPacket, RouteMetrics), TopologyErr> {
		// Generate route
		let mut targets = ArrayVec::new();
		let mut their_kx_publics = ArrayVec::new();
		let first_mixnode_index = self.route_generator.gen_route(
			&mut targets,
			&mut their_kx_publics,
			rng,
			RouteKind::ToMixnode(self.destination_index),
			num_hops,
		)?;
		let peer_id =
			self.route_generator.topology().mixnode_index_to_peer_id(first_mixnode_index)?;

		// Build packet
		let mut packet = default_boxed_array();
		write_payload_data(mut_payload_data(&mut packet), rng)?;
		let forwarding_delay =
			complete_request_packet(&mut packet, rng, &targets, &their_kx_publics);

		let packet = AddressedPacket { peer_id, packet };
		let metrics = RouteMetrics { num_hops: their_kx_publics.len(), forwarding_delay };
		Ok((packet, metrics))
	}

	pub fn build_surb(
		&self,
		surb: &mut Surb,
		payload_encryption_keys: &mut SurbPayloadEncryptionKeys,
		rng: &mut (impl Rng + CryptoRng),
		id: &SurbId,
		num_hops: usize,
	) -> Result<RouteMetrics, TopologyErr> {
		// Generate route
		let mut targets = ArrayVec::new();
		let mut their_kx_publics = ArrayVec::new();
		let first_mixnode_index = self.route_generator.gen_route(
			&mut targets,
			&mut their_kx_publics,
			rng,
			RouteKind::FromMixnode(self.destination_index),
			num_hops,
		)?;

		// Build SURB
		let forwarding_delay = build_surb(
			surb,
			payload_encryption_keys,
			rng,
			first_mixnode_index,
			&targets,
			&their_kx_publics,
			id,
		);

		Ok(RouteMetrics { num_hops: their_kx_publics.len(), forwarding_delay })
	}
}
