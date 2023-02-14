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
	boxed_packet::{AddressedPacket, BoxedPacket},
	sphinx::{
		build_surb, complete_request_packet, mut_payload_data, Delay, MixnodeIndex, PayloadData,
		Surb, SurbId, SurbPayloadEncryptionKeys,
	},
	topology::{LocalNetworkStatus, RouteGenerator, RouteKind, Topology, TopologyErr},
};
use arrayvec::ArrayVec;
use rand::{CryptoRng, Rng};

pub struct RequestBuilder<'topology> {
	route_generator: RouteGenerator<'topology>,
	destination_index: MixnodeIndex,
}

impl<'topology> RequestBuilder<'topology> {
	pub fn new(
		rng: &mut (impl Rng + CryptoRng),
		topology: &'topology Topology,
		lns: &dyn LocalNetworkStatus,
		destination_index: Option<MixnodeIndex>,
	) -> Result<Self, TopologyErr> {
		let route_generator = RouteGenerator::new(topology, lns);
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
	) -> Result<(AddressedPacket, Delay), TopologyErr> {
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
		let mut boxed_packet = BoxedPacket::default();
		let packet = boxed_packet.as_mut();
		write_payload_data(mut_payload_data(packet), rng)?;
		let delay = complete_request_packet(packet, rng, &targets, &their_kx_publics);

		Ok((AddressedPacket { peer_id, packet: boxed_packet }, delay))
	}

	pub fn build_surb(
		&self,
		surb: &mut Surb,
		payload_encryption_keys: &mut SurbPayloadEncryptionKeys,
		rng: &mut (impl Rng + CryptoRng),
		id: &SurbId,
		num_hops: usize,
	) -> Result<Delay, TopologyErr> {
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
		Ok(build_surb(
			surb,
			payload_encryption_keys,
			rng,
			first_mixnode_index,
			&targets,
			&their_kx_publics,
			id,
		))
	}
}
