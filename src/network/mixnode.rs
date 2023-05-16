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

use super::peer_id::{to_core_peer_id, INVALID_CORE_PEER_ID};
use crate::core::{KxPublic, Mixnode as CoreMixnode};
use libp2p_core::PeerId;
use multiaddr::{multiaddr, Multiaddr, Protocol};

/// Just like `CoreMixnode` but with a libp2p peer ID instead of a mixnet peer ID.
#[derive(Clone)]
pub struct Mixnode {
	/// Key-exchange public key for the mixnode.
	pub kx_public: KxPublic,
	/// Peer ID for the mixnode.
	pub peer_id: PeerId,
	/// External addresses for the mixnode.
	pub external_addresses: Vec<Multiaddr>,
}

impl Mixnode {
	/// Modify [`external_addresses`](Self::external_addresses) such that there is at least one
	/// address and the final component of each address matches [`peer_id`](Self::peer_id).
	pub fn fixup_external_addresses(&mut self, log_target: &'static str) {
		// Ensure the final component of each address matches peer_id
		self.external_addresses
			.retain_mut(|addr| match PeerId::try_from_multiaddr(addr) {
				Some(peer_id) if peer_id == self.peer_id => true,
				Some(_) => {
					log::error!(
						target: log_target,
						"Mixnode address {} does not match mixnode peer ID {}, ignoring",
						addr,
						self.peer_id
					);
					false
				},
				None if matches!(addr.iter().last(), Some(Protocol::P2p(_))) => {
					log::error!(
						target: log_target,
						"Mixnode address {} has unrecognised P2P protocol, ignoring",
						addr
					);
					false
				},
				None => {
					addr.push(Protocol::P2p(*self.peer_id.as_ref()));
					true
				},
			});

		// If there are no external addresses, insert one consisting of just the peer ID
		if self.external_addresses.is_empty() {
			self.external_addresses.push(multiaddr!(P2p(*self.peer_id.as_ref())));
		}
	}

	/// Convert to a `CoreMixnode`. The peer ID conversion may fail; in this case, an error message
	/// is logged, but a `CoreMixnode` is still returned, with `peer_id` set to
	/// [`INVALID_CORE_PEER_ID`].
	///
	/// It would be possible to handle conversion failure in a better way, but this would
	/// complicate things for what should be a rare case. Note that even if we succeed in
	/// converting the peer ID here, there is no guarantee that we will be able to connect to the
	/// peer or send packets to it. The most common failure case is expected to be that the peer is
	/// simply unreachable over the network.
	pub fn to_core(self, log_target: &'static str) -> CoreMixnode {
		CoreMixnode {
			kx_public: self.kx_public,
			peer_id: to_core_peer_id(&self.peer_id).unwrap_or_else(|| {
				log::error!(
					target: log_target,
					"Failed to convert libp2p peer ID {} to mixnet peer ID",
					self.peer_id
				);
				INVALID_CORE_PEER_ID
			}),
			external_addresses: self.external_addresses,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use multiaddr::multihash::Multihash;

	#[test]
	fn fixup_external_addresses() {
		let peer_id = PeerId::random();
		let mut mixnode =
			Mixnode { kx_public: Default::default(), peer_id, external_addresses: Vec::new() };
		mixnode.fixup_external_addresses("mixnet");
		assert_eq!(mixnode.external_addresses, vec![multiaddr!(P2p(*peer_id.as_ref()))]);

		let other_peer_id = PeerId::random();
		mixnode.external_addresses = vec![
			multiaddr!(Tcp(0u16), P2p(*peer_id.as_ref())),
			multiaddr!(Tcp(1u16), P2p(*other_peer_id.as_ref())),
			multiaddr!(Tcp(2u16), P2p(Multihash::wrap(999, &[1, 2, 3]).unwrap())),
			multiaddr!(Tcp(3u16)),
		];
		mixnode.fixup_external_addresses("mixnet");
		assert_eq!(
			mixnode.external_addresses,
			vec![
				multiaddr!(Tcp(0u16), P2p(*peer_id.as_ref())),
				multiaddr!(Tcp(3u16), P2p(*peer_id.as_ref())),
			]
		);
	}
}
