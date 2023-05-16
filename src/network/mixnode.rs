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
use libp2p_core::{Multiaddr, PeerId};

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
