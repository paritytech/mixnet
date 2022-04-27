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

//! Mixnet configuration.

use libp2p_core::identity::ed25519::Keypair;

use crate::{public_from_ed25519, secret_from_ed25519, MixPeerId, MixPublicKey, MixSecretKey};

/// Configuration data for the mixnet protocol.
pub struct Config {
	/// Static DH secret for this node
	pub secret_key: MixSecretKey,
	/// DH public key for this node
	pub public_key: MixPublicKey,
	/// Local node id.
	pub local_id: MixPeerId,
	/// Target traffic rate. This is combined for the stream of real and cover messages. If the
	/// stream of real messages exceeds this rate incoming messages will be dropped.
	pub target_bits_per_second: u32,
	/// Connection read timeout in milliseconds.
	pub timeout_ms: u32,
	/// Number of hops for the outgoing messages to traverse. If no topology provide is specified
	/// this setting is ignored and only one hop is used.
	pub num_hops: u32,
	/// Average number of seconds to delay each each message fragment at each hop.
	pub average_message_delay_ms: u32,
	/// Limit number of message in a windows of time for a peer.
	/// Default value, this can be change from topology.
	/// Above limit message are drop, so topology should raise the
	/// limit for routing peers.
	/// `None` is unlimited.
	/// Window is `WINDOW_BACKPRESSURE` duration.
	pub limit_per_window: Option<u32>,
}

impl Config {
	pub fn new_with_ed25519_keypair(kp: &Keypair, id: MixPeerId) -> Self {
		Self {
			secret_key: secret_from_ed25519(&kp.secret()),
			public_key: public_from_ed25519(&kp.public()),
			local_id: id,
			target_bits_per_second: 128 * 1024,
			timeout_ms: 5000,
			num_hops: 3,
			average_message_delay_ms: 500,
			limit_per_window: Some(
				(crate::network::WINDOW_BACKPRESSURE.as_millis() as u32 / 500) * 2,
			),
		}
	}
}
