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

use crate::{MixPeerId, MixPublicKey, MixSecretKey};

const WINDOW_BACKPRESSURE: std::time::Duration = std::time::Duration::from_secs(5);

/// Configuration data for the mixnet protocol.
#[derive(Clone)]
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
	pub limit_per_window: Option<usize>,
	/// Same as `limit_per_window` but for connection that are routing.
	pub limit_per_window_routing: Option<u32>,
	/// Retention time until we drop surb query.
	pub surb_ttl_ms: u64,
	/// Retention time until we drop surb replay protection.
	pub replay_ttl_ms: u64,
	/// Do we keep trace of query with the surb keys.
	pub persist_surb_query: bool,
}

impl Config {
	pub fn new(id: MixPeerId) -> Self {
		let mut secret = [0u8; 32];
		use rand::RngCore;
		rand::thread_rng().fill_bytes(&mut secret);
		let secret_key: MixSecretKey = secret.into();
		let public_key = MixPublicKey::from(&secret_key);
		Self::new_with_keys(id, public_key, secret_key)
	}

	pub fn new_with_keys(
		id: MixPeerId,
		public_key: MixPublicKey,
		secret_key: MixSecretKey,
	) -> Self {
		Self {
			secret_key,
			public_key,
			local_id: id,
			target_bits_per_second: 128 * 1024,
			timeout_ms: 5000,
			num_hops: 3,
			average_message_delay_ms: 500,
			limit_per_window: Some((WINDOW_BACKPRESSURE.as_millis() as usize / 250) * 2),
			limit_per_window_routing: None,
			surb_ttl_ms: 100_000,
			replay_ttl_ms: 100_000,
			persist_surb_query: true,
		}
	}
}
