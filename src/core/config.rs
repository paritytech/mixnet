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

/// Default bandwidth to maintain for each connection.
/// In number of bytes per seconds
const DEFAULT_PEER_CONNECTION: u32 = 128 * 1024;

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
	pub target_bytes_per_second: u32,
	/// Connection read timeout in milliseconds.
	pub timeout_ms: u32,
	/// Default umber of hops for the outgoing messages to traverse. If no topology provide is
	/// specified this setting is ignored and only one hop is used.
	pub num_hops: u32,
	/// Average number of seconds to delay each message fragment at each hop.
	pub average_message_delay_ms: u32,
	/// Retention time until we drop surb query.
	pub surb_ttl_ms: u64,
	/// Retention time until we drop surb replay protection.
	pub replay_ttl_ms: u64,
	/// Do we keep trace of query with the surb keys.
	pub persist_surb_query: bool,
}

impl Config {
	pub fn new(id: MixPeerId) -> Self {
		let (public_key, secret_key) = super::generate_new_keys();
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
			target_bytes_per_second: DEFAULT_PEER_CONNECTION,
			timeout_ms: 5000,
			num_hops: 3,
			average_message_delay_ms: 500,
			surb_ttl_ms: 100_000,
			replay_ttl_ms: 100_000,
			persist_surb_query: true,
		}
	}
}
