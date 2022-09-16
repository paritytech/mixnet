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
use std::time::Duration;

/// Default bandwidth to maintain for each connection.
/// In number of bytes per seconds
const DEFAULT_PEER_CONNECTION: u32 = 128 * 1024;

/// Size of the polling window in time.
pub const DEFAULT_WINDOW_SIZE: Duration = Duration::from_secs(2);

const DEFAULT_NO_YIELD_BUDGET: usize = 128;

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
	/// Size of window for reporting stat and ensuring
	/// bandwidth expectation. In millis seconds.
	pub window_size_ms: u64,
	/// Mixnet will yield if it did not for that many
	/// consecutive poll calls.
	pub no_yield_budget: usize,
	/// Peer handshake connection when
	/// dropped can persist due to multiplexing.
	/// In this case keep peer id info to be
	/// able to reconnect faster.
	/// TODO a ttl
	pub keep_handshaken_disconnected_address: bool,

	/// When topology change, usually connection will
	/// be closed and usually as many connection will
	/// be opened. A gracefull period can be use to
	/// avoid breaking too many connections.
	/// During this period closed and open connection
	/// from topology change will use half the available
	/// bandwidth.
	/// So usually depending on network load, this should
	/// be set to the average round trip or twice it.
	/// Note that this period should be the same for all peers.
	pub graceful_topology_change_period_ms: u64,

	/// Keep forwarded messages in queue for a given time.
	/// (message is only queued if topology allows it and the
	/// peer will potentially connect).
	pub queue_message_unconnected_ms: u64,

	/// Limit total number of queued message received by a single peer.
	pub queue_message_unconnected_number: u32,
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
		let average_message_delay_ms: u32 = 500;
		let target_bytes_per_second = DEFAULT_PEER_CONNECTION;
		let packet_duration_ms =
			crate::PACKET_SIZE as u64 * 1_000 / target_bytes_per_second as u64;
		let graceful_topology_change_period_ms = crate::core::sphinx::MAX_HOPS as u64 * (average_message_delay_ms as u64 + packet_duration_ms) * 2;
		Self {
			secret_key,
			public_key,
			local_id: id,
			target_bytes_per_second,
			timeout_ms: 5000,
			num_hops: 3,
			average_message_delay_ms,
			surb_ttl_ms: 100_000,
			replay_ttl_ms: 100_000,
			persist_surb_query: true,
			no_yield_budget: DEFAULT_NO_YIELD_BUDGET,
			keep_handshaken_disconnected_address: true,
			graceful_topology_change_period_ms,
			queue_message_unconnected_ms: 0,
			queue_message_unconnected_number: 0,
			window_size_ms: DEFAULT_WINDOW_SIZE
				.as_millis()
				.try_into()
				.expect("Window duration too big"),
		}
	}
}
