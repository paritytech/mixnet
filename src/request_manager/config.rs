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

use std::time::Duration;

/// Request manager configuration.
#[derive(Clone, Debug)]
pub struct Config {
	/// Maximum number of requests that can be managed at once.
	pub capacity: super::pool::Index,

	/// Number of different destinations to try sending a request to before giving up.
	pub num_destinations: u32,
	/// Number of times to retry a destination after timing out before moving on to the next
	/// destination. Must not be 0.
	pub num_retries_per_destination: u32,
	/// Number of copies of the message to post each time we send a request. Must not be 0.
	pub num_posts_per_retry: u32,

	/// Conservative estimate of the network (and processing) delay per hop.
	pub per_hop_net_delay: Duration,
}

impl Default for Config {
	fn default() -> Self {
		Self {
			capacity: 20,

			num_destinations: 3,
			num_retries_per_destination: 2,
			num_posts_per_retry: 2,

			per_hop_net_delay: Duration::from_millis(300),
		}
	}
}
