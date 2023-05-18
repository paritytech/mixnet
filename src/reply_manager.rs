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

//! A mixnode may receive the same request multiple times due to retransmission (see eg
//! [`request_manager`](super::request_manager)). A [`ReplyManager`] can be used to cache replies,
//! to avoid needing to execute requests more than once.

use super::core::{MessageId, Mixnet, RequestMessage, SessionIndex, Surb, MESSAGE_ID_SIZE};
use hashlink::{linked_hash_map::Entry, LinkedHashMap};
use log::{debug, warn};
use rand::RngCore;
use std::time::{Duration, Instant};

/// Reply manager configuration.
#[derive(Clone, Debug)]
pub struct Config {
	/// The target for log messages.
	pub log_target: &'static str,
	/// Maximum number of requests to remember. When this limit is reached, old requests will be
	/// automatically discarded to make space for new ones.
	pub capacity: usize,
	/// Maximum number of copies of a reply message to post in response to a single request
	/// message. Note that the number of copies is also limited by the number of SURBs provided in
	/// the request message.
	pub max_posts: usize,
	/// After replying to a request, ignore repeats of the request for this length of time. This
	/// should ideally be set such that extra copies of a request message posted at the same time
	/// as the first received one get ignored, but retries posted after a timeout do not.
	pub cooldown: Duration,
}

impl Default for Config {
	fn default() -> Self {
		Self {
			log_target: "mixnet",
			capacity: 400,
			max_posts: 2,
			cooldown: Duration::from_secs(10),
		}
	}
}

struct Reply {
	/// The _reply_ message ID.
	message_id: MessageId,
	data: Vec<u8>,
}

impl Reply {
	fn new(data: Vec<u8>) -> Self {
		let mut message_id = [0; MESSAGE_ID_SIZE];
		rand::thread_rng().fill_bytes(&mut message_id);
		Self { message_id, data }
	}
}

/// Context needed to reply to a request.
pub struct ReplyContext {
	session_index: SessionIndex,
	/// The _request_ message ID.
	message_id: MessageId,
	surbs: Vec<Surb>,
}

impl ReplyContext {
	/// Returns a reference to the request message ID.
	pub fn message_id(&self) -> &MessageId {
		&self.message_id
	}

	fn post_reply(&mut self, reply: &Reply, mixnet: &mut Mixnet, config: &Config) {
		let data = [self.message_id.as_slice(), &reply.data];
		let data = data.as_slice().into();

		for _ in 0..config.max_posts {
			if let Err(err) =
				mixnet.post_reply(&mut self.surbs, self.session_index, &reply.message_id, data)
			{
				warn!(target: config.log_target,
					"Failed to post reply to request with message ID {:x?}: {err}",
					self.message_id);
				break
			}
		}
	}
}

enum ReplyState {
	/// The request is currently being handled.
	Pending,
	/// The request has been handled already.
	Complete { reply: Reply, last_post: Instant },
}

/// Reply manager state.
pub struct ReplyManager {
	config: Config,
	states: LinkedHashMap<MessageId, ReplyState>,
}

impl ReplyManager {
	/// Create a new `ReplyManager` with the given configuration.
	pub fn new(config: Config) -> Self {
		let states = LinkedHashMap::with_capacity(
			// Plus one because we only evict _after_ going over the limit
			config.capacity.saturating_add(1),
		);
		Self { config, states }
	}

	fn maybe_evict(&mut self) {
		if self.states.len() > self.config.capacity {
			self.states.pop_front();
			debug_assert_eq!(self.states.len(), self.config.capacity);
		}
	}

	/// Attempt to insert a request.
	///
	/// If the request is already present, posts the reply if necessary, and returns `None`. The
	/// caller does not need to do anything more.
	///
	/// If `Some` is returned, the caller should handle the request and then call either
	/// [`abandon`](Self::abandon) or [`complete`](Self::complete) with the [`ReplyContext`]. The
	/// `Vec<u8>` contains the request message data.
	pub fn insert(
		&mut self,
		message: RequestMessage,
		mixnet: &mut Mixnet,
	) -> Option<(ReplyContext, Vec<u8>)> {
		let mut reply_context = ReplyContext {
			session_index: message.session_index,
			message_id: message.id,
			surbs: message.surbs,
		};

		match self.states.entry(message.id) {
			Entry::Occupied(mut entry) => {
				match entry.get_mut() {
					ReplyState::Pending => debug!(target: self.config.log_target,
						"Ignoring repeat request with message ID {:x?}; currently handling", message.id),
					ReplyState::Complete { reply, last_post } => {
						let now = Instant::now();
						let since_last = now.saturating_duration_since(*last_post);
						if since_last < self.config.cooldown {
							debug!(target: self.config.log_target,
								"Ignoring repeat request with message ID {:x?}; posted a reply {:.1}s ago",
								message.id, since_last.as_secs_f32());
						} else {
							*last_post = now;
							reply_context.post_reply(reply, mixnet, &self.config);
						}
					},
				}
				None
			},
			Entry::Vacant(entry) => {
				entry.insert(ReplyState::Pending);
				self.maybe_evict();
				Some((reply_context, message.data))
			},
		}
	}

	/// Abandon a request. This should be called if you do not wish to reply at this time. If
	/// [`insert`](Self::insert) is called again with a matching message (same ID), it will return
	/// `Some`, and you will have another chance to handle the request.
	pub fn abandon(&mut self, reply_context: ReplyContext) {
		if let Entry::Occupied(entry) = self.states.entry(reply_context.message_id) {
			match entry.get() {
				ReplyState::Pending => {
					entry.remove();
				},
				ReplyState::Complete { .. } => warn!(
					target: self.config.log_target,
					"Ignoring abandon of request with message ID {:x?}; already completed",
					reply_context.message_id
				),
			}
		}
	}

	/// Complete a request. This will post the reply and cache it for repeat requests. Note that
	/// the reply message is implicitly prefixed with the request message ID
	/// (`reply_context.message_id()`).
	pub fn complete(
		&mut self,
		mut reply_context: ReplyContext,
		data: Vec<u8>,
		mixnet: &mut Mixnet,
	) {
		let state = match self.states.entry(reply_context.message_id) {
			Entry::Occupied(entry) => match entry.into_mut() {
				state @ ReplyState::Pending => state,
				ReplyState::Complete { .. } => {
					warn!(target: self.config.log_target,
						"Request with message ID {:x?} completed twice",
						reply_context.message_id);
					return
				},
			},
			Entry::Vacant(entry) => entry.insert(ReplyState::Pending),
		};

		let reply = Reply::new(data);
		reply_context.post_reply(&reply, mixnet, &self.config);
		*state = ReplyState::Complete { reply, last_post: Instant::now() };

		self.maybe_evict();
	}
}
