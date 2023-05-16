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

//! For more reliable delivery, a [`RequestManager`] can be used instead of calling
//! [`Mixnet::post_request`] directly. A [`RequestManager`] serves as an additional buffer for
//! requests, and will retry posting if requests are not removed within the expected time.

mod config;
mod pool;
mod post_queues;

pub use self::config::Config;
use self::{
	pool::{Handle, Pool},
	post_queues::PostQueues,
};
use super::core::{
	MessageId, Mixnet, MixnodeIndex, NetworkStatus, PostErr, RelSessionIndex, Scattered,
	SessionIndex, SessionPhase, SessionStatus,
};
use rand::RngCore;
use std::{
	cmp::max,
	collections::VecDeque,
	time::{Duration, Instant},
};

/// Requests managed by a [`RequestManager`] must implement this trait.
pub trait Request {
	/// Opaque context type; a `&Context` is passed through [`RequestManager`] methods to `Request`
	/// methods.
	type Context;

	/// Call `f` with the message data. The same data must be provided every time this is called.
	fn with_data<T>(&self, f: impl FnOnce(Scattered<u8>) -> T, context: &Self::Context) -> T;
	/// Returns the number of SURBs that should be sent along with the request. The same number
	/// must be returned every time this is called.
	fn num_surbs(&self, context: &Self::Context) -> usize;
	/// Returns a conservative estimate of the handling delay. That is, the maximum time it should
	/// take for the destination mixnode to process the request and post a reply.
	fn handling_delay(&self, message_id: &MessageId, context: &Self::Context) -> Duration;

	/// Called if an unrecoverable error is encountered while posting to the mixnet.
	fn handle_post_err(self, err: PostErr, context: &Self::Context);
	/// Called if we cannot retry posting because the configured limit has been reached.
	fn handle_retry_limit_reached(self, context: &Self::Context);
}

struct RequestState<R> {
	request: R,

	destinations_remaining: u32,
	retries_remaining: u32,
	/// This is decremented on insertion into the post queue.
	posts_remaining: u32,

	message_id: MessageId,
	/// Should be `None` iff `destination_index` is `None`.
	session_index: Option<SessionIndex>,
	destination_index: Option<MixnodeIndex>,
	retry_deadline: Instant,
}

impl<R> RequestState<R> {
	/// `past` should be some instant in the past.
	fn new_destination(&mut self, past: Instant) {
		// Change message ID when changing destination; a message ID should only be known by the
		// sender and receiver. Assuming that message IDs are used to identify replies, this will
		// mean that we no longer recognise replies from the previous destination. We only switch
		// if there is an issue with the previous destination (eg the session is ending, or it has
		// not replied), so this shouldn't matter much. TODO We could keep the old message ID
		// around as well as the new one and match against it in remove().
		rand::thread_rng().fill_bytes(&mut self.message_id);
		self.session_index = None;
		self.destination_index = None;
		self.retry_deadline = past;
	}
}

/// Request manager state. The user is responsible for calling
/// [`update_session_status`](Self::update_session_status),
/// [`process_post_queues`](Self::process_post_queues), and
/// [`pop_next_retry`](Self::pop_next_retry) at the appropriate times to make progress.
pub struct RequestManager<R> {
	config: Config,
	created_at: Instant,
	session_status: SessionStatus,
	pool: Pool<RequestState<R>>,
	/// `post_queues.prev` should be empty if `session_status.current_index` is 0, or if
	/// previous-session requests are not allowed in the current phase. Similarly,
	/// `post_queues.current` should be empty if current-session requests are not allowed in the
	/// current phase.
	post_queues: PostQueues,
	retry_queue: VecDeque<Handle>,
	next_retry_deadline_changed: bool,
}

impl<C, R: Request<Context = C>> RequestManager<R> {
	/// Create a new `RequestManager` with the given configuration.
	pub fn new(config: Config) -> Self {
		let capacity = config.capacity;
		Self {
			config,
			created_at: Instant::now(),
			session_status: SessionStatus {
				current_index: 0,
				phase: SessionPhase::ConnectToCurrent,
			},
			pool: Pool::new(capacity),
			post_queues: PostQueues::new(capacity),
			retry_queue: VecDeque::with_capacity(capacity as usize),
			next_retry_deadline_changed: false,
		}
	}

	/// Update the current session index and phase. This should be called after
	/// [`Mixnet::set_session_status`]. This may post messages to `mixnet`.
	pub fn update_session_status(
		&mut self,
		mixnet: &mut Mixnet,
		ns: &dyn NetworkStatus,
		context: &C,
	) {
		let session_status = mixnet.session_status();
		if self.session_status == session_status {
			return
		}

		let prev_default_len = self.post_queues.default.len();

		if self.session_status.current_index != session_status.current_index {
			self.post_queues.default.append(&mut self.post_queues.prev);
			if session_status.current_index.saturating_sub(self.session_status.current_index) == 1 {
				std::mem::swap(&mut self.post_queues.current, &mut self.post_queues.prev);
			} else {
				// Unexpected session index change. Mixnet core will warn about this, don't bother
				// warning again here.
				self.post_queues.default.append(&mut self.post_queues.current);
			}
		}

		if !session_status.phase.allow_requests_and_replies(RelSessionIndex::Current) {
			self.post_queues.default.append(&mut self.post_queues.current);
		}
		if !session_status.phase.allow_requests_and_replies(RelSessionIndex::Prev) {
			self.post_queues.default.append(&mut self.post_queues.prev);
		}

		for handle in self.post_queues.default.iter().skip(prev_default_len) {
			self.pool[*handle].new_destination(self.created_at);
		}

		self.session_status = session_status;

		// The session status shouldn't change very often. For simplicity just retry posting in all
		// sessions, rather than trying to figure out if we can skip some.
		self.process_post_queues(mixnet, ns, context);
	}

	/// Returns `true` iff there is space for another request.
	pub fn has_space(&self) -> bool {
		self.pool.has_space()
	}

	/// Insert a request. This should only be called if there is space (see
	/// [`has_space`](Self::has_space)). This may post messages to `mixnet`.
	///
	/// A request is only removed when:
	///
	/// - [`remove`](Self::remove) is called with the corresponding message ID. This would typically
	///   happen when a reply is received.
	/// - An unrecoverable error is encountered while posting to the mixnet. In this case,
	///   [`Request::handle_post_err`] is called.
	/// - The retry limit is reached. In this case, [`Request::handle_retry_limit_reached`] is
	///   called.
	pub fn insert(&mut self, request: R, mixnet: &mut Mixnet, ns: &dyn NetworkStatus, context: &C) {
		let state = RequestState {
			request,

			destinations_remaining: self.config.num_destinations,
			retries_remaining: 0,
			posts_remaining: 0,

			// The message ID will get generated when retry (below) calls state.new_destination()
			message_id: Default::default(),
			session_index: None,
			destination_index: None,
			retry_deadline: self.created_at,
		};
		let handle = self.pool.alloc(state).expect("Should only insert if there is space");
		self.retry(handle, mixnet, ns, context);
	}

	/// Remove a request. Typically this would be called when a reply is received. Returns `None`
	/// if there is no request with the given message ID.
	pub fn remove(&mut self, message_id: &MessageId) -> Option<R> {
		let Some((handle, _)) = self.pool.iter().find(|(_, state)| &state.message_id == message_id) else {
			return None
		};

		for post_queue in self.post_queues.iter_mut() {
			if let Some(i) = post_queue.iter().position(|h| *h == handle) {
				post_queue.remove(i);
			}
		}

		if let Some(i) = self.retry_queue.iter().position(|h| *h == handle) {
			self.retry_queue.remove(i);
			if i == 0 {
				self.next_retry_deadline_changed = true;
			}
		}

		Some(self.pool.free(handle).request)
	}

	fn process_post_queue(
		&mut self,
		rel_session_index: Option<RelSessionIndex>,
		mixnet: &mut Mixnet,
		ns: &dyn NetworkStatus,
		context: &C,
	) {
		let rel_session_index_or_default =
			rel_session_index.unwrap_or(self.session_status.phase.default_request_session());
		if (rel_session_index_or_default == RelSessionIndex::Prev) &&
			(self.session_status.current_index == 0)
		{
			// The session does not exist. If this is the default session queue, just wait for the
			// default session to change.
			debug_assert!(self.post_queues.prev.is_empty());
			return
		}

		let session_index = rel_session_index
			.map(|rel_session_index| rel_session_index + self.session_status.current_index);
		let session_index_or_default =
			rel_session_index_or_default + self.session_status.current_index;

		while let Some(handle) = self.post_queues[rel_session_index].pop_front() {
			let state = &mut self.pool[handle];
			debug_assert_eq!(state.session_index, session_index);

			// Attempt to post a request message
			let res = state.request.with_data(
				|data| {
					mixnet.post_request(
						session_index_or_default,
						&mut state.destination_index,
						&state.message_id,
						data,
						state.request.num_surbs(context),
						ns,
					)
				},
				context,
			);

			match res {
				Ok(metrics) => {
					state.session_index = Some(session_index_or_default);

					// Extend the retry deadline
					let handling_delay = state.request.handling_delay(&state.message_id, context);
					let rtt = metrics.estimate_rtt(self.config.per_hop_net_delay, handling_delay);
					state.retry_deadline = max(state.retry_deadline, Instant::now() + rtt);

					match state.posts_remaining.checked_sub(1) {
						Some(posts_remaining) => {
							state.posts_remaining = posts_remaining;
							self.post_queues[Some(rel_session_index_or_default)].push_back(handle);
						},
						None => {
							let deadline = state.retry_deadline;
							let i = self.retry_queue.partition_point(|handle| {
								self.pool[*handle].retry_deadline < deadline
							});
							self.retry_queue.insert(i, handle);
							if i == 0 {
								self.next_retry_deadline_changed = true;
							}
						},
					}
				},
				Err(PostErr::NotEnoughSpaceInQueue) => {
					// In this case, nothing should have changed. Just push the request back on the
					// front of the queue and try again later.
					self.post_queues[rel_session_index].push_front(handle);
					break
				},
				Err(err) => self.pool.free(handle).request.handle_post_err(err, context),
			}
		}
	}

	/// Attempt to transfer messages from the internal post queues to `mixnet`. This should be
	/// called when the
	/// [`SPACE_IN_AUTHORED_PACKET_QUEUE`](super::core::Events::SPACE_IN_AUTHORED_PACKET_QUEUE)
	/// event fires.
	pub fn process_post_queues(
		&mut self,
		mixnet: &mut Mixnet,
		ns: &dyn NetworkStatus,
		context: &C,
	) {
		// Process the default session queue first, as doing so might result in requests getting
		// pushed onto the other queues
		self.process_post_queue(None, mixnet, ns, context);
		self.process_post_queue(Some(RelSessionIndex::Current), mixnet, ns, context);
		self.process_post_queue(Some(RelSessionIndex::Prev), mixnet, ns, context);
	}

	fn session_post_queues_empty(&self, rel_session_index: Option<RelSessionIndex>) -> bool {
		if !self.post_queues[rel_session_index].is_empty() {
			return false
		}
		let default = self.session_status.phase.default_request_session();
		match rel_session_index {
			Some(rel_session_index) if rel_session_index == default =>
				self.post_queues.default.is_empty(),
			Some(_) => true,
			None => self.post_queues[Some(default)].is_empty(),
		}
	}

	fn retry(&mut self, handle: Handle, mixnet: &mut Mixnet, ns: &dyn NetworkStatus, context: &C) {
		let state = &mut self.pool[handle];

		debug_assert_eq!(state.posts_remaining, 0);
		match state.retries_remaining.checked_sub(1) {
			Some(retries_remaining) => state.retries_remaining = retries_remaining,
			None => {
				let Some(destinations_remaining) = state.destinations_remaining.checked_sub(1) else {
					self.pool.free(handle).request.handle_retry_limit_reached(context);
					return
				};
				state.destinations_remaining = destinations_remaining;
				state.retries_remaining = self.config.num_retries_per_destination - 1;
				state.new_destination(self.created_at);
			},
		}
		state.posts_remaining = self.config.num_posts_per_retry - 1;

		let rel_session_index = state.session_index.and_then(|session_index| {
			let rel_session_index = RelSessionIndex::from_session_index(
				session_index,
				self.session_status.current_index,
			);
			if !rel_session_index.map_or(false, |rel_session_index| {
				self.session_status.phase.allow_requests_and_replies(rel_session_index)
			}) {
				state.new_destination(self.created_at);
				return None
			}
			rel_session_index
		});

		let empty = self.session_post_queues_empty(rel_session_index);
		self.post_queues[rel_session_index].push_back(handle);
		if empty {
			// There were no requests waiting. It might be possible to post immediately.
			self.process_post_queue(rel_session_index, mixnet, ns, context);
			if rel_session_index.is_none() {
				// Might have pushed requests onto this queue while processing the default session
				// queue
				self.process_post_queue(
					Some(self.session_status.phase.default_request_session()),
					mixnet,
					ns,
					context,
				);
			}
		}
	}

	/// Returns the next instant at which [`pop_next_retry`](Self::pop_next_retry) should be
	/// called.
	pub fn next_retry_deadline(&self) -> Option<Instant> {
		self.retry_queue.front().map(|handle| self.pool[*handle].retry_deadline)
	}

	/// Pop the next request from the internal retry queue. This should be called whenever the
	/// deadline returned by [`next_retry_deadline`](Self::next_retry_deadline) is reached. This
	/// may post messages to `mixnet`. Returns `false` if the internal retry queue is empty.
	pub fn pop_next_retry(
		&mut self,
		mixnet: &mut Mixnet,
		ns: &dyn NetworkStatus,
		context: &C,
	) -> bool {
		if let Some(handle) = self.retry_queue.pop_front() {
			self.next_retry_deadline_changed = true;
			self.retry(handle, mixnet, ns, context);
			true
		} else {
			false
		}
	}

	/// Returns `true` if the next retry deadline (see
	/// [`next_retry_deadline`](Self::next_retry_deadline)) has changed since the last call.
	pub fn next_retry_deadline_changed(&mut self) -> bool {
		let changed = self.next_retry_deadline_changed;
		self.next_retry_deadline_changed = false;
		changed
	}
}
