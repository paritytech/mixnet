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

//! Mixnet core logic. This module tries to be network agnostic.

// Get a bunch of these from [mut_]array_refs
#![allow(clippy::ptr_offset_with_cast)]

mod config;
mod cover;
mod fragment;
mod kx_store;
mod packet_queues;
mod replay_filter;
mod request_builder;
mod scattered;
mod sessions;
mod sphinx;
mod surb_keystore;
mod topology;
mod util;

pub use self::{
	config::{Config, SessionConfig},
	fragment::{MessageId, MESSAGE_ID_SIZE},
	kx_store::KxPublicStore,
	packet_queues::AddressedPacket,
	scattered::Scattered,
	sessions::{RelSessionIndex, SessionIndex, SessionPhase, SessionStatus},
	sphinx::{
		Delay, KxPublic, MixnodeIndex, Packet, PeerId, RawMixnodeIndex, Surb, KX_PUBLIC_SIZE,
		MAX_HOPS, MAX_MIXNODE_INDEX, PACKET_SIZE, PEER_ID_SIZE, SURB_SIZE,
	},
	topology::{Mixnode, NetworkStatus, TopologyErr},
};
use self::{
	cover::{gen_cover_packet, CoverKind},
	fragment::{fragment_blueprints, FragmentAssembler},
	kx_store::KxStore,
	packet_queues::{AuthoredPacketQueue, CheckSpaceErr, ForwardPacketQueue},
	replay_filter::ReplayFilter,
	request_builder::RequestBuilder,
	sessions::{Session, SessionSlot, Sessions},
	sphinx::{
		complete_reply_packet, decrypt_reply_payload, kx_public, mut_payload_data, peel, Action,
		PeelErr, PAYLOAD_DATA_SIZE, PAYLOAD_SIZE,
	},
	surb_keystore::SurbKeystore,
	topology::Topology,
	util::default_boxed_array,
};
use arrayref::{array_mut_ref, array_ref};
use arrayvec::ArrayVec;
use bitflags::bitflags;
use either::Either;
use log::{debug, error, info, warn};
use multiaddr::Multiaddr;
use rand::Rng;
use std::{
	cmp::{max, min},
	collections::HashSet,
	sync::Arc,
	time::{Duration, Instant},
};

/// Error querying the mixnodes for a session.
pub enum MixnodesErr {
	/// Transient error. The query might succeed later. Do not disable the mixnet for the session.
	Transient,
	/// Permanent error. The query will never succeed. Disable the mixnet for the session.
	Permanent,
}

/// A request from another node.
#[derive(Debug, PartialEq, Eq)]
pub struct RequestMessage {
	/// Index of the session this message was received in. This session index should be used when
	/// sending replies.
	pub session_index: SessionIndex,
	/// Message identifier, explicitly provided by the request sender.
	pub id: MessageId,
	/// The message contents.
	pub data: Vec<u8>,
	/// SURBs that were attached to the message. These can be used to send replies.
	pub surbs: Vec<Surb>,
}

/// A reply to a previously sent request.
#[derive(Debug, PartialEq, Eq)]
pub struct ReplyMessage {
	/// The message contents.
	pub data: Vec<u8>,
}

/// A message received over the mixnet.
#[derive(Debug, PartialEq, Eq)]
pub enum Message {
	/// A request from another node.
	Request(RequestMessage),
	/// A reply to a previously sent request.
	Reply(ReplyMessage),
}

/// Request/reply posting error.
#[derive(Debug, thiserror::Error)]
pub enum PostErr {
	/// Message contents too large or too many SURBs.
	#[error("Message would need to be split into too many fragments")]
	TooManyFragments,
	/// The session is no longer active.
	#[error("Session {0} is no longer active")]
	SessionNoLongerActive(SessionIndex),
	/// The session is not active yet.
	#[error("Session {0} is not active yet")]
	SessionNotActiveYet(SessionIndex),
	/// Mixnodes not yet known for the session.
	#[error("Mixnodes not yet known for session {0}")]
	SessionEmpty(SessionIndex),
	/// Mixnet disabled for the session.
	#[error("Mixnet disabled for session {0}")]
	SessionDisabled(SessionIndex),
	/// Not enough space in the authored packet queue.
	#[error("There is not enough space in the authored packet queue")]
	NotEnoughSpaceInQueue,
	/// Topology error.
	#[error("Topology error: {0}")]
	Topology(#[from] TopologyErr),
	/// Bad SURB.
	#[error("Bad SURB")]
	BadSurb,
}

fn post_session(
	sessions: &mut Sessions,
	status: SessionStatus,
	index: SessionIndex,
) -> Result<&mut Session, PostErr> {
	let Some(rel_index) = RelSessionIndex::from_session_index(index, status.current_index) else {
		return Err(if index < status.current_index {
			PostErr::SessionNoLongerActive(index)
		} else {
			PostErr::SessionNotActiveYet(index)
		})
	};
	if !status.phase.allow_requests_and_replies(rel_index) {
		return Err(match rel_index {
			RelSessionIndex::Prev => PostErr::SessionNoLongerActive(index),
			RelSessionIndex::Current => PostErr::SessionNotActiveYet(index),
		})
	}
	match &mut sessions[rel_index] {
		SessionSlot::Empty => Err(PostErr::SessionEmpty(index)),
		// Note that in the case where the session has been disabled because it is no longer
		// needed, we will enter the !allow_requests_and_replies if above and not get here
		SessionSlot::Disabled => Err(PostErr::SessionDisabled(index)),
		SessionSlot::Full(session) => Ok(session),
	}
}

impl From<CheckSpaceErr> for PostErr {
	fn from(value: CheckSpaceErr) -> Self {
		match value {
			CheckSpaceErr::Capacity => PostErr::TooManyFragments,
			CheckSpaceErr::Len => PostErr::NotEnoughSpaceInQueue,
		}
	}
}

/// Returns a conservative estimate of the time taken for the last packet in the authored packet
/// queue to get dispatched plus the time taken for all reply packets to get through the authored
/// packet queue at the far end.
fn estimate_authored_packet_queue_delay(config: &Config, session: &Session) -> Duration {
	let rate_mul =
		// In the worst case, when transitioning between two sessions with equal rate, the rate is
		// effectively halved
		0.5 *
		// Loop cover packets are never replaced with packets from the authored packet queue
		(1.0 - config.loop_cover_proportion);
	let request_period = session.mean_authored_packet_period.div_f64(rate_mul);
	let request_len = session.authored_packet_queue.len();
	// Assume that the destination mixnode is using the same configuration as us
	let reply_period = config.mixnode_session.mean_authored_packet_period.div_f64(rate_mul);
	let reply_len = config.mixnode_session.authored_packet_queue.capacity; // Worst case

	// The delays between authored packet queue pops follow an exponential distribution. The sum of
	// n independent exponential random variables with scale s follows a gamma distribution with
	// shape n and scale s. A reasonable approximation to the 99.995th percentile of the gamma
	// distribution with shape n and scale s is:
	//
	// s * (4.92582 + (3.87809 * sqrt(n)) + n)
	//
	// The constants were obtained by fitting to the actual values for n=1..200.
	//
	// This isn't quite what we want here; we are interested in the sum of two gamma-distributed
	// random variables with different scales (request_period and reply_period). An approximation
	// to the 99.995th percentile of such a sum is:
	//
	// s * (4.92582 + (3.87809 * sqrt(n + (r^3 * m))) + n + (r * m))
	//
	// Where:
	//
	// - s is the larger scale.
	// - n is the corresponding shape.
	// - m is the other shape.
	// - r is the other scale divided by s (between 0 and 1).
	//
	// Note that when r is 0 this matches the first approximation, and when r is 1 this matches the
	// first approximation with n replaced by (n + m).
	let (s, n, m, rs) = if request_period > reply_period {
		(request_period, request_len, reply_len, reply_period)
	} else {
		(reply_period, reply_len, request_len, request_period)
	};
	let n = n as f64;
	let m = m as f64;
	let r = rs.as_secs_f64() / s.as_secs_f64();
	s.mul_f64(4.92582 + (3.87809 * (n + (r * r * r * m)).sqrt()) + n + (r * m))
}

/// Metrics that can be used to estimate a request's round-trip time.
pub struct RequestMetrics {
	/// The maximum number of hops for any of the fragments to reach the destination, plus the
	/// maximum number of hops for any of the SURBs to come back.
	pub num_hops: usize,
	/// Conservative estimate of the network (and processing) delay per hop.
	pub per_hop_net_delay: Duration,
	/// The maximum total forwarding delay for any request fragment, plus the maximum total
	/// forwarding delay for any SURB.
	pub forwarding_delay: Duration,
	/// A conservative estimate of the total delay through the authored packet queues at the source
	/// and destination.
	pub authored_packet_queue_delay: Duration,
}

impl RequestMetrics {
	/// Returns a conservative estimate of the round-trip time, suitable for use as a timeout.
	/// `handling_delay` should be a conservative estimate of the time taken to handle the request
	/// at the destination and post the reply.
	pub fn estimate_rtt(&self, handling_delay: Duration) -> Duration {
		let net_delay = self.per_hop_net_delay * (self.num_hops as u32);
		self.forwarding_delay + self.authored_packet_queue_delay + net_delay + handling_delay
	}
}

bitflags! {
	/// Flags to indicate events that have occurred. Note that these may be set spuriously.
	pub struct Events: u32 {
		/// The reserved peers returned by [`Mixnet::reserved_peer_addresses`] have changed.
		const RESERVED_PEERS_CHANGED = 0b1;
		/// The deadline returned by [`Mixnet::next_forward_packet_deadline`] has changed.
		const NEXT_FORWARD_PACKET_DEADLINE_CHANGED = 0b10;
		/// The effective deadline returned by [`Mixnet::next_authored_packet_delay`] has changed.
		/// The delay (and thus the effective deadline) is randomly generated according to an
		/// exponential distribution each time the function is called, but the last returned
		/// deadline remains valid until this bit indicates otherwise. Due to the memoryless nature
		/// of exponential distributions, it is harmless for this bit to be set spuriously.
		const NEXT_AUTHORED_PACKET_DEADLINE_CHANGED = 0b100;
		/// Space has become available in an authored packet queue.
		const SPACE_IN_AUTHORED_PACKET_QUEUE = 0b1000;
	}
}

/// Network-agnostic mixnet core.
pub struct Mixnet {
	config: Config,

	/// Index and phase of current session.
	session_status: SessionStatus,
	/// Keystore for the per-session key-exchange keys.
	kx_store: KxStore,
	/// Current and previous sessions.
	sessions: Sessions,

	/// Queue of packets to be forwarded, after some delay.
	forward_packet_queue: ForwardPacketQueue,

	/// Keystore for SURB payload encryption keys.
	surb_keystore: SurbKeystore,
	/// Reassembles fragments into messages. Note that for simplicity there is just one assembler
	/// for everything (requests and replies across all sessions).
	fragment_assembler: FragmentAssembler,

	/// Flags to indicate events that have occurred.
	events: Events,
}

impl Mixnet {
	/// Create a new `Mixnet`.
	pub fn new(config: Config, kx_public_store: Arc<KxPublicStore>) -> Self {
		let forward_packet_queue = ForwardPacketQueue::new(config.forward_packet_queue_capacity);

		let surb_keystore = SurbKeystore::new(config.surb_keystore_capacity);
		let fragment_assembler = FragmentAssembler::new(
			config.max_incomplete_messages,
			config.max_incomplete_fragments,
			config.max_fragments_per_message,
		);

		Self {
			config,

			session_status: SessionStatus {
				current_index: 0,
				phase: SessionPhase::ConnectToCurrent,
			},
			sessions: Sessions { current: SessionSlot::Empty, prev: SessionSlot::Disabled },
			kx_store: KxStore::new(kx_public_store),

			forward_packet_queue,

			surb_keystore,
			fragment_assembler,

			events: Events::empty(),
		}
	}

	/// Returns the current session index and phase.
	pub fn session_status(&self) -> SessionStatus {
		self.session_status
	}

	/// Sets the current session index and phase. The current and previous mixnodes may need to be
	/// provided after calling this; see [`maybe_set_mixnodes`](Self::maybe_set_mixnodes).
	pub fn set_session_status(&mut self, session_status: SessionStatus) {
		if self.session_status == session_status {
			return
		}

		// Shift sessions in self.sessions when current session changes
		if self.session_status.current_index != session_status.current_index {
			if session_status.current_index.saturating_sub(self.session_status.current_index) == 1 {
				// This will discard any replay filter we have for the (old) previous session. The
				// corresponding secret key will be discarded by the discard_sessions_before() call
				// below.
				self.sessions.advance_by_one();
			} else if !self.sessions.is_empty() {
				warn!(
					target: self.config.log_target,
					"Unexpected session index {}; previous session index was {}",
					session_status.current_index,
					self.session_status.current_index
				);
				// If discarding any replay filters, also discard the corresponding secret keys.
				// This is a bit overzealous in some cases, but this should never really happen so
				// don't worry about it too much.
				if self.sessions.current.is_full() {
					let Some(next_session_index) = self.session_status.current_index.checked_add(1) else {
						panic!("Session index overflow")
					};
					self.kx_store.discard_sessions_before(next_session_index);
				} else if self.sessions.prev.is_full() {
					self.kx_store.discard_sessions_before(self.session_status.current_index);
				}
				self.sessions = Sessions { current: SessionSlot::Empty, prev: SessionSlot::Empty };
			}
		}

		// Discard sessions which are no longer needed. Also, avoid ever having a previous session
		// when the current session index is 0... there is no sensible index for it.
		if !session_status.phase.need_prev() || (session_status.current_index == 0) {
			self.sessions.prev = SessionSlot::Disabled;
		}
		if session_status.current_index != 0 {
			let min_needed_rel_session_index = if session_status.phase.need_prev() {
				RelSessionIndex::Prev
			} else {
				RelSessionIndex::Current
			};
			self.kx_store.discard_sessions_before(
				min_needed_rel_session_index + session_status.current_index,
			);
		}

		// For simplicity just assume these have changed. This should happen at most once a minute
		// or so.
		self.events |=
			Events::RESERVED_PEERS_CHANGED | Events::NEXT_AUTHORED_PACKET_DEADLINE_CHANGED;

		self.session_status = session_status;

		info!(target: self.config.log_target, "Session status changed: {session_status}");
	}

	/// Sets the mixnodes for the specified session, if they are needed. If `mixnodes()` returns
	/// `Err(MixnodesErr::Permanent)`, the session slot will be disabled, and later calls to
	/// `maybe_set_mixnodes` for the session will return immediately. If `mixnodes()` returns
	/// `Err(MixnodesErr::Transient)`, the session slot will merely remain empty, and later calls to
	/// `maybe_set_mixnodes` may succeed.
	///
	/// The mixnode peer IDs are used for two things:
	///
	/// - Checking for connectivity (they are passed to [`NetworkStatus::is_connected`]).
	/// - Sending packets (they are put in [`AddressedPacket::peer_id`]).
	///
	/// The mixnode external addresses are merely collated and returned by
	/// [`reserved_peer_addresses`](Self::reserved_peer_addresses).
	pub fn maybe_set_mixnodes(
		&mut self,
		rel_session_index: RelSessionIndex,
		mixnodes: &mut dyn FnMut() -> Result<Vec<Mixnode>, MixnodesErr>,
	) {
		// Create the Session only if the slot is empty. If the slot is disabled, don't even try.
		let session = &mut self.sessions[rel_session_index];
		if !session.is_empty() {
			return
		}

		let session_index = rel_session_index + self.session_status.current_index;
		let mut rng = rand::thread_rng();

		// Build Topology struct
		let mut mixnodes = match mixnodes() {
			Ok(mixnodes) => mixnodes,
			Err(err) => {
				if matches!(err, MixnodesErr::Permanent) {
					*session = SessionSlot::Disabled;
				}
				return
			},
		};
		let max_mixnodes = (MAX_MIXNODE_INDEX + 1) as usize;
		if mixnodes.len() > max_mixnodes {
			warn!(
				target: self.config.log_target,
				"Session {session_index}: Too many mixnodes ({}, max {max_mixnodes}); ignoring excess",
				mixnodes.len()
			);
			mixnodes.truncate(max_mixnodes);
		}
		let Some(local_kx_public) = self.kx_store.public().public_for_session(session_index) else {
			error!(target: self.config.log_target,
				"Session {session_index}: Key-exchange keys discarded already; \
				mixnet will not be available");
			*session = SessionSlot::Disabled;
			return
		};
		let topology =
			Topology::new(&mut rng, mixnodes, &local_kx_public, self.config.num_gateway_mixnodes);

		// Determine session config
		let config = if topology.is_mixnode() {
			&self.config.mixnode_session
		} else {
			match &self.config.non_mixnode_session {
				Some(config) => config,
				None => {
					info!(target: self.config.log_target,
						"Session {session_index}: Local node is not a mixnode; \
						disabling mixnet as per configuration");
					*session = SessionSlot::Disabled;
					return
				},
			}
		};

		info!(target: self.config.log_target, "Session {session_index}: {topology}");

		// Build Session struct
		*session = SessionSlot::Full(Session {
			topology,
			authored_packet_queue: AuthoredPacketQueue::new(config.authored_packet_queue),
			mean_authored_packet_period: config.mean_authored_packet_period,
			replay_filter: ReplayFilter::new(&mut rng),
		});

		self.events |=
			Events::RESERVED_PEERS_CHANGED | Events::NEXT_AUTHORED_PACKET_DEADLINE_CHANGED;
	}

	/// Returns the addresses of the peers we should try to maintain connections to.
	pub fn reserved_peer_addresses(&self) -> HashSet<Multiaddr> {
		self.sessions
			.iter()
			.flat_map(|session| session.topology.reserved_peer_addresses())
			.cloned()
			.collect()
	}

	/// Handle an incoming packet. If the packet completes a message, the message is returned.
	/// Otherwise, [`None`] is returned.
	pub fn handle_packet(&mut self, packet: &Packet) -> Option<Message> {
		self.kx_store.add_pending_session_secrets();

		let mut out = [0; PACKET_SIZE];
		let res = self.sessions.enumerate_mut().find_map(|(rel_session_index, session)| {
			if session.replay_filter.contains(kx_public(packet)) {
				return Some(Err(Either::Left(
					"Packet key-exchange public key found in replay filter",
				)))
			}

			let session_index = rel_session_index + self.session_status.current_index;
			// If secret key for session not found, try other session
			let kx_shared_secret =
				self.kx_store.session_exchange(session_index, kx_public(packet))?;

			match peel(&mut out, packet, &kx_shared_secret) {
				// Bad MAC possibly means we used the wrong secret; try other session
				Err(PeelErr::Mac) => None,
				// Any other error means the packet is bad; just discard it
				Err(err) => Some(Err(Either::Right(err))),
				Ok(action) => Some(Ok((action, session_index, session))),
			}
		});

		let (action, session_index, session) = match res {
			None => {
				// This will usually get hit quite a bit on session changeover after we discard the
				// keys for the previous session
				debug!(
					target: self.config.log_target,
					"Failed to peel packet; either bad MAC or unknown secret"
				);
				return None
			},
			Some(Err(err)) => {
				error!(target: self.config.log_target, "Failed to peel packet: {err}");
				return None
			},
			Some(Ok(x)) => x,
		};

		match action {
			Action::ForwardTo { target, delay } => {
				if !session.topology.is_mixnode() {
					error!(target: self.config.log_target,
						"Received packet to forward despite not being a mixnode in the session; discarding");
					return None
				}

				if !self.forward_packet_queue.has_space() {
					warn!(target: self.config.log_target, "Dropped forward packet; forward queue full");
					return None
				}

				// After the is_mixnode check to avoid inserting anything into the replay filters
				// for sessions where we are not a mixnode
				session.replay_filter.insert(kx_public(packet));

				match session.topology.target_to_peer_id(&target) {
					Ok(peer_id) => {
						let deadline =
							Instant::now() + delay.to_duration(self.config.mean_forwarding_delay);
						let packet = AddressedPacket { peer_id, packet: out.into() };
						if self.forward_packet_queue.insert(deadline, packet) {
							self.events |= Events::NEXT_FORWARD_PACKET_DEADLINE_CHANGED;
						}
					},
					Err(err) => error!(
						target: self.config.log_target,
						"Failed to map target {target:?} to peer ID: {err}"
					),
				}

				None
			},
			Action::DeliverRequest => {
				let payload_data = array_ref![out, 0, PAYLOAD_DATA_SIZE];

				if !session.topology.is_mixnode() {
					error!(target: self.config.log_target,
						"Received request packet despite not being a mixnode in the session; discarding");
					return None
				}

				// After the is_mixnode check to avoid inserting anything into the replay filters
				// for sessions where we are not a mixnode
				session.replay_filter.insert(kx_public(packet));

				// Add to fragment assembler and return any completed message
				self.fragment_assembler.insert(payload_data, self.config.log_target).map(
					|message| {
						Message::Request(RequestMessage {
							session_index,
							id: message.id,
							data: message.data,
							surbs: message.surbs,
						})
					},
				)
			},
			Action::DeliverReply { surb_id } => {
				let payload = array_mut_ref![out, 0, PAYLOAD_SIZE];

				// Note that we do not insert anything into the replay filter here. The SURB ID
				// lookup will fail for replayed SURBs, so explicit replay prevention is not
				// necessary. The main reason for avoiding the replay filter here is so that it
				// does not need to be allocated at all for sessions where we are not a mixnode.

				// Lookup payload encryption keys and decrypt payload
				let Some(entry) = self.surb_keystore.entry(&surb_id) else {
					warn!(target: self.config.log_target,
						"Received reply with unrecognised SURB ID {surb_id:x?}; discarding");
					return None
				};
				let res = decrypt_reply_payload(payload, entry.keys());
				entry.remove();
				if let Err(err) = res {
					error!(target: self.config.log_target, "Failed to decrypt reply payload: {err}");
					return None
				}
				let payload_data = array_ref![payload, 0, PAYLOAD_DATA_SIZE];

				// Add to fragment assembler and return any completed message
				self.fragment_assembler.insert(payload_data, self.config.log_target).map(
					|message| {
						if !message.surbs.is_empty() {
							error!(target: self.config.log_target,
								"Reply message included SURBs; discarding them");
						}
						Message::Reply(ReplyMessage { data: message.data })
					},
				)
			},
			Action::DeliverCover { cover_id: _ } => None,
		}
	}

	/// Returns the next instant at which
	/// [`pop_next_forward_packet`](Self::pop_next_forward_packet) should be called. [`None`] means
	/// never.
	pub fn next_forward_packet_deadline(&self) -> Option<Instant> {
		self.forward_packet_queue.next_deadline()
	}

	/// Pop and return the packet at the head of the forward packet queue. Returns [`None`] if the
	/// queue is empty.
	pub fn pop_next_forward_packet(&mut self) -> Option<AddressedPacket> {
		self.events |= Events::NEXT_FORWARD_PACKET_DEADLINE_CHANGED;
		self.forward_packet_queue.pop()
	}

	/// Returns the delay after which [`pop_next_authored_packet`](Self::pop_next_authored_packet)
	/// should be called. [`None`] means an infinite delay.
	pub fn next_authored_packet_delay(&self) -> Option<Duration> {
		// Send packets at the maximum rate of any active session; pop_next_authored_packet will
		// choose between the sessions randomly based on their rates
		self.sessions
			.enumerate()
			.filter(|(rel_session_index, _)| {
				self.session_status.phase.gen_cover_packets(*rel_session_index)
			})
			.map(|(_, session)| session.mean_authored_packet_period)
			.min()
			.map(|mean| {
				let delay: f64 = rand::thread_rng().sample(rand_distr::Exp1);
				// Cap at 10x the mean; this is about the 99.995th percentile. This avoids
				// potential panics in mul_f64() due to overflow.
				mean.mul_f64(delay.min(10.0))
			})
	}

	/// Either generate and return a cover packet or pop and return the packet at the head of one
	/// of the authored packet queues. May return [`None`] if cover packets are disabled, we fail
	/// to generate a cover packet, or there are no active sessions (though in the no active
	/// sessions case [`next_authored_packet_delay`](Self::next_authored_packet_delay) should
	/// return [`None`] and so this function should not really be called).
	pub fn pop_next_authored_packet(&mut self, ns: &dyn NetworkStatus) -> Option<AddressedPacket> {
		// This function should be called according to a Poisson process. Randomly choosing between
		// sessions and cover kinds here is equivalent to there being multiple independent Poisson
		// processes; see https://www.randomservices.org/random/poisson/Splitting.html
		let mut rng = rand::thread_rng();

		// First pick the session
		let sessions: ArrayVec<_, 2> = self
			.sessions
			.enumerate_mut()
			.filter(|(rel_session_index, _)| {
				self.session_status.phase.gen_cover_packets(*rel_session_index)
			})
			.collect();
		let (rel_session_index, session) = match sessions.into_inner() {
			Ok(sessions) => {
				// Both sessions active. We choose randomly based on their rates.
				let periods = sessions
					// TODO This could be replaced with .each_ref() once it is stabilised, allowing
					// the collect/into_inner/expect at the end to be dropped
					.iter()
					.map(|(_, session)| session.mean_authored_packet_period.as_secs_f64())
					.collect::<ArrayVec<_, 2>>()
					.into_inner()
					.expect("Input is array of length 2");
				let [session_0, session_1] = sessions;
				// Rate is 1/period, and (1/a)/((1/a)+(1/b)) = b/(a+b)
				if rng.gen_bool(periods[1] / (periods[0] + periods[1])) {
					session_0
				} else {
					session_1
				}
			},
			// Either just one active session or no active sessions. This function shouldn't really
			// be called in the latter case, as next_authored_packet_delay() should return None.
			Err(mut sessions) => sessions.pop()?,
		};

		self.events |= Events::NEXT_AUTHORED_PACKET_DEADLINE_CHANGED;

		// Choose randomly between drop and loop cover packet
		if rng.gen_bool(self.config.loop_cover_proportion) {
			gen_cover_packet(&mut rng, &session.topology, ns, CoverKind::Loop, &self.config)
		} else {
			self.session_status
				.phase
				.allow_requests_and_replies(rel_session_index)
				.then(|| {
					let (packet, space) = session.authored_packet_queue.pop();
					if space {
						self.events |= Events::SPACE_IN_AUTHORED_PACKET_QUEUE;
					}
					packet
				})
				.flatten()
				.or_else(|| {
					gen_cover_packet(&mut rng, &session.topology, ns, CoverKind::Drop, &self.config)
				})
		}
	}

	/// Post a request message. If `destination_index` is [`None`], a destination mixnode is chosen
	/// at random and (on success) its index is written back to `destination_index`. The message is
	/// split into fragments and each fragment is sent over a different path to the destination.
	pub fn post_request(
		&mut self,
		session_index: SessionIndex,
		destination_index: &mut Option<MixnodeIndex>,
		message_id: &MessageId,
		data: Scattered<u8>,
		num_surbs: usize,
		ns: &dyn NetworkStatus,
	) -> Result<RequestMetrics, PostErr> {
		// Split the message into fragments
		let fragment_blueprints = match fragment_blueprints(message_id, data, num_surbs) {
			Some(fragment_blueprints)
				if fragment_blueprints.len() <= self.config.max_fragments_per_message =>
				fragment_blueprints,
			_ => return Err(PostErr::TooManyFragments),
		};

		// Grab the session and check there's room in the queue
		let session = post_session(&mut self.sessions, self.session_status, session_index)?;
		session.authored_packet_queue.check_space(fragment_blueprints.len())?;

		// Generate the packets and push them into the queue
		let mut rng = rand::thread_rng();
		let request_builder =
			RequestBuilder::new(&mut rng, &session.topology, ns, *destination_index)?;
		let mut request_hops = 0;
		let mut request_forwarding_delay = Delay::zero();
		let mut reply_hops = 0;
		let mut reply_forwarding_delay = Delay::zero();
		for fragment_blueprint in fragment_blueprints {
			let (packet, metrics) = request_builder.build_packet(
				&mut rng,
				|fragment, rng| {
					fragment_blueprint.write_except_surbs(fragment);
					for surb in fragment_blueprint.surbs(fragment) {
						// TODO Currently we don't clean up keystore entries on failure
						let (id, keys) = self.surb_keystore.insert(rng, self.config.log_target);
						let num_hops = self.config.num_hops;
						let metrics = request_builder.build_surb(surb, keys, rng, &id, num_hops)?;
						reply_hops = max(reply_hops, metrics.num_hops);
						reply_forwarding_delay =
							max(reply_forwarding_delay, metrics.forwarding_delay);
					}
					Ok(())
				},
				self.config.num_hops,
			)?;
			session.authored_packet_queue.push(packet);
			request_hops = max(request_hops, metrics.num_hops);
			request_forwarding_delay = max(request_forwarding_delay, metrics.forwarding_delay);
		}

		// Calculate metrics
		let metrics = RequestMetrics {
			num_hops: request_hops + reply_hops,
			per_hop_net_delay: self.config.per_hop_net_delay,
			forwarding_delay: (request_forwarding_delay + reply_forwarding_delay)
				.to_duration(self.config.mean_forwarding_delay),
			authored_packet_queue_delay: estimate_authored_packet_queue_delay(
				&self.config,
				session,
			),
		};

		*destination_index = Some(request_builder.destination_index());
		Ok(metrics)
	}

	/// Post a reply message using SURBs. The session index must match the session the SURBs were
	/// generated for. SURBs are removed from `surbs` on use.
	pub fn post_reply(
		&mut self,
		surbs: &mut Vec<Surb>,
		session_index: SessionIndex,
		message_id: &MessageId,
		data: Scattered<u8>,
	) -> Result<(), PostErr> {
		// Split the message into fragments
		let fragment_blueprints = match fragment_blueprints(message_id, data, 0) {
			Some(fragment_blueprints)
				if fragment_blueprints.len() <=
					min(self.config.max_fragments_per_message, surbs.len()) =>
				fragment_blueprints,
			_ => return Err(PostErr::TooManyFragments),
		};

		// Grab the session and check there's room in the queue
		let session = post_session(&mut self.sessions, self.session_status, session_index)?;
		session.authored_packet_queue.check_space(fragment_blueprints.len())?;

		// Generate the packets and push them into the queue
		for fragment_blueprint in fragment_blueprints {
			let mut packet = default_boxed_array();
			fragment_blueprint.write_except_surbs(mut_payload_data(&mut packet));
			let mixnode_index = complete_reply_packet(
				&mut packet,
				&surbs.pop().expect("Checked number of SURBs above"),
			)
			.ok_or(PostErr::BadSurb)?;
			let peer_id = session.topology.mixnode_index_to_peer_id(mixnode_index)?;
			session.authored_packet_queue.push(AddressedPacket { peer_id, packet });
		}

		Ok(())
	}

	/// Clear the event flags. Returns the flags that were cleared.
	pub fn take_events(&mut self) -> Events {
		let events = self.events;
		self.events = Events::empty();
		events
	}
}
