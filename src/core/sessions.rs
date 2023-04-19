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

//! Mixnet sessions.

use super::{packet_queues::AuthoredPacketQueue, replay_filter::ReplayFilter, topology::Topology};
use std::{
	ops::{Add, Index, IndexMut},
	time::Duration,
};

pub struct Session {
	/// Mixnode topology.
	pub topology: Topology,
	/// Queue of packets authored by us, to be dispatched in place of drop cover traffic.
	pub authored_packet_queue: AuthoredPacketQueue,
	/// See [`SessionConfig`](super::config::SessionConfig::mean_authored_packet_period).
	pub mean_authored_packet_period: Duration,
	/// Filter applied to incoming packets to prevent replay. This is per-session because the
	/// key-exchange keys are rotated every session. Note that while this always exists, for
	/// sessions where we are not a mixnode, it should never contain anything, and so should not
	/// cost anything ([`ReplayFilter`] lazily allocates internally).
	pub replay_filter: ReplayFilter,
}

/// Absolute session index.
pub type SessionIndex = u32;

#[derive(Clone, Copy, PartialEq, Eq)]
/// Relative session index.
pub enum RelSessionIndex {
	/// The current session.
	Current,
	/// The previous session.
	Prev,
}

impl Add<SessionIndex> for RelSessionIndex {
	type Output = SessionIndex;

	fn add(self, other: SessionIndex) -> Self::Output {
		match self {
			Self::Current => other,
			Self::Prev => other.saturating_sub(1),
		}
	}
}

pub enum SessionSlot {
	Empty,
	/// Like [`Empty`](Self::Empty), but we should not try to create a [`Session`] struct.
	Disabled,
	Full(Session),
}

impl SessionSlot {
	pub fn is_empty(&self) -> bool {
		matches!(self, Self::Empty)
	}

	pub fn is_full(&self) -> bool {
		matches!(self, Self::Full(_))
	}

	pub fn as_option(&self) -> Option<&Session> {
		match self {
			Self::Full(session) => Some(session),
			_ => None,
		}
	}

	pub fn as_mut_option(&mut self) -> Option<&mut Session> {
		match self {
			Self::Full(session) => Some(session),
			_ => None,
		}
	}
}

pub struct Sessions {
	pub current: SessionSlot,
	pub prev: SessionSlot,
}

impl Sessions {
	pub fn is_empty(&self) -> bool {
		self.current.is_empty() && self.prev.is_empty()
	}

	pub fn advance_by_one(&mut self) {
		self.prev = std::mem::replace(&mut self.current, SessionSlot::Empty);
	}

	pub fn iter(&self) -> impl Iterator<Item = &Session> {
		[&self.current, &self.prev]
			.into_iter()
			.filter_map(|session| session.as_option())
	}

	pub fn enumerate(&self) -> impl Iterator<Item = (RelSessionIndex, &Session)> {
		[(RelSessionIndex::Current, &self.current), (RelSessionIndex::Prev, &self.prev)]
			.into_iter()
			.filter_map(|(index, session)| session.as_option().map(|session| (index, session)))
	}

	/// This is guaranteed to return the current session first, if it exists.
	pub fn enumerate_mut(&mut self) -> impl Iterator<Item = (RelSessionIndex, &mut Session)> {
		[(RelSessionIndex::Current, &mut self.current), (RelSessionIndex::Prev, &mut self.prev)]
			.into_iter()
			.filter_map(|(index, session)| session.as_mut_option().map(|session| (index, session)))
	}
}

impl Default for Sessions {
	fn default() -> Self {
		Self { current: SessionSlot::Empty, prev: SessionSlot::Empty }
	}
}

impl Index<RelSessionIndex> for Sessions {
	type Output = SessionSlot;

	fn index(&self, index: RelSessionIndex) -> &Self::Output {
		match index {
			RelSessionIndex::Current => &self.current,
			RelSessionIndex::Prev => &self.prev,
		}
	}
}

impl IndexMut<RelSessionIndex> for Sessions {
	fn index_mut(&mut self, index: RelSessionIndex) -> &mut Self::Output {
		match index {
			RelSessionIndex::Current => &mut self.current,
			RelSessionIndex::Prev => &mut self.prev,
		}
	}
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Each session should progress through these phases in order.
pub enum SessionPhase {
	/// Connect to the mixnode set for the current session, but only attempt to forward traffic to
	/// it.
	ConnectToCurrent,
	/// Generate cover traffic to the current session's mixnode set.
	CoverToCurrent,
	/// Build requests using the current session's mixnode set. The previous session's mixnode set
	/// may be used if this is explicitly requested.
	RequestsToCurrent,
	/// Only send cover (and forwarded) traffic to the previous session's mixnode set. Any packets
	/// in the authored packet queue for the previous session at this point are effectively
	/// dropped.
	CoverToPrev,
	/// Disconnect the previous session's mixnode set.
	DisconnectFromPrev,
}

impl SessionPhase {
	/// Is the previous session still needed?
	pub fn need_prev(self) -> bool {
		self < Self::DisconnectFromPrev
	}

	/// Should cover packets be generated for the specified session?
	pub fn gen_cover_packets(self, rel_session_index: RelSessionIndex) -> bool {
		match rel_session_index {
			RelSessionIndex::Prev => self < Self::DisconnectFromPrev,
			RelSessionIndex::Current => self >= Self::CoverToCurrent,
		}
	}

	/// Should we allowing pushing to and popping from the authored packet queue for the specified
	/// session?
	pub fn allow_requests_and_replies(self, rel_session_index: RelSessionIndex) -> bool {
		match rel_session_index {
			RelSessionIndex::Prev => self < Self::CoverToPrev,
			RelSessionIndex::Current => self >= Self::RequestsToCurrent,
		}
	}

	/// Which session should requests be built for by default?
	pub fn default_request_session(self) -> RelSessionIndex {
		if self >= Self::RequestsToCurrent {
			RelSessionIndex::Current
		} else {
			RelSessionIndex::Prev
		}
	}
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// The index and phase of the current session.
pub struct SessionStatus {
	/// Index of the current session.
	pub current_index: SessionIndex,
	/// Current session phase.
	pub phase: SessionPhase,
}
