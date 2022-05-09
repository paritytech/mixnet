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

// libp2p connection handler for the mixnet protocol.

use crate::{
	network::{protocol, WorkerIn, WorkerSink},
	MixPeerId,
};
use futures::prelude::*;
use libp2p_core::{upgrade::NegotiationError, UpgradeError};
use libp2p_swarm::{
	ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, KeepAlive,
	NegotiatedSubstream, SubstreamProtocol,
};
use std::{
	collections::VecDeque,
	error::Error,
	fmt,
	task::{Context, Poll},
	time::Duration,
};
use void::Void;

/// The configuration for the protocol.
#[derive(Clone, Debug)]
pub struct Config {
	/// Target traffic rate in bits per second.
	connection_timeout: Duration,
}

impl Config {
	pub fn new() -> Self {
		Self { connection_timeout: Duration::new(10, 0) }
	}
}

/// An outbound failure.
#[derive(Debug)]
pub enum Failure {
	Timeout,
	/// The peer does not support the protocol.
	Unsupported,
	/// The protocol failed for some other reason.
	Other {
		error: Box<dyn std::error::Error + Send + 'static>,
	},
}

impl fmt::Display for Failure {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Failure::Timeout => f.write_str("Mix message timeout"),
			Failure::Other { error } => write!(f, "Mixnet error: {}", error),
			Failure::Unsupported => write!(f, "Mixnet protocol not supported"),
		}
	}
}

impl Error for Failure {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Failure::Timeout => None,
			Failure::Other { error } => Some(&**error),
			Failure::Unsupported => None,
		}
	}
}

/// Protocol handler that handles dispatching messages.
///
/// If the remote doesn't send anything within a time frame, produces an error that closes the
/// connection.
pub struct Handler {
	/// Configuration options.
	config: Config,
	/// Outbound failures that are pending to be processed by `poll()`.
	pending_errors: VecDeque<Failure>,
	/// The outbound state.
	do_outbound_query: bool,

	/// Inbound stream.
	inbound: Option<NegotiatedSubstream>,
	/// Outbound sink.
	outbound: Option<NegotiatedSubstream>,

	peer_id: Option<MixPeerId>,
	/// Tracks the state of our handler.
	state: State,
	/// Send connection to worker.
	mixnet_worker_sink: WorkerSink,
	connection_closed: Option<futures::channel::oneshot::Receiver<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
	/// We are inactive because the other peer doesn't support the protocol.
	Inactive {
		/// Whether or not we've reported the missing support yet.
		///
		/// This is used to avoid repeated events being emitted for a specific connection.
		reported: bool,
	},
	/// We are actively exchanging mixnet traffic, no info sent to worker.
	ActiveNotSent,
	/// We are actively exchanging mixnet traffic, worker missing inbound.
	ActiveInboundNotSent,
	/// We are actively exchanging mixnet traffic.
	Active,
}

impl Handler {
	/// Builds a new `Handler` with the given configuration.
	pub fn new(config: Config, mixnet_worker_sink: WorkerSink) -> Self {
		Handler {
			config,
			pending_errors: VecDeque::with_capacity(2),
			do_outbound_query: true,
			outbound: None,
			inbound: None,
			peer_id: None,
			state: State::ActiveNotSent,
			mixnet_worker_sink,
			connection_closed: None,
		}
	}

	pub(crate) fn set_peer_id(&mut self, peer_id: MixPeerId) {
		self.peer_id = Some(peer_id);
	}
}

impl Handler {
	fn try_send_connected(&mut self) {
		if self.state == State::ActiveNotSent && self.outbound.is_some() && self.peer_id.is_some() {
			match (self.inbound.take(), self.outbound.take(), self.peer_id.clone().take()) {
				(inbound, Some(outbound), Some(peer)) => {
					let with_inbound = inbound.is_some();
					let (sender, r) = futures::channel::oneshot::channel();
					self.connection_closed = Some(r);
					log::trace!(target: "mixnet", "Sending peer to worker {:?}", peer);
					if let Err(e) = self.mixnet_worker_sink.as_mut().start_send_unpin(
						WorkerIn::AddPeer(peer.clone(), inbound, outbound, sender),
					) {
						log::error!(target: "mixnet", "Error sending in worker sink {:?}", e);
					}
					if with_inbound {
						self.state = State::Active;
					} else {
						self.state = State::ActiveInboundNotSent;
					}
				},
				_ => (),
			}
		} else if self.state == State::ActiveInboundNotSent &&
			self.inbound.is_some() &&
			self.peer_id.is_some()
		{
			match (self.inbound.take(), self.peer_id.clone().take()) {
				(Some(inbound), Some(peer)) => {
					log::trace!(target: "mixnet", "Sending peer inbound to worker {:?}", peer);
					if let Err(e) = self
						.mixnet_worker_sink
						.as_mut()
						.start_send_unpin(WorkerIn::AddPeerInbound(peer.clone(), inbound))
					{
						log::error!(target: "mixnet", "Error sending in worker sink {:?}", e);
					}
				},
				_ => (),
			}
		}
	}
}

impl ConnectionHandler for Handler {
	type InEvent = MixPeerId;
	type OutEvent = ();
	type Error = Failure;
	type InboundProtocol = protocol::Mixnet;
	type OutboundProtocol = protocol::Mixnet;
	type OutboundOpenInfo = ();
	type InboundOpenInfo = ();

	fn listen_protocol(&self) -> SubstreamProtocol<protocol::Mixnet, ()> {
		SubstreamProtocol::new(protocol::Mixnet, ())
	}

	fn inject_fully_negotiated_inbound(&mut self, stream: NegotiatedSubstream, _: ()) {
		if self.state == State::ActiveNotSent || self.state == State::ActiveInboundNotSent {
			self.inbound = Some(stream);
		}
		self.try_send_connected();
	}

	fn inject_fully_negotiated_outbound(&mut self, stream: NegotiatedSubstream, (): ()) {
		if self.state == State::ActiveNotSent {
			self.outbound = Some(stream);
		}
		self.try_send_connected();
	}

	fn inject_event(&mut self, peer: MixPeerId) {
		if self.peer_id.is_none() {
			self.peer_id = Some(peer);
			self.try_send_connected();
		}
	}

	fn inject_dial_upgrade_error(&mut self, _info: (), error: ConnectionHandlerUpgrErr<Void>) {
		let error = match error {
			ConnectionHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
				log::warn!(target: "mixnet", "Connaction upgrade fail on dial.");
				self.state = State::Inactive { reported: false };
				return
			},
			// Note: This timeout only covers protocol negotiation.
			ConnectionHandlerUpgrErr::Timeout => Failure::Timeout,
			e => Failure::Other { error: Box::new(e) },
		};

		self.pending_errors.push_front(error);
	}

	fn connection_keep_alive(&self) -> KeepAlive {
		// TODO keep alive only for actively routing in topology and if between to connected nodes?
		KeepAlive::Yes
	}

	fn poll(
		&mut self,
		cx: &mut Context<'_>,
	) -> Poll<ConnectionHandlerEvent<protocol::Mixnet, (), (), Self::Error>> {
		if let Some(r) = self.connection_closed.as_mut() {
			match r.poll_unpin(cx) {
				Poll::Pending => (),
				_ => {
					log::trace!(target: "mixnet", "Close connection from handler");
					return Poll::Ready(ConnectionHandlerEvent::Close(Failure::Unsupported))
				},
			}
		}
		match self.state {
			State::Inactive { reported: true } => {
				return Poll::Pending // nothing to do on this connection
			},
			State::Inactive { reported: false } => {
				log::trace!(target: "mixnet", "Network error: {}", Failure::Unsupported);
				self.state = State::Inactive { reported: true };
			},
			State::Active => {},
			State::ActiveNotSent => {},
			State::ActiveInboundNotSent => {},
		}

		// Check for outbound failures.
		if let Some(error) = self.pending_errors.pop_back() {
			log::debug!(target: "mixnet", "Protocol failure: {:?}", error);
			return Poll::Ready(ConnectionHandlerEvent::Close(error))
		}

		if self.do_outbound_query {
			self.do_outbound_query = false;
			let protocol = SubstreamProtocol::new(protocol::Mixnet, ())
				.with_timeout(self.config.connection_timeout);
			return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest { protocol })
		}

		// This is suspending with no wake register, but is poll very often by libp2p.
		Poll::Pending
	}
}
