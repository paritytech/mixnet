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

use crate::network::protocol;
use futures::{future::BoxFuture, prelude::*};
use libp2p_core::{upgrade::NegotiationError, UpgradeError};
use libp2p_swarm::{
	ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, KeepAlive,
	NegotiatedSubstream, SubstreamProtocol,
};
use std::{
	collections::VecDeque,
	error::Error,
	fmt, io,
	task::{Context, Poll},
	time::Duration,
};
use void::Void;

/// The configuration for the protocol.
#[derive(Clone, Debug)]
pub struct Config {
	pub log_target: &'static str,
	pub connection_timeout: Duration,
}

impl Default for Config {
	fn default() -> Self {
		Self { log_target: "mixnet", connection_timeout: Duration::new(10, 0) }
	}
}

/// The packet event
#[derive(Debug)]
pub struct Packet(pub Vec<u8>);

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
			Failure::Other { error } => write!(f, "Mixnet error: {error}"),
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

/// Protocol handler that handles dispatching packets.
///
/// If the remote doesn't send anything within a time frame, produces an error that closes the
/// connection.
pub struct Handler {
	/// Configuration options.
	config: Config,
	/// Outbound failures that are pending to be processed by `poll()`.
	pending_errors: VecDeque<Failure>,
	/// The outbound state.
	outbound: Option<ProtocolState>,
	/// The inbound handler, i.e. if there is an inbound
	/// substream, this is always a future that waits for the
	/// next inbound packet.
	inbound: Option<PacketFuture>,
	/// Tracks the state of our handler.
	state: State,
	pending_packet: Option<Packet>,
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
	/// We are actively exchanging mixnet traffic.
	Active,
}

impl Handler {
	/// Builds a new `Handler` with the given configuration.
	pub fn new(config: Config) -> Self {
		Handler {
			config,
			pending_errors: VecDeque::with_capacity(2),
			outbound: None,
			inbound: None,
			state: State::Active,
			pending_packet: None,
		}
	}
}

impl ConnectionHandler for Handler {
	type InEvent = Packet;
	type OutEvent = crate::network::Result;
	type Error = Failure;
	type InboundProtocol = protocol::Mixnet;
	type OutboundProtocol = protocol::Mixnet;
	type OutboundOpenInfo = ();
	type InboundOpenInfo = ();

	fn listen_protocol(&self) -> SubstreamProtocol<protocol::Mixnet, ()> {
		SubstreamProtocol::new(protocol::Mixnet, ())
	}

	fn inject_fully_negotiated_inbound(&mut self, stream: NegotiatedSubstream, (): ()) {
		self.inbound = Some(protocol::recv_message(stream).boxed());
	}

	fn inject_fully_negotiated_outbound(&mut self, stream: NegotiatedSubstream, (): ()) {
		if let Some(packet) = self.pending_packet.take() {
			let Packet(packet) = packet;
			let stream = protocol::send_message(stream, packet).boxed();
			self.outbound = Some(ProtocolState::Sending(stream));
		} else {
			self.outbound = Some(ProtocolState::Idle(stream));
		}
	}

	fn inject_event(&mut self, packet: Packet) {
		// Send an outbound packet.
		match self.outbound.take() {
			Some(ProtocolState::Idle(stream)) => {
				let Packet(packet) = packet;
				let stream = protocol::send_message(stream, packet).boxed();
				self.outbound = Some(ProtocolState::Sending(stream));
			},
			Some(ProtocolState::OpenStream) => {
				self.outbound = Some(ProtocolState::OpenStream);
				if self.pending_packet.is_some() {
					log::warn!(target: self.config.log_target, "Dropped packet, opening stream");
				} else {
					self.pending_packet = Some(packet);
				}
			},
			Some(ProtocolState::Sending(stream)) => {
				self.outbound = Some(ProtocolState::Sending(stream));
				log::warn!(target: self.config.log_target, "Dropped packet, already sending");
			},
			None =>
				if self.pending_packet.is_some() {
					log::warn!(target: self.config.log_target, "Dropped packet");
				} else {
					self.pending_packet = Some(packet);
				},
		}
	}

	fn inject_dial_upgrade_error(&mut self, _info: (), error: ConnectionHandlerUpgrErr<Void>) {
		let error = match error {
			ConnectionHandlerUpgrErr::Upgrade(UpgradeError::Select(NegotiationError::Failed)) => {
				log::warn!(target: self.config.log_target, "Connection upgrade fail on dial");
				debug_assert_eq!(self.state, State::Active);
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
		KeepAlive::Yes
	}

	fn poll(
		&mut self,
		cx: &mut Context<'_>,
	) -> Poll<ConnectionHandlerEvent<protocol::Mixnet, (), crate::network::Result, Self::Error>> {
		match self.state {
			State::Inactive { reported: true } => {
				return Poll::Pending // nothing to do on this connection
			},
			State::Inactive { reported: false } => {
				self.state = State::Inactive { reported: true };
				return Poll::Ready(ConnectionHandlerEvent::Custom(Err(Failure::Unsupported)))
			},
			State::Active => {},
		}

		// Handle inbound packets.
		if let Some(fut) = self.inbound.as_mut() {
			match fut.poll_unpin(cx) {
				Poll::Pending => {},
				Poll::Ready(Err(e)) => {
					log::debug!(target: self.config.log_target, "Inbound packet error: {e:?}");
					self.inbound = None;
				},
				Poll::Ready(Ok((stream, packet))) => {
					// An inbound packet.
					self.inbound = Some(protocol::recv_message(stream).boxed());
					return Poll::Ready(ConnectionHandlerEvent::Custom(Ok(Packet(packet))))
				},
			}
		}

		loop {
			// Check for outbound failures.
			if let Some(error) = self.pending_errors.pop_back() {
				log::debug!(target: self.config.log_target, "Protocol failure: {error:?}");
				return Poll::Ready(ConnectionHandlerEvent::Close(error))
			}

			// Continue outbound packets.
			match self.outbound.take() {
				Some(ProtocolState::Idle(stream)) => {
					self.outbound = Some(ProtocolState::Idle(stream));
					break
				},
				Some(ProtocolState::OpenStream) => {
					self.outbound = Some(ProtocolState::OpenStream);
					break
				},
				Some(ProtocolState::Sending(mut future)) => match future.poll_unpin(cx) {
					Poll::Pending => {
						self.outbound = Some(ProtocolState::Sending(future));
						break
					},
					Poll::Ready(Ok(stream)) => {
						self.outbound = Some(ProtocolState::Idle(stream));
						break
					},
					Poll::Ready(Err(e)) => {
						self.pending_errors.push_front(Failure::Other { error: Box::new(e) });
					},
				},
				None => {
					self.outbound = Some(ProtocolState::OpenStream);
					let protocol = SubstreamProtocol::new(protocol::Mixnet, ())
						.with_timeout(self.config.connection_timeout);
					return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
						protocol,
					})
				},
			}
		}

		Poll::Pending
	}
}

type PacketFuture = BoxFuture<'static, Result<(NegotiatedSubstream, Vec<u8>), io::Error>>;
type SendFuture = BoxFuture<'static, Result<NegotiatedSubstream, io::Error>>;

/// The current state w.r.t. outbound packets.
enum ProtocolState {
	OpenStream,
	Idle(NegotiatedSubstream),
	Sending(SendFuture),
}
