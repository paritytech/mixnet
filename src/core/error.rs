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

/// Error handling
use crate::core::{sphinx::Error as SphinxError, Packet};
use crate::MixPeerId;
use std::fmt;

/// Mixnet generic error.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// Attempting to send oversized message.
	MessageTooLarge,
	/// Sphinx format error.
	SphinxError(SphinxError),
	/// No path to give peer or no random peer to select from.
	NoPath(Option<MixPeerId>),
	/// Not enough peers.
	NotEnoughRoutingPeers,
	/// Invalid network id.
	InvalidId(libp2p_core::PeerId),
	/// Invalid id in the Sphinx packet.
	InvalidSphinxId(MixPeerId),
	/// Invalid message fragment format.
	BadFragment,
	/// Packet queue is full.
	QueueFull,
	/// Requested number of hop is too big.
	TooManyHops,
	/// Surbs message exceed single fragment length.
	BadSurbsLength,
	/// Worker channel is full.
	WorkerChannelFull,
	/// Destination peer not connected.
	/// Depending on use case, dial could be attempted here.
	Unreachable(Packet),
	/// No sphinx id from handshake.
	NoSphinxId,
	/// Mixnet not ready.
	NotReady,
	/// Other.
	Other(String),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Error::MessageTooLarge => write!(f, "Mix message is too large."),
			Error::SphinxError(e) => write!(f, "Sphinx packet format error: {:?}.", e),
			Error::NoPath(p) => write!(f, "No path to {:?}.", p),
			Error::NotEnoughRoutingPeers => write!(f, "Not enough routing peers."),
			Error::InvalidId(id) => write!(f, "Invalid peer id: {}.", id),
			Error::InvalidSphinxId(id) =>
				write!(f, "Invalid peer id in the Sphinx packet: {:?}.", id),
			Error::BadFragment => write!(f, "Bad message fragment."),
			Error::BadSurbsLength => write!(f, "Surbs message too long."),
			Error::QueueFull => write!(f, "Packet queue is full."),
			Error::WorkerChannelFull => write!(f, "Worker channel is full."),
			Error::TooManyHops => write!(f, "Too many hops for mixnet."),
			Error::Unreachable(_) => write!(f, "Destination peer not connected."),
			Error::NoSphinxId => write!(f, "Sphinx Id not obtain from handshake."),
			Error::NotReady => write!(f, "Mixnet not ready."),
			Error::Other(e) => write!(f, "Other: {}", e),
		}
	}
}

impl std::error::Error for Error {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		None
	}
}
