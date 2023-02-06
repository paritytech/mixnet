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

mod core;
mod network;

pub use crate::core::{
	public_from_ed25519, secret_from_ed25519, to_mix_peer_id, Config, Error, MixPublicKey,
	MixSecretKey, PublicKeyStore, SessionTopology, SurbPayload,
};
pub use network::{MixnetBehaviour, NetworkEvent};

/// Mixnet peer identity.
pub type MixPeerId = [u8; 32];

/// Mixnet network peer identity.
pub type NetworkPeerId = libp2p_core::PeerId;

/// Options for sending a message in the mixnet.
pub struct SendOptions {
	/// Number of hops for the message.
	/// If undefined, mixnet configured number of hop will be used.
	/// This number is automatically increased by one for node that are not
	/// in traits and by two for node that are not in topology trying to
	/// reach another node that is not in traits.
	pub num_hop: Option<usize>,

	/// Do we attach a surb with the message.
	pub with_surb: bool,
}

/// Variant of message received.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MessageType {
	/// Message only.
	StandAlone,
	/// Message with a surb for reply.
	WithSurb(Box<SurbPayload>),
	/// Message from a surb reply (trusted), and initial query
	/// if stored.
	FromSurb(Box<(MixPeerId, MixPublicKey)>),
}

impl MessageType {
	/// can the message a surb reply.
	pub fn with_surb(&self) -> bool {
		matches!(self, &MessageType::WithSurb(_))
	}

	/// Extract surb.
	pub fn surb(self) -> Option<Box<SurbPayload>> {
		match self {
			MessageType::WithSurb(surb) => Some(surb),
			_ => None,
		}
	}
}

/// A full mixnet message that has reached its recipient.
#[derive(Debug)]
pub struct DecodedMessage {
	/// The peer ID of the last hop that we have received the message from. This is not the message
	/// origin.
	pub peer: MixPeerId,
	/// Message data.
	pub message: Vec<u8>,
	/// Message kind.
	pub kind: MessageType,
}
