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

//! Mixnet topology interface.

use crate::{MixPeerId, MixPublicKey};

/// Provide network topology information to the mixnet.
pub trait Topology: Send + 'static {
	/// If topology is not active, we use direct connection.
	const ACTIVE: bool = true;

	/// Content shared in the swarm specific to topology.
	type ConnectionInfo;

	/// Select a random recipient for the message to be delivered. This is
	/// called when the user sends the message with no recipient specified.
	/// E.g. this can select a random validator that can accept the blockchain
	/// transaction into the block.
	/// Return `None` if no such selection is possible.
	fn random_recipient(&self) -> Option<MixPeerId>;

	/// For a given peer return a list of peers it is supposed to be connected to.
	/// Return `None` if peer is unknown to the topology.
	/// TODO when `None` allow sending even if not part of topology but in the mixnet:
	/// external hop for latest (see gen_path function). Then last hop will expose
	/// a new connection, so it need to be an additional hop (if possible).
	fn neighbors(&self, id: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>>;

	/// Indicate if we are currently a node that is routing message.
	fn routing(&self) -> bool;

	/// Append connection infos to a handshake message.
	fn encoded_connection_info(info: &Self::ConnectionInfo) -> Vec<u8>;

	/// Read connection info from a message, return `None` if missing or
	/// extra data remaining.
	fn read_connection_info(encoded: &[u8]) -> Option<Self::ConnectionInfo>;

	/// On connection successful handshake.
	fn connected(&mut self, id: MixPeerId, public_key: MixPublicKey, connection_info: Self::ConnectionInfo);

	/// On disconnect.
	fn disconnect(&mut self, id: &MixPeerId);
}

/// No specific topology defined, we use all connected peers instead.
pub struct NoTopology;

impl Topology for NoTopology {
	const ACTIVE: bool = false;

	type ConnectionInfo = ();

	fn random_recipient(&self) -> Option<MixPeerId> {
		None
	}
	fn neighbors(&self, _: &MixPeerId) -> Option<Vec<(MixPeerId, MixPublicKey)>> {
		None
	}
	fn routing(&self) -> bool {
		true
	}
	fn encoded_connection_info(_: &Self::ConnectionInfo) -> Vec<u8> {
		Vec::new()
	}
	fn read_connection_info(encoded: &[u8]) -> Option<Self::ConnectionInfo> {
		(encoded.len() == 0).then(|| ())
	}
	fn connected(&mut self, _: MixPeerId, _: MixPublicKey, _: Self::ConnectionInfo) {
	}
	fn disconnect(&mut self, _: &MixPeerId) {
	}
}
