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
	/// External info received by mixnet.
	type Command;

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

	/// Manage external command.
	/// Return false if shutdown is needed.
	fn process(&mut self, command: Self::Command) -> bool;
}
