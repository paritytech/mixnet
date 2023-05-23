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

//! The [`MixnetBehaviour`] struct implements the
//! [`NetworkBehaviour`](libp2p_swarm::NetworkBehaviour) trait. When used with a
//! [`libp2p_swarm::Swarm`], it will handle the mixnet protocol.

mod behaviour;
mod handler;
mod maybe_inf_delay;
mod mixnode;
mod peer_id;
mod protocol;

pub use self::{
	behaviour::{MixnetBehaviour, MixnetEvent},
	maybe_inf_delay::MaybeInfDelay,
	mixnode::Mixnode,
	peer_id::{from_core_peer_id, to_core_peer_id, INVALID_CORE_PEER_ID},
};
