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

use crate::core::PeerId as CorePeerId;
use libp2p_core::PeerId;

pub fn to_core_peer_id(peer_id: &PeerId) -> Option<CorePeerId> {
	let hash = peer_id.as_ref();
	let Ok(libp2p_core::multihash::Code::Identity) = libp2p_core::multihash::Code::try_from(hash.code()) else {
		return None
	};
	let public = libp2p_core::identity::PublicKey::from_protobuf_encoding(hash.digest()).ok()?;
	let libp2p_core::identity::PublicKey::Ed25519(public) = public;
	Some(public.encode())
}

pub fn from_core_peer_id(core_peer_id: &CorePeerId) -> Option<PeerId> {
	let public = libp2p_core::identity::ed25519::PublicKey::decode(core_peer_id).ok()?;
	let public = libp2p_core::identity::PublicKey::Ed25519(public);
	Some(public.into())
}
