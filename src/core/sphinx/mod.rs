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

//! Sphinx packet building and "peeling".

mod build;
mod crypto;
mod delay;
mod packet;
mod peel;
mod target;
mod tests;

pub use self::{
	build::*,
	crypto::{
		clamp_scalar, derive_kx_public, derive_kx_shared_secret, gen_kx_secret,
		kx_shared_secret_is_identity, SharedSecret,
	},
	delay::Delay,
	packet::{
		CoverId, KxPublic, Packet, Payload, PayloadData, PeerId, RawMixnodeIndex, SurbId,
		COVER_ID_SIZE, KX_PUBLIC_SIZE, MAX_HOPS, MAX_MIXNODE_INDEX, PACKET_SIZE, PAYLOAD_DATA_SIZE,
		PAYLOAD_SIZE, PEER_ID_SIZE, SURB_ID_SIZE,
	},
	peel::*,
	target::{MixnodeIndex, Target},
};
