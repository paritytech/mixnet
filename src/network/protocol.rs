// Copyright 2018 Parity Technologies (UK) Ltd.
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

use futures::prelude::*;
use libp2p_core::{InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use libp2p_swarm::NegotiatedSubstream;
use std::{io, iter};
use void::Void;

/// The Mixnet protocol upgrade.
pub struct Mixnet;

impl UpgradeInfo for Mixnet {
	type Info = &'static [u8];
	type InfoIter = iter::Once<Self::Info>;

	fn protocol_info(&self) -> Self::InfoIter {
		iter::once(b"/mixnet/1.0.0")
	}
}

impl InboundUpgrade<NegotiatedSubstream> for Mixnet {
	type Output = NegotiatedSubstream;
	type Error = Void;
	type Future = future::Ready<Result<Self::Output, Self::Error>>;

	fn upgrade_inbound(self, stream: NegotiatedSubstream, _: Self::Info) -> Self::Future {
		future::ok(stream)
	}
}

impl OutboundUpgrade<NegotiatedSubstream> for Mixnet {
	type Output = NegotiatedSubstream;
	type Error = Void;
	type Future = future::Ready<Result<Self::Output, Self::Error>>;

	fn upgrade_outbound(self, stream: NegotiatedSubstream, _: Self::Info) -> Self::Future {
		future::ok(stream)
	}
}

/// Sends a packet.
pub async fn send_packet<S>(mut stream: S, packet: Vec<u8>) -> io::Result<S>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let size: [u8; 4] = (packet.len() as u32).to_le_bytes();
	stream.write_all(&size).await?;
	stream.write_all(&packet).await?;
	stream.flush().await?;
	Ok(stream)
}

/// Waits for an incoming packet.
pub async fn recv_packet<S>(mut stream: S) -> io::Result<(S, Vec<u8>)>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let mut size: [u8; 4] = Default::default();
	stream.read_exact(&mut size).await?;
	let mut packet = Vec::new();
	packet.resize(u32::from_le_bytes(size) as usize, 0u8);
	stream.read_exact(&mut packet).await?;
	Ok((stream, packet))
}
