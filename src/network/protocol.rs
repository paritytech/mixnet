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

/// Sends a payload.
pub async fn send_message<S>(mut stream: S, message: Vec<u8>) -> io::Result<S>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let size: [u8; 4] = (message.len() as u32).to_le_bytes();
	stream.write_all(&size).await?;
	stream.write_all(&message).await?;
	stream.flush().await?;
	Ok(stream)
}

/// Waits for an incoming message
pub async fn recv_message<S>(mut stream: S) -> io::Result<(S, Vec<u8>)>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let mut size: [u8; 4] = Default::default();
	stream.read_exact(&mut size).await?;
	let mut message = Vec::new();
	message.resize(u32::from_le_bytes(size) as usize, 0u8);
	stream.read_exact(&mut message).await?;
	Ok((stream, message))
}

#[cfg(test)]
mod tests {
	use super::*;
	use libp2p_core::{
		multiaddr::multiaddr,
		transport::{memory::MemoryTransport, ListenerEvent, Transport},
	};
	use rand::{thread_rng, Rng};

	#[test]
	fn ping_pong() {
		let mem_addr = multiaddr![Memory(thread_rng().gen::<u64>())];
		let mut listener = MemoryTransport.listen_on(mem_addr).unwrap();

		let listener_addr =
			if let Some(Some(Ok(ListenerEvent::NewAddress(a)))) = listener.next().now_or_never() {
				a
			} else {
				panic!("MemoryTransport not listening on an address!");
			};

		async_std::task::spawn(async move {
			let listener_event = listener.next().await.unwrap();
			let (listener_upgrade, _) = listener_event.unwrap().into_upgrade().unwrap();
			let conn = listener_upgrade.await.unwrap();
			recv_message(conn).await.unwrap();
		});

		async_std::task::block_on(async move {
			let c = MemoryTransport.dial(listener_addr).unwrap().await.unwrap();
			let _s = send_message(c, vec![42]).await.unwrap();
		});
	}
}
