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

//! Network connection.

use crate::{EXTERNAL_QUERY_SIZE, EXTERNAL_REPLY_SIZE, PACKET_SIZE};
use futures::{channel::oneshot::Sender as OneShotSender, io::IoSlice, AsyncRead, AsyncWrite};
use std::{
	pin::Pin,
	task::{Context, Poll},
};

use crate::traits::Connection as ConnectionT;
use libp2p_swarm::NegotiatedSubstream;

/// Internal information tracked for an established connection.
pub struct Connection {
	inbound: Option<Pin<Box<NegotiatedSubstream>>>,
	outbound: Pin<Box<NegotiatedSubstream>>,
	outbound_buffer: Option<(Option<u8>, Vec<u8>, usize)>,
	outbound_flushing: bool,
	// size see consta assen
	inbound_buffer: (Box<[u8; EXTERNAL_QUERY_SIZE]>, usize),
	// Inform connection handler when connection is dropped.
	close_handler: Option<OneShotSender<()>>,
}

static_assertions::const_assert!(EXTERNAL_QUERY_SIZE >= EXTERNAL_REPLY_SIZE);
static_assertions::const_assert!(EXTERNAL_REPLY_SIZE >= PACKET_SIZE);

impl Drop for Connection {
	fn drop(&mut self) {
		self.close_handler.take().map(|s| s.send(()));
	}
}

impl ConnectionT for Connection {
	fn can_queue_send(&self) -> bool {
		!(self.outbound_buffer.is_some() || self.outbound_flushing)
	}

	fn queue_send(&mut self, header: Option<u8>, message: Vec<u8>) {
		debug_assert!(self.outbound_buffer.is_none());
		self.outbound_buffer = Some((header, message, 0));
	}

	fn send_flushed(&mut self, cx: &mut Context) -> Poll<Result<bool, ()>> {
		loop {
			if let Some((header, waiting, ix)) = self.outbound_buffer.as_mut() {
				match if let Some(header) = header {
					self.outbound.as_mut().poll_write_vectored(
						cx,
						&[IoSlice::new(&[*header][..]), IoSlice::new(&waiting[*ix..])],
					)
				} else {
					self.outbound.as_mut().poll_write(cx, &waiting[*ix..])
				} {
					Poll::Ready(Ok(mut nb)) => {
						if nb > 0 && header.is_some() {
							nb -= 1;
							*header = None;
						}
						*ix += nb;
						if *ix != waiting.len() {
							continue
						}
						self.outbound_flushing = true;
						self.outbound_buffer = None;
					},
					Poll::Ready(Err(e)) => {
						log::error!(target: "mixnet", "Error writing: {:?}", e);
						return Poll::Ready(Err(()))
					},
					Poll::Pending => return Poll::Pending,
				}
			}
			break
		}

		if self.outbound_flushing {
			match self.outbound.as_mut().poll_flush(cx) {
				Poll::Ready(Ok(())) => {
					self.outbound_flushing = false;
					Poll::Ready(Ok(true))
				},
				Poll::Ready(Err(e)) => {
					log::trace!(target: "mixnet", "Error flushing: {:?}", e);
					Poll::Ready(Err(()))
				},
				Poll::Pending => Poll::Pending,
			}
		} else {
			Poll::Ready(Ok(false))
		}
	}

	fn try_recv(&mut self, cx: &mut Context, size: usize) -> Poll<Result<Option<Vec<u8>>, ()>> {
		if size > PACKET_SIZE {
			return Poll::Ready(Err(()))
		}
		match self.inbound.as_mut().map(|inbound| {
			inbound
				.as_mut()
				.poll_read(cx, &mut self.inbound_buffer.0[self.inbound_buffer.1..])
		}) {
			Some(Poll::Ready(Ok(nb))) => {
				// Some implementation return 0 on disconnection.
				if nb == 0 && size != 0 {
					log::error!(target: "mixnet", "Transport reading 0 byte, disconnecting.");
					return Poll::Ready(Err(()))
				}
				self.inbound_buffer.1 += nb;
				let message = (self.inbound_buffer.1 == size).then(|| {
					self.inbound_buffer.1 = 0;
					if size == self.inbound_buffer.0.len() {
						self.inbound_buffer.0.to_vec()
					} else {
						self.inbound_buffer.0[..size].to_vec()
					}
				});
				Poll::Ready(Ok(message))
			},
			Some(Poll::Ready(Err(e))) => {
				log::trace!(target: "mixnet", "Error receiving from peer, closing: {:?}", e);
				Poll::Ready(Err(()))
			},
			Some(Poll::Pending) => Poll::Pending,
			None => {
				// pending until wake by inbound stream message.
				Poll::Pending
			},
		}
	}
}

impl Connection {
	pub fn new(
		close_handler: OneShotSender<()>,
		inbound: Option<NegotiatedSubstream>,
		outbound: NegotiatedSubstream,
	) -> Self {
		Self {
			inbound: inbound.map(Box::pin),
			outbound: Box::pin(outbound),
			outbound_buffer: None,
			inbound_buffer: (Box::new([0u8; EXTERNAL_QUERY_SIZE]), 0),
			outbound_flushing: false,
			close_handler: Some(close_handler),
		}
	}

	pub fn set_inbound(&mut self, inbound: NegotiatedSubstream) {
		self.inbound = Some(Box::pin(inbound));
	}
}
