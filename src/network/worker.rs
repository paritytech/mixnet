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

//! `NetworkBehaviour` can be to heavy (especially when shared with others), using
//! a worker allows sending the process to a queue instead of runing it directly.

use crate::{
	core::{MixEvent, MixPublicKey, Mixnet, SurbsEncoded, Topology},
	network::CommandsStream,
	MixPeerId,
};
use futures::{Sink, Stream};
use futures_timer::Delay;
use std::{
	pin::Pin,
	task::{Context, Poll},
};

// TODO rem pin, this is just to abstract substrate custom channel type.
type WorkerStream = Pin<Box<dyn Stream<Item = WorkerIn> + Send>>;
type WorkerSink = Pin<Box<dyn Sink<WorkerOut, Error = ()> + Send>>;

// TODO Arc those Vec<u8>
pub enum WorkerIn {
	RegisterMessage(Option<MixPeerId>, Vec<u8>, bool),
	RegisterSurbs(Vec<u8>, SurbsEncoded),
	AddConnectedPeer(MixPeerId, MixPublicKey),
	RemoveConnectedPeer(MixPeerId),
	ImportMessage(MixPeerId, Vec<u8>),
}

pub enum WorkerOut {
	Event(MixEvent), // TODO could be simplified
	ReceivedMessage(MixPeerId, Vec<u8>, Option<SurbsEncoded>),
}

/// Embed mixnet and process queue of instruction.
pub struct MixnetWorker<C> {
	mixnet: Mixnet,
	commands: Option<CommandsStream<C>>,
	worker_in: WorkerStream,
	worker_out: WorkerSink,
}

impl<C> MixnetWorker<C> {
	pub fn new(mixnet: Mixnet, worker_in: WorkerStream, worker_out: WorkerSink) -> Self {
		MixnetWorker { mixnet, commands: None, worker_in, worker_out }
	}

	/// Define mixnet topology.
	pub fn with_topology(mut self, topology: Box<dyn Topology>) -> Self {
		// if worker use case, topology is already define in worker.
		self.mixnet = self.mixnet.with_topology(topology);
		self
	}

	/// Add input topology commands stream.
	pub fn with_commands(mut self, commands: CommandsStream<C>) -> Self {
		self.commands = Some(commands);
		self
	}

	pub fn poll(&mut self, cx: &mut Context) -> Poll<()> {
		match self.commands.as_mut().map(|c| c.as_mut().poll_next(cx)) {
			Some(Poll::Ready(Some(command))) => {
				unimplemented!(
					"TODO does not make sense to have command with worker: could
				poll it externally and call directly method -> just don't dyn topology and make it public :)."
				)
			},
			Some(Poll::Ready(None)) => {
				// TODO shutdown event?
			},
			_ => (),
		}

		if let Poll::Ready(e @ MixEvent::SendMessage(..)) = self.mixnet.poll(cx) {
			if let Err(e) = self.worker_out.as_mut().start_send(WorkerOut::Event(e)) {
				log::error!(target: "mixnet", "Error sending event to channel: {:?}", e);
			}
		}

		match self.worker_in.as_mut().poll_next(cx) {
			Poll::Ready(Some(message)) =>
				match message {
					WorkerIn::RegisterMessage(peer_id, message, with_surbs) => {
						match self.mixnet.register_message(peer_id, message, with_surbs) {
							Ok(()) => (),
							Err(e) => {
								log::error!(target: "mixnet", "Error registering message: {:?}", e);
							},
						}
						return Poll::Ready(())
					},
					WorkerIn::RegisterSurbs(message, surbs) => {
						match self.mixnet.register_surbs(message, surbs) {
							Ok(()) => (),
							Err(e) => {
								log::error!(target: "mixnet", "Error registering surbs: {:?}", e);
							},
						}
						return Poll::Ready(())
					},
					WorkerIn::AddConnectedPeer(peer, public_key) => {
						self.mixnet.add_connected_peer(peer, public_key);
					},
					WorkerIn::RemoveConnectedPeer(peer) => {
						self.mixnet.remove_connected_peer(&peer);
					},
					WorkerIn::ImportMessage(peer, message) => {
						match self.mixnet.import_message(peer, message) {
							Ok(Some((full_message, surbs))) => {
								if let Err(e) = self.worker_out.as_mut().start_send(
									WorkerOut::ReceivedMessage(peer, full_message, surbs),
								) {
									log::error!(target: "mixnet", "Error sending full message to channel: {:?}", e);
								}
							},
							Ok(None) => (),
							Err(e) => {
								log::warn!(target: "mixnet", "Error importing message: {:?}", e);
							},
						}
					},
				},
			_ => (),
		}

		Poll::Pending
	}
}
