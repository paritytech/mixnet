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

use futures::FutureExt;
use futures_timer::Delay;
use std::{
	future::Future,
	pin::Pin,
	task::{Context, Poll, Waker},
	time::Duration,
};

enum Inner {
	Infinite {
		/// Waker from the most recent `poll` call. If `None`, either `poll` has not been called
		/// yet, we returned `Poll::Ready` from the last call, or the waker is attached to `delay`.
		waker: Option<Waker>,
		delay: Option<Delay>,
	},
	Finite(Delay),
}

/// Like [`Delay`] but the duration can be infinite (in which case the future will never fire).
pub struct MaybeInfDelay(Inner);

impl MaybeInfDelay {
	/// Create a new `MaybeInfDelay` future. If `duration` is [`Some`], the future will fire after
	/// the given duration has elapsed. If `duration` is [`None`], the future will "never" fire
	/// (although see [`reset`](Self::reset)).
	pub fn new(duration: Option<Duration>) -> Self {
		match duration {
			Some(duration) => Self(Inner::Finite(Delay::new(duration))),
			None => Self(Inner::Infinite { waker: None, delay: None }),
		}
	}

	/// Reset the timer. `duration` is handled just like in [`new`](Self::new). Note that while
	/// this is similar to `std::mem::replace(&mut self, MaybeInfDelay::new(duration))`, with
	/// `replace` you would have to manually ensure [`poll`](Self::poll) was called again; with
	/// `reset` this is not necessary.
	pub fn reset(&mut self, duration: Option<Duration>) {
		match duration {
			Some(duration) => match &mut self.0 {
				Inner::Infinite { waker, delay } => {
					let mut delay = match delay.take() {
						Some(mut delay) => {
							delay.reset(duration);
							delay
						},
						None => Delay::new(duration),
					};
					if let Some(waker) = waker.take() {
						let mut cx = Context::from_waker(&waker);
						match delay.poll_unpin(&mut cx) {
							Poll::Pending => (), // Waker attached to delay
							Poll::Ready(_) => waker.wake(),
						}
					}
					self.0 = Inner::Finite(delay);
				},
				Inner::Finite(delay) => delay.reset(duration),
			},
			None =>
				self.0 = match std::mem::replace(
					&mut self.0,
					Inner::Infinite { waker: None, delay: None },
				) {
					Inner::Finite(delay) => Inner::Infinite { waker: None, delay: Some(delay) },
					infinite => infinite,
				},
		}
	}
}

impl Future for MaybeInfDelay {
	type Output = ();

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		match &mut self.0 {
			Inner::Infinite { waker, .. } => {
				*waker = Some(cx.waker().clone());
				Poll::Pending
			},
			Inner::Finite(delay) => delay.poll_unpin(cx),
		}
	}
}
