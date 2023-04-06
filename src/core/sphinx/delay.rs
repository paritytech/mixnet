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

//! Forwarding delay type.

use arrayref::array_mut_ref;
use rand::Rng;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use std::{
	cmp::Ordering,
	ops::{Add, AddAssign},
	time::Duration,
};

pub const DELAY_SEED_SIZE: usize = 16;
pub type DelaySeed = [u8; DELAY_SEED_SIZE];

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct Delay(f64);

impl Delay {
	pub fn zero() -> Self {
		Self(0.0)
	}

	pub(super) fn from_seed(seed: &DelaySeed) -> Self {
		// The algorithm for sampling from an exponential distribution consumes a variable amount
		// of random data; possibly more random data than is in seed. So it is not sufficient to
		// just use the random data in seed directly; we really do need to seed an RNG with it.
		let mut double_seed = [0; 32];
		*array_mut_ref![double_seed, 0, 16] = *seed;
		*array_mut_ref![double_seed, 16, 16] = *seed;
		let mut rng = ChaChaRng::from_seed(double_seed);
		let delay: f64 = rng.sample(rand_distr::Exp1);
		// Cap at 10x the mean; this is about the 99.995th percentile. This avoids potential panics
		// in to_duration() due to overflow.
		Self(delay.min(10.0))
	}

	/// Convert the raw delay value into a [`Duration`]. `mean` is the desired mean delay; for
	/// delays calculated by senders to match the delays calculated by mixnodes, senders and
	/// mixnodes must agree on this.
	pub fn to_duration(self, mean: Duration) -> Duration {
		mean.mul_f64(self.0)
	}
}

// Delays are never NaN
impl Eq for Delay {}

#[allow(clippy::derive_ord_xor_partial_ord)]
impl Ord for Delay {
	fn cmp(&self, other: &Self) -> Ordering {
		self.partial_cmp(other).expect("Delays are never NaN")
	}
}

impl Add for Delay {
	type Output = Self;

	fn add(self, other: Self) -> Self {
		Self(self.0 + other.0)
	}
}

impl AddAssign for Delay {
	fn add_assign(&mut self, other: Self) {
		self.0 += other.0;
	}
}
