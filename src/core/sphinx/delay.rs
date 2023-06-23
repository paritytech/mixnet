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

//! Unitless delay type.

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

/// Unitless delay. Can be converted to a [`Duration`] with [`to_duration`](Self::to_duration).
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct Delay(f64);

impl Delay {
	/// Returns a delay of zero time.
	pub fn zero() -> Self {
		Self(0.0)
	}

	/// Returns a random delay sampled from an exponential distribution with mean 1. `seed`
	/// provides the entropy.
	pub fn exp(seed: &DelaySeed) -> Self {
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

	/// Convert the unitless delay into a [`Duration`] by multiplying by `unit`. For delays
	/// calculated by different parties to match, they must all agree on `unit`!
	pub fn to_duration(self, unit: Duration) -> Duration {
		unit.mul_f64(self.0)
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn portable_deterministic_exp() {
		assert_eq!(
			Delay::exp(&[
				0xdc, 0x18, 0x0e, 0xe6, 0x71, 0x1e, 0xcf, 0x2d, 0xad, 0x0c, 0xde, 0xd1, 0xd4, 0x94,
				0xbd, 0x3b
			]),
			Delay(2.953842296445717)
		);
		assert_eq!(
			Delay::exp(&[
				0x0a, 0xcc, 0x48, 0xbd, 0xa2, 0x30, 0x9a, 0x48, 0xc8, 0x78, 0x61, 0x0d, 0xf8, 0xc2,
				0x8d, 0x99
			]),
			Delay(1.278588765412407)
		);
		assert_eq!(
			Delay::exp(&[
				0x17, 0x4c, 0x40, 0x2f, 0x8f, 0xda, 0xa6, 0x46, 0x45, 0xe7, 0x1c, 0xb0, 0x1e, 0xff,
				0xf8, 0xfc
			]),
			Delay(0.7747915675800142)
		);
		assert_eq!(
			Delay::exp(&[
				0xca, 0xe8, 0x07, 0x72, 0x17, 0x28, 0xf7, 0x09, 0xd8, 0x7d, 0x3e, 0xa2, 0x03, 0x7d,
				0x4f, 0x03
			]),
			Delay(0.8799379598933348)
		);
		assert_eq!(
			Delay::exp(&[
				0x61, 0x56, 0x54, 0x41, 0xd0, 0x25, 0xdf, 0xe7, 0xb9, 0xc8, 0x6a, 0x56, 0xdd, 0x27,
				0x09, 0xa6
			]),
			Delay(10.0)
		);
	}
}
