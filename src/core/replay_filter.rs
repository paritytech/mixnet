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

//! Mixnet replay filter.

use super::sphinx::SharedSecret;
use blake2::{
	digest::{
		consts::U8,
		generic_array::{sequence::Concat, GenericArray},
		Mac,
	},
	Blake2bMac,
};
use rand::{
	distributions::{Distribution, Standard},
	CryptoRng, Rng,
};

// https://hur.st/bloomfilter/?n=7000000&p=&m=67108864&k=8
// The false positive rate is ~1% with 7m packets in the filter. 1% packet loss per hop over 5 hops
// gives ~5% packet loss overall. The key-exchange keys are rotated every session. Polkadot
// sessions are 4 hours. To accumulate 7m packets over a session, we would need to process ~490
// packets per second.
const NUM_BITS: usize = 64 * 1024 * 1024;
const NUM_WORDS: usize = NUM_BITS / 64;
const NUM_TAG_BITS: usize = 8;

#[derive(Clone, Copy)]
pub struct ReplayTag {
	base: u32,
	inc: u32,
}

impl Distribution<ReplayTag> for Standard {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ReplayTag {
		ReplayTag { base: rng.gen(), inc: rng.gen() }
	}
}

pub struct ReplayFilter {
	key: [u8; 32],
	/// Allocated on demand.
	words: Option<Box<[u64; NUM_WORDS]>>,
}

impl ReplayFilter {
	fn new_with_key(key: [u8; 32]) -> Self {
		Self { key, words: None }
	}

	pub fn new(rng: &mut (impl Rng + CryptoRng)) -> Self {
		let mut key = [0; 32];
		rng.fill_bytes(&mut key);
		Self::new_with_key(key)
	}

	pub fn tag(&self, shared_secret: &SharedSecret) -> ReplayTag {
		let key: &GenericArray<_, _> = (&self.key).into();
		let key = key.concat((*shared_secret).into());
		let h = Blake2bMac::<U8>::new_with_salt_and_personal(&key, b"", b"sphinx-replay-tg")
			.expect("Key, salt, and personalisation sizes are fixed and small enough");
		let tag = u64::from_le_bytes(h.finalize().into_bytes().into());
		ReplayTag { base: tag as u32, inc: (tag >> 32) as u32 }
	}

	pub fn insert(&mut self, tag: ReplayTag) {
		let mut i = tag.base;
		let words = self
			.words
			.get_or_insert_with(|| vec![0; NUM_WORDS].try_into().expect("Vec has the right size"));
		for _ in 0..NUM_TAG_BITS {
			words[((i as usize) >> 6) % NUM_WORDS] |= 1 << (i & 63);
			i = i.wrapping_add(tag.inc);
		}
	}

	pub fn contains(&self, tag: ReplayTag) -> bool {
		match &self.words {
			None => false,
			Some(words) => {
				let mut i = tag.base;
				for _ in 0..NUM_TAG_BITS {
					if (words[((i as usize) >> 6) % NUM_WORDS] & (1 << (i & 63))) == 0 {
						return false
					}
					i = i.wrapping_add(tag.inc);
				}
				true
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::{Rng, SeedableRng};

	#[test]
	fn basic_operation() {
		let mut rf = ReplayFilter::new_with_key(Default::default());
		let zero: SharedSecret = Default::default();
		let mut one: SharedSecret = Default::default();
		one[0] = 1;
		assert!(!rf.contains(rf.tag(&zero)));
		assert!(!rf.contains(rf.tag(&one)));
		rf.insert(rf.tag(&zero));
		assert!(rf.contains(rf.tag(&zero)));
		assert!(!rf.contains(rf.tag(&one)));
	}

	#[test]
	fn false_positive_rate() {
		let mut rf = ReplayFilter::new_with_key(Default::default());

		let mut rng = rand_xoshiro::Xoshiro256StarStar::seed_from_u64(0);
		for _ in 0..3_000_000 {
			rf.insert(rng.gen());
		}

		{
			let mut rng = rand_xoshiro::Xoshiro256StarStar::seed_from_u64(0);
			for _ in 0..3_000_000 {
				assert!(rf.contains(rng.gen()));
			}
		}

		// One of these randomly generated tags might actually match one we inserted earlier, but
		// this is much less likely than a false positive...
		let mut false_positives = 0;
		for _ in 0..1_000_000 {
			if rf.contains(rng.gen()) {
				false_positives += 1;
			}
		}

		// The false positive rate should be about 1 in 15,000 with 3m packets in the filter. With
		// the seed above we get 62 false positives among 1,000,000 random tags that (most likely)
		// aren't actually in the set...
		assert_eq!(false_positives, 62);
	}
}
