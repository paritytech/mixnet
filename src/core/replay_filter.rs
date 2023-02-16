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

use super::sphinx::KxPublic;
use rand::{CryptoRng, Rng};
use siphasher::sip::SipHasher;
use std::hash::{Hash, Hasher};

// https://hur.st/bloomfilter/?n=7000000&p=&m=67108864&k=8
// The false positive rate is ~1% with 7m packets in the filter. 1% packet loss per hop over 5 hops
// gives ~5% packet loss overall. The key-exchange keys are rotated every session. Polkadot
// sessions are 4 hours. To accumulate 7m packets over a session, we would need to process ~490
// packets per second.
const NUM_BITS: usize = 64 * 1024 * 1024;
const NUM_WORDS: usize = NUM_BITS / 64;
const NUM_HASHES: usize = 8;

pub struct ReplayFilter {
	hash_key: [u8; 16],
	/// Allocated on demand.
	words: Option<Box<[u64; NUM_WORDS]>>,
}

impl ReplayFilter {
	fn new_with_hash_key(hash_key: [u8; 16]) -> Self {
		Self { hash_key, words: None }
	}

	pub fn new(rng: &mut (impl Rng + CryptoRng)) -> Self {
		let mut hash_key = [0; 16];
		rng.fill_bytes(&mut hash_key);
		Self::new_with_hash_key(hash_key)
	}

	fn hash(&self, value: &KxPublic) -> (u32, u32) {
		let mut hasher = SipHasher::new_with_key(&self.hash_key);
		value.hash(&mut hasher);
		let h = hasher.finish();
		(h as u32, (h >> 32) as u32)
	}

	pub fn insert(&mut self, value: &KxPublic) {
		let (mut h, inc) = self.hash(value);
		let words = self
			.words
			.get_or_insert_with(|| vec![0; NUM_WORDS].try_into().expect("Vec has the right size"));
		for _ in 0..NUM_HASHES {
			words[((h as usize) >> 6) % NUM_WORDS] |= 1 << (h & 63);
			h = h.wrapping_add(inc);
		}
	}

	pub fn contains(&self, value: &KxPublic) -> bool {
		match &self.words {
			None => false,
			Some(words) => {
				let (mut h, inc) = self.hash(value);
				for _ in 0..NUM_HASHES {
					if (words[((h as usize) >> 6) % NUM_WORDS] & (1 << (h & 63))) == 0 {
						return false
					}
					h = h.wrapping_add(inc);
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
		let mut rf = ReplayFilter::new_with_hash_key(Default::default());
		let zero: KxPublic = Default::default();
		let mut one: KxPublic = Default::default();
		one[0] = 1;
		assert!(!rf.contains(&zero));
		assert!(!rf.contains(&one));
		rf.insert(&zero);
		assert!(rf.contains(&zero));
		assert!(!rf.contains(&one));
	}

	#[test]
	fn false_positive_rate() {
		let mut rf = ReplayFilter::new_with_hash_key(Default::default());

		let mut rng = rand_xoshiro::Xoshiro256StarStar::seed_from_u64(0);
		for _ in 0..3_000_000 {
			rf.insert(&rng.gen());
		}

		{
			let mut rng = rand_xoshiro::Xoshiro256StarStar::seed_from_u64(0);
			for _ in 0..3_000_000 {
				assert!(rf.contains(&rng.gen()));
			}
		}

		// One of these randomly generated integers might actually match one we inserted earlier,
		// but this is much less likely than a false positive...
		let mut false_positives = 0;
		for _ in 0..1_000_000 {
			if rf.contains(&rng.gen()) {
				false_positives += 1;
			}
		}

		// The false positive rate should be about 1 in 15,000 with 3m packets in the filter. With
		// the seeds above we get 61 false positives among 1,000,000 random integers that (most
		// likely) aren't actually in the set...
		assert_eq!(false_positives, 61);
	}
}
