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

/// A concatenation of multiple slices. The slices are not copied until
/// [`copy_to_slice`](Self::copy_to_slice) or [`to_vec`](Self::to_vec) is called.
#[derive(Clone, Copy)]
pub struct Scattered<'a, T> {
	len: usize,
	first_slice: &'a [T],
	mid_slices: &'a [&'a [T]],
	last_slice: &'a [T],
}

impl<'a, T> Scattered<'a, T> {
	/// Returns the total number of elements.
	pub fn len(&self) -> usize {
		self.len
	}

	/// Returns `true` if there are no elements.
	pub fn is_empty(&self) -> bool {
		self.len == 0
	}

	/// Just like [`slice::split_at`].
	pub fn split_at(&self, mid: usize) -> (Self, Self) {
		let right_len = self.len.checked_sub(mid).expect("mid must be <= len");

		// Split first_slice case
		let Some(mut mid_in_remaining) = mid.checked_sub(self.first_slice.len()) else {
			let (first_slice_left, first_slice_right) = self.first_slice.split_at(mid);
			return (
				Self {
					len: mid,
					first_slice: first_slice_left,
					mid_slices: &[],
					last_slice: &[],
				},
				Self {
					len: right_len,
					first_slice: first_slice_right,
					mid_slices: self.mid_slices,
					last_slice: self.last_slice,
				},
			)
		};

		// Split mid_slices case
		for (i, mid_slice) in self.mid_slices.iter().enumerate() {
			mid_in_remaining = match mid_in_remaining.checked_sub(mid_slice.len()) {
				Some(mid_in_remaining) => mid_in_remaining,
				None => {
					let (mid_slices_left, mid_slices_right) = self.mid_slices.split_at(i);
					let mid_slices_right =
						mid_slices_right.split_first().expect("i < self.mid_slices.len()").1;
					let (mid_slice_left, mid_slice_right) = mid_slice.split_at(mid_in_remaining);
					return (
						Self {
							len: mid,
							first_slice: self.first_slice,
							mid_slices: mid_slices_left,
							last_slice: mid_slice_left,
						},
						Self {
							len: right_len,
							first_slice: mid_slice_right,
							mid_slices: mid_slices_right,
							last_slice: self.last_slice,
						},
					)
				},
			};
		}

		// Split last_slice case
		let (last_slice_left, last_slice_right) = self.last_slice.split_at(mid_in_remaining);
		(
			Self {
				len: mid,
				first_slice: self.first_slice,
				mid_slices: self.mid_slices,
				last_slice: last_slice_left,
			},
			Self {
				len: right_len,
				first_slice: last_slice_right,
				mid_slices: &[],
				last_slice: &[],
			},
		)
	}
}

impl<'a, T: Copy> Scattered<'a, T> {
	/// Copy all elements into `dst`. `dst.len()` must equal `self.len()`.
	pub fn copy_to_slice(&self, dst: &mut [T]) {
		let (dst_first_slice, mut dst) = dst.split_at_mut(self.first_slice.len());
		dst_first_slice.copy_from_slice(self.first_slice);
		for mid_slice in self.mid_slices {
			let (dst_mid_slice, remaining_dst) = dst.split_at_mut(mid_slice.len());
			dst_mid_slice.copy_from_slice(mid_slice);
			dst = remaining_dst;
		}
		dst.copy_from_slice(self.last_slice);
	}
}

impl<'a, T: Clone> Scattered<'a, T> {
	/// Copy all elements to a new [`Vec`].
	pub fn to_vec(&self) -> Vec<T> {
		let mut vec = Vec::with_capacity(self.len);
		vec.extend_from_slice(self.first_slice);
		for mid_slice in self.mid_slices {
			vec.extend_from_slice(mid_slice);
		}
		vec.extend_from_slice(self.last_slice);
		vec
	}
}

impl<'a, T> From<&'a [T]> for Scattered<'a, T> {
	fn from(slice: &'a [T]) -> Self {
		Self { len: slice.len(), first_slice: slice, mid_slices: &[], last_slice: &[] }
	}
}

impl<'a, T> From<&'a [&'a [T]]> for Scattered<'a, T> {
	fn from(slices: &'a [&'a [T]]) -> Self {
		Self {
			len: slices.iter().map(|slice| slice.len()).sum(),
			first_slice: &[],
			mid_slices: slices,
			last_slice: &[],
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::RngCore;

	fn to_vec_using_copy_to_slice(scattered: &Scattered<u8>) -> Vec<u8> {
		let mut vec = vec![0; scattered.len()];
		scattered.copy_to_slice(&mut vec);
		vec
	}

	fn test_splits(slice_lens: &[usize], mids: &[usize]) {
		let mut contig = vec![0; slice_lens.iter().sum()];
		rand::thread_rng().fill_bytes(&mut contig);
		let mut contig = contig.as_slice();

		let slices: Vec<_> = {
			let mut remaining = contig;
			slice_lens
				.iter()
				.map(|slice_len| {
					let (left, right) = remaining.split_at(*slice_len);
					remaining = right;
					left
				})
				.collect()
		};
		let mut scattered: Scattered<u8> = slices.as_slice().into();

		for mid in mids {
			let (contig_left, contig_right) = contig.split_at(*mid);
			let (scattered_left, scattered_right) = scattered.split_at(*mid);
			assert_eq!(contig_left, scattered_left.to_vec());
			assert_eq!(contig_right, scattered_right.to_vec());
			assert_eq!(contig_left, to_vec_using_copy_to_slice(&scattered_left));
			assert_eq!(contig_right, to_vec_using_copy_to_slice(&scattered_right));
			contig = contig_right;
			scattered = scattered_right;
		}
	}

	#[test]
	fn single_slice() {
		test_splits(&[20], &[0, 9, 5, 6]);
	}

	#[test]
	fn multiple_slices() {
		test_splits(&[5, 7, 10, 7, 5], &[3, 2, 3, 4, 6, 4, 3, 4, 4, 1]);
		test_splits(&[5, 7, 10, 7, 5], &[6, 9, 16, 3]);
		test_splits(&[5, 7, 10, 7, 5], &[33, 1]);
		test_splits(&[5, 7, 10, 7, 5], &[34]);
	}
}
