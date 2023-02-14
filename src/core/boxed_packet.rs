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

//! Mixnet "boxed" packet types.

use super::sphinx::{PeerId, PACKET_SIZE};

#[derive(Clone)]
/// Fixed-size "boxed" array, easily convertible to/from `Vec`.
pub struct BoxedArray<T, const N: usize>(Vec<T>);

impl<T, const N: usize> BoxedArray<T, N> {
	pub fn from_vec(vec: Vec<T>) -> Option<Self> {
		if vec.len() == N {
			Some(Self(vec))
		} else {
			None
		}
	}

	pub fn into_vec(self) -> Vec<T> {
		self.0
	}

	pub fn as_ref(&self) -> &[T; N] {
		let arr: Result<&[T; N], _> = self.0.as_slice().try_into();
		arr.expect("Inner vector always the right size")
	}

	pub fn as_mut(&mut self) -> &mut [T; N] {
		let arr: Result<&mut [T; N], _> = self.0.as_mut_slice().try_into();
		arr.expect("Inner vector always the right size")
	}

	pub fn truncate<const M: usize>(mut self) -> BoxedArray<T, M> {
		self.0.truncate(M);
		BoxedArray::<T, M>(self.0)
	}
}

impl<T: Default + Clone, const N: usize> Default for BoxedArray<T, N> {
	fn default() -> Self {
		Self(vec![Default::default(); N])
	}
}

pub type BoxedPacket = BoxedArray<u8, PACKET_SIZE>;

pub struct AddressedPacket {
	/// Where the packet should be sent.
	pub peer_id: PeerId,
	/// The packet contents.
	pub packet: BoxedPacket,
}
