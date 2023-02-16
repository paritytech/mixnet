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

//! Hop target type.

use super::packet::{PeerId, RawMixnodeIndex, MAX_MIXNODE_INDEX};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// The contained index is always <= `MAX_MIXNODE_INDEX`.
pub struct MixnodeIndex(RawMixnodeIndex);

impl MixnodeIndex {
	pub fn get(self) -> RawMixnodeIndex {
		self.0
	}
}

impl TryFrom<usize> for MixnodeIndex {
	type Error = ();

	fn try_from(index: usize) -> Result<Self, Self::Error> {
		if index <= MAX_MIXNODE_INDEX as usize {
			Ok(Self(index as RawMixnodeIndex))
		} else {
			Err(())
		}
	}
}

impl TryFrom<RawMixnodeIndex> for MixnodeIndex {
	type Error = ();

	fn try_from(index: RawMixnodeIndex) -> Result<Self, Self::Error> {
		(index as usize).try_into()
	}
}

impl fmt::Display for MixnodeIndex {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		self.0.fmt(fmt)
	}
}

#[derive(Debug, PartialEq, Eq)]
pub enum Target {
	MixnodeIndex(MixnodeIndex),
	PeerId(PeerId),
}
