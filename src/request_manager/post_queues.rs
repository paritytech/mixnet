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

use super::{super::core::RelSessionIndex, pool::Handle};
use std::collections::VecDeque;

pub struct PostQueues {
	/// Post queue for the current session.
	pub current: VecDeque<Handle>,
	/// Post queue for the previous session.
	pub prev: VecDeque<Handle>,
	/// Additional post queue for the default session (either the previous or the current session,
	/// depending on the current session phase).
	pub default: VecDeque<Handle>,
}

impl PostQueues {
	pub fn new(capacity: super::pool::Index) -> Self {
		Self {
			current: VecDeque::with_capacity(capacity as usize),
			prev: VecDeque::with_capacity(capacity as usize),
			default: VecDeque::with_capacity(capacity as usize),
		}
	}

	pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut VecDeque<Handle>> {
		[&mut self.current, &mut self.prev, &mut self.default].into_iter()
	}
}

impl std::ops::Index<Option<RelSessionIndex>> for PostQueues {
	type Output = VecDeque<Handle>;

	fn index(&self, index: Option<RelSessionIndex>) -> &Self::Output {
		match index {
			Some(RelSessionIndex::Current) => &self.current,
			Some(RelSessionIndex::Prev) => &self.prev,
			None => &self.default,
		}
	}
}

impl std::ops::IndexMut<Option<RelSessionIndex>> for PostQueues {
	fn index_mut(&mut self, index: Option<RelSessionIndex>) -> &mut Self::Output {
		match index {
			Some(RelSessionIndex::Current) => &mut self.current,
			Some(RelSessionIndex::Prev) => &mut self.prev,
			None => &mut self.default,
		}
	}
}
