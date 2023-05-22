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

use super::super::core::RelSessionIndex;
use std::collections::VecDeque;

pub struct PostQueues<T> {
	/// Post queue for the current session.
	pub current: VecDeque<T>,
	/// Post queue for the previous session.
	pub prev: VecDeque<T>,
	/// Additional post queue for the default session (either the previous or the current session,
	/// depending on the current session phase).
	pub default: VecDeque<T>,
}

impl<T> PostQueues<T> {
	pub fn new(capacity: usize) -> Self {
		Self {
			current: VecDeque::with_capacity(capacity),
			prev: VecDeque::with_capacity(capacity),
			default: VecDeque::with_capacity(capacity),
		}
	}

	pub fn iter(&self) -> impl Iterator<Item = &VecDeque<T>> {
		[&self.current, &self.prev, &self.default].into_iter()
	}

	pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut VecDeque<T>> {
		[&mut self.current, &mut self.prev, &mut self.default].into_iter()
	}
}

impl<T> std::ops::Index<Option<RelSessionIndex>> for PostQueues<T> {
	type Output = VecDeque<T>;

	fn index(&self, index: Option<RelSessionIndex>) -> &Self::Output {
		match index {
			Some(RelSessionIndex::Current) => &self.current,
			Some(RelSessionIndex::Prev) => &self.prev,
			None => &self.default,
		}
	}
}

impl<T> std::ops::IndexMut<Option<RelSessionIndex>> for PostQueues<T> {
	fn index_mut(&mut self, index: Option<RelSessionIndex>) -> &mut Self::Output {
		match index {
			Some(RelSessionIndex::Current) => &mut self.current,
			Some(RelSessionIndex::Prev) => &mut self.prev,
			None => &mut self.default,
		}
	}
}
