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

use std::mem::replace;

pub type Index = u16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle(Index);

enum Slot<T> {
	Free(Option<Index>),
	Alloced(T),
}

pub struct Pool<T> {
	slots: Box<[Slot<T>]>,
	free: Option<Index>,
}

impl<T> Pool<T> {
	pub fn new(capacity: Index) -> Self {
		let mut slots = Vec::with_capacity(capacity as usize);
		for next in 1..capacity {
			slots.push(Slot::Free(Some(next)));
		}
		slots.push(Slot::Free(None));
		Self { slots: slots.into_boxed_slice(), free: Some(0) }
	}

	pub fn has_space(&self) -> bool {
		self.free.is_some()
	}

	pub fn alloc(&mut self, value: T) -> Option<Handle> {
		let Some(index) = self.free else {
			return None
		};
		match replace(&mut self.slots[index as usize], Slot::Alloced(value)) {
			Slot::Free(next) => self.free = next,
			Slot::Alloced(_) => panic!("Allocated slot in free list"),
		}
		Some(Handle(index))
	}

	pub fn free(&mut self, handle: Handle) -> T {
		let value = match replace(&mut self.slots[handle.0 as usize], Slot::Free(self.free)) {
			Slot::Free(_) => panic!("Double free"),
			Slot::Alloced(value) => value,
		};
		self.free = Some(handle.0);
		value
	}

	pub fn iter(&self) -> impl Iterator<Item = (Handle, &T)> {
		self.slots.iter().enumerate().flat_map(|(index, slot)| match slot {
			Slot::Free(_) => None,
			Slot::Alloced(value) => Some((Handle(index as Index), value)),
		})
	}
}

impl<T> std::ops::Index<Handle> for Pool<T> {
	type Output = T;

	fn index(&self, index: Handle) -> &Self::Output {
		match &self.slots[index.0 as usize] {
			Slot::Free(_) => panic!("Handle has been freed"),
			Slot::Alloced(value) => value,
		}
	}
}

impl<T> std::ops::IndexMut<Handle> for Pool<T> {
	fn index_mut(&mut self, index: Handle) -> &mut Self::Output {
		match &mut self.slots[index.0 as usize] {
			Slot::Free(_) => panic!("Handle has been freed"),
			Slot::Alloced(value) => value,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn alloc_free() {
		let capacity = 10;
		let mut pool = Pool::new(capacity);

		for _ in 0..2 {
			let handles: Vec<_> = (0..capacity)
				.map(|i| {
					assert!(pool.has_space());
					let handle = pool.alloc(i).unwrap();
					assert_eq!(pool[handle], i);
					handle
				})
				.collect();
			assert!(!pool.has_space());
			assert!(pool.alloc(0).is_none());

			for (i, handle) in handles.into_iter().enumerate() {
				assert_eq!(pool.free(handle), i as Index);
				assert!(pool.has_space());
			}
		}
	}
}
