// Copyright 2018-2019 Parity Technologies (UK) Ltd.
// This file is part of ink!.
//
// ink! is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ink! is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ink!.  If not, see <http://www.gnu.org/licenses/>.

use crate::{
    storage::{
        alloc::{
            AllocateUsing,
            BumpAlloc,
            Initialize,
        },
        Heap,
        Key,
    },
    test_utils::run_test,
};
use core::cmp;
use scale::{
    Decode,
    Encode,
};

fn empty_heap() -> Heap<i32> {
    unsafe {
        let mut alloc = BumpAlloc::from_raw_parts(Key([0x0; 32]));
        Heap::allocate_using(&mut alloc).initialize_into(())
    }
}

fn filled_heap() -> Heap<i32> {
    let mut heap = empty_heap();
    heap.push(42);
    heap.push(5);
    heap.push(1337);
    heap.push(77);
    assert_eq!(heap.len(), 4);
    heap
}

/// Pushes all element from `vec` onto the heap, in the order in which they
/// are supplied in the vector.
///
/// Subsequently all elements are popped from the vec and for the retrieved
/// elements it is asserted that they are in the exact same order as the ones
/// in `expected`. The `expected` vec must contain all elements which are
/// returned, as the function finally checks that there are no more elements
/// left in the heap.
fn assert_push_equals_sorted_pop<T: Ord + scale::Codec + core::fmt::Debug>(
    heap: &mut Heap<T>,
    vec: Vec<T>,
    expected: Vec<T>,
) {
    vec.into_iter().for_each(|i| heap.push(i));

    expected
        .into_iter()
        .for_each(|i| assert_eq!(heap.pop(), Some(i)));

    assert_eq!(heap.pop(), None);
    assert_eq!(heap.len(), 0);
}

#[test]
fn new_unchecked() {
    run_test(|| {
        // given
        let heap = empty_heap();

        // then
        assert_eq!(heap.len(), 0);
        assert!(heap.is_empty());
        assert_eq!(heap.iter().next(), None);
    })
}

#[test]
fn push_on_empty_heap() {
    run_test(|| {
        // given
        let mut heap = empty_heap();
        assert_eq!(heap.pop(), None);

        // when
        heap.push(42);

        // then
        assert_eq!(heap.len(), 1);
        assert_eq!(heap.pop(), Some(42));
    })
}

#[test]
fn push_duplicates_max() {
    run_test(|| {
        // given
        let mut heap = empty_heap();

        // when
        heap.push(10);
        heap.push(20);
        heap.push(10);
        heap.push(20);

        // then
        assert_eq!(heap.pop(), Some(20));
        assert_eq!(heap.pop(), Some(20));
        assert_eq!(heap.pop(), Some(10));
        assert_eq!(heap.pop(), Some(10));
    })
}

#[test]
fn peek() {
    run_test(|| {
        // given
        let mut heap = empty_heap();
        assert_eq!(heap.peek(), None);

        // when
        heap.push(42);

        // then
        assert_eq!(heap.peek(), Some(&42));
    })
}

#[test]
fn peek_mut() {
    run_test(|| {
        // given
        let mut heap = empty_heap();
        heap.push(42);

        // when
        let val = heap.peek_mut().unwrap();
        assert_eq!(val, &42);
        *val = 1337;

        // then
        assert_eq!(heap.peek(), Some(&1337));
    })
}

#[test]
fn pop_empty_and_refill() {
    run_test(|| {
        // given
        let mut heap = filled_heap();
        for _ in 0..heap.len() {
            let _ = heap.pop();
        }
        assert_eq!(heap.len(), 0);

        // when
        heap.push(123);

        // then
        assert_eq!(heap.pop(), Some(123));
        assert_eq!(heap.len(), 0);
    })
}

#[test]
fn take_empty() {
    run_test(|| {
        // given
        let mut heap = empty_heap();

        // then
        assert_eq!(heap.pop(), None);
        assert_eq!(heap.peek(), None);
        assert_eq!(heap.peek_mut(), None);
    })
}

#[test]
fn push_negative_positive_range_min() {
    run_test(|| {
        // given
        let mut heap = empty_heap();

        // when
        heap.push(-1);
        heap.push(0);
        heap.push(1);

        // then
        assert_eq!(heap.len(), 3);
        assert_eq!(heap.pop(), Some(1));
        assert_eq!(heap.pop(), Some(0));
        assert_eq!(heap.pop(), Some(-1));
    })
}

#[test]
fn push_negative_positive_range_max() {
    run_test(|| {
        // given
        let mut heap = empty_heap();

        // when
        heap.push(-1);
        heap.push(0);
        heap.push(1);

        // then
        assert_eq!(heap.len(), 3);
        assert_eq!(heap.pop(), Some(1));
        assert_eq!(heap.pop(), Some(0));
        assert_eq!(heap.pop(), Some(-1));
    })
}

#[test]
fn iterator_min() {
    run_test(|| {
        // given
        let heap = filled_heap();

        // when
        let mut iter = heap.iter();

        // then
        assert_eq!(iter.next(), Some((0, &1337)));
        assert_eq!(iter.next(), Some((1, &5)));
        assert_eq!(iter.next(), Some((2, &42)));
        assert_eq!(iter.next(), Some((3, &77)));
        assert_eq!(iter.next(), None);
    })
}

#[test]
fn iterator_max() {
    run_test(|| {
        // given
        let heap = filled_heap();

        // when
        let mut iter = heap.iter();

        // then
        assert_eq!(iter.next(), Some((0, &1337)));
        assert_eq!(iter.next(), Some((1, &5)));
        assert_eq!(iter.next(), Some((2, &42)));
        assert_eq!(iter.next(), Some((3, &77)));
        assert_eq!(iter.next(), None);
    })
}

#[test]
fn iter_back() {
    run_test(|| {
        // given
        let heap = filled_heap();

        // when
        let mut iter = heap.iter();

        // then
        assert_eq!(iter.next_back(), Some((3, &77)));
        assert_eq!(iter.next_back(), Some((2, &42)));
        assert_eq!(iter.next_back(), Some((1, &5)));
        assert_eq!(iter.next_back(), Some((0, &1337)));
        assert_eq!(iter.next_back(), None);
    })
}

#[test]
fn iter_size_hint() {
    run_test(|| {
        // given
        let heap = filled_heap();

        // when
        let mut iter = heap.iter();
        assert_eq!(iter.size_hint(), (4, Some(4)));

        // then
        iter.next();
        assert_eq!(iter.size_hint(), (3, Some(3)));
    })
}

#[test]
fn unordered_push_results_in_ordered_pop() {
    run_test(|| {
        let mut heap = empty_heap();
        let vec = vec![5, 42, 1337, 77, -1, 0, 9999, 3, 65, 90, 1000000, -32];
        let mut expected = vec.clone();
        expected.sort_by(|a, b| b.cmp(a));
        assert_push_equals_sorted_pop(&mut heap, vec, expected);
    })
}

#[test]
fn max_heap_with_three_levels() {
    run_test(|| {
        let mut heap = empty_heap();
        let vec = vec![100, 10, 20, 30, 7, 8, 9, 17, 18, 29, 27, 28, 30];
        let mut expected = vec.clone();
        expected.sort_by(|a, b| b.cmp(a));
        assert_push_equals_sorted_pop(&mut heap, vec, expected);
    })
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Encode, Decode)]
struct V(u32);

impl Ord for V {
    fn cmp(&self, other: &V) -> cmp::Ordering {
        other.0.cmp(&self.0)
    }
}

impl PartialOrd for V {
    fn partial_cmp(&self, other: &V) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[test]
fn min_heap_with_three_levels() {
    run_test(|| {
        let mut heap: Heap<V> = unsafe {
            let mut alloc = BumpAlloc::from_raw_parts(Key([0x0; 32]));
            Heap::allocate_using(&mut alloc).initialize_into(())
        };
        let vec = vec![
            V(100), V(10), V(20), V(30), V(7), V(8), V(9),
            V(17), V(18), V(29), V(27), V(28), V(30)
        ];
        let mut expected = vec.clone();
        expected.sort_by(|a, b| b.cmp(a));
        assert_push_equals_sorted_pop(&mut heap, vec, expected);
    })
}
