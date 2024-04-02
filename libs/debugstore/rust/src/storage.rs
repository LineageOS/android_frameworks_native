/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crossbeam_queue::ArrayQueue;

/// A thread-safe storage that allows non-blocking attempts to store and visit elements.
pub struct Storage<T, const N: usize> {
    insertion_buffer: ArrayQueue<T>,
}

impl<T, const N: usize> Storage<T, N> {
    /// Creates a new Storage with the specified size.
    pub fn new() -> Self {
        Self { insertion_buffer: ArrayQueue::new(N) }
    }

    /// Inserts a value into the storage, returning an error if the lock cannot be acquired.
    pub fn insert(&self, value: T) {
        self.insertion_buffer.force_push(value);
    }

    /// Folds over the elements in the storage using the provided function.
    pub fn fold<U, F>(&self, init: U, mut func: F) -> U
    where
        F: FnMut(U, &T) -> U,
    {
        let mut acc = init;
        while let Some(value) = self.insertion_buffer.pop() {
            acc = func(acc, &value);
        }
        acc
    }

    /// Returns the number of elements that have been inserted into the storage.
    pub fn len(&self) -> usize {
        self.insertion_buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_retrieve() {
        let storage = Storage::<i32, 10>::new();
        storage.insert(7);

        let sum = storage.fold(0, |acc, &x| acc + x);
        assert_eq!(sum, 7, "The sum of the elements should be equal to the inserted value.");
    }

    #[test]
    fn test_fold_functionality() {
        let storage = Storage::<i32, 5>::new();
        storage.insert(1);
        storage.insert(2);
        storage.insert(3);

        let sum = storage.fold(0, |acc, &x| acc + x);
        assert_eq!(
            sum, 6,
            "The sum of the elements should be equal to the sum of inserted values."
        );
    }

    #[test]
    fn test_insert_and_retrieve_multiple_values() {
        let storage = Storage::<i32, 10>::new();
        storage.insert(1);
        storage.insert(2);
        storage.insert(5);

        let first_sum = storage.fold(0, |acc, &x| acc + x);
        assert_eq!(first_sum, 8, "The sum of the elements should be equal to the inserted values.");

        storage.insert(30);
        storage.insert(22);

        let second_sum = storage.fold(0, |acc, &x| acc + x);
        assert_eq!(
            second_sum, 52,
            "The sum of the elements should be equal to the inserted values."
        );
    }

    #[test]
    fn test_storage_limit() {
        let storage = Storage::<i32, 1>::new();
        storage.insert(1);
        // This value should overwrite the previously inserted value (1).
        storage.insert(4);
        let sum = storage.fold(0, |acc, &x| acc + x);
        assert_eq!(sum, 4, "The sum of the elements should be equal to the inserted values.");
    }

    #[test]
    fn test_concurrent_insertions() {
        use std::sync::Arc;
        use std::thread;

        let storage = Arc::new(Storage::<i32, 100>::new());
        let threads: Vec<_> = (0..10)
            .map(|_| {
                let storage_clone = Arc::clone(&storage);
                thread::spawn(move || {
                    for i in 0..10 {
                        storage_clone.insert(i);
                    }
                })
            })
            .collect();

        for thread in threads {
            thread.join().expect("Thread should finish without panicking");
        }

        let count = storage.fold(0, |acc, _| acc + 1);
        assert_eq!(count, 100, "Storage should be filled to its limit with concurrent insertions.");
    }
}
