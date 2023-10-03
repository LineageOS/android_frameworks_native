// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A Buffer Pool containing and managing HardwareBuffers

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use nativewindow::*;

use crate::StreamConfig;

use super::{Buffer, BufferOwner};

pub(super) struct BufferPoolInner {
    size: usize,
    hardware_buffers: HashMap<u64, HardwareBuffer>,
    available_buffers: Vec<u64>,
}

impl BufferPoolInner {
    pub(super) fn return_buffer(&mut self, buffer_id: u64) {
        assert!(self.hardware_buffers.contains_key(&buffer_id));
        assert!(!self.available_buffers.contains(&buffer_id));

        self.available_buffers.push(buffer_id);
    }
}

struct BufferPoolOwner(Weak<Mutex<BufferPoolInner>>);

impl BufferOwner for BufferPoolOwner {
    fn on_return(&self, buffer: &Buffer) {
        if let Some(locked_buffer_pool) = self.0.upgrade() {
            let mut buffer_pool = locked_buffer_pool.lock().unwrap();

            buffer_pool.return_buffer(buffer.id());
        }
    }
}

/// A thread-safe collection of buffers.
///
/// A buffer pool can be of arbitrary size. It creates and then holds references to all buffers
/// associated with it.
pub struct BufferPool(Arc<Mutex<BufferPoolInner>>);

impl BufferPool {
    /// Creates a new buffer pool of size pool_size. All buffers will be created according to
    /// the stream config.
    ///
    /// This constructor creates all buffers at initialization.
    pub fn new(pool_size: usize, stream_config: StreamConfig) -> Option<Self> {
        let mut hardware_buffers = HashMap::new();
        let mut available_buffers = Vec::new();
        for _ in 0..pool_size {
            if let Some(buffer) = stream_config.create_hardware_buffer() {
                available_buffers.push(buffer.id());
                hardware_buffers.insert(buffer.id(), buffer);
            } else {
                return None;
            }
        }
        Some(Self(Arc::new(Mutex::new(BufferPoolInner {
            size: pool_size,
            hardware_buffers,
            available_buffers,
        }))))
    }

    /// Try to acquire the next available buffer in the buffer pool.
    ///
    /// If all buffers are in use it will return None.
    pub fn next_buffer(&mut self) -> Option<Buffer> {
        let mut inner = self.0.lock().unwrap();
        if let Some(buffer_id) = inner.available_buffers.pop() {
            Some(Buffer::new(
                Box::new(BufferPoolOwner(Arc::downgrade(&self.0))),
                inner.hardware_buffers[&buffer_id].clone(),
            ))
        } else {
            None
        }
    }

    /// Gets the size of the buffer pool.
    pub fn size(&self) -> usize {
        let inner = self.0.lock().unwrap();
        inner.size
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const STREAM_CONFIG: StreamConfig = StreamConfig {
        width: 1,
        height: 1,
        layers: 1,
        format: AHardwareBuffer_Format::AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
        usage: AHardwareBuffer_UsageFlags::AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
        stride: 0,
    };

    #[test]
    fn buffer_pool_next_buffer() {
        let mut buffer_pool = BufferPool::new(1, STREAM_CONFIG).unwrap();
        let next_buffer = buffer_pool.next_buffer();

        assert!(next_buffer.is_some());
        assert!(buffer_pool.next_buffer().is_none());
    }

    #[test]
    fn drop_buffer_returns_to_pool() {
        let mut buffer_pool = BufferPool::new(1, STREAM_CONFIG).unwrap();
        let next_buffer = buffer_pool.next_buffer();

        assert!(next_buffer.is_some());
        drop(next_buffer);
        assert!(buffer_pool.next_buffer().is_some());
    }
}
