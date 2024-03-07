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

//! Wrapper around the HardwareBuffer

use nativewindow::*;

use super::{buffer_owner::NoBufferOwner, BufferOwner};

/// A wrapper for a hardware buffer.
///
/// This buffer may be associated with a buffer pool to which it will be returned to it when dropped.
pub struct Buffer {
    buffer_owner: Box<dyn BufferOwner>,
    hardware_buffer: HardwareBuffer,
}

impl Buffer {
    /// Create new buffer with a custom [BufferOwner].
    pub fn new(buffer_owner: Box<dyn BufferOwner>, hardware_buffer: HardwareBuffer) -> Self {
        Self { buffer_owner, hardware_buffer }
    }

    /// Create a new buffer with no association to any buffer pool.
    pub fn new_unowned(hardware_buffer: HardwareBuffer) -> Self {
        Self { buffer_owner: Box::new(NoBufferOwner), hardware_buffer }
    }

    /// Get the id of the underlying buffer.
    pub fn id(&self) -> u64 {
        self.hardware_buffer.id()
    }

    /// Get a reference to the underlying hardware buffer.
    pub fn buffer(&self) -> &HardwareBuffer {
        &self.hardware_buffer
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.buffer_owner.on_return(self);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::StreamConfig;

    const STREAM_CONFIG: StreamConfig = StreamConfig {
        width: 1,
        height: 1,
        layers: 1,
        format: AHardwareBuffer_Format::AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
        usage: AHardwareBuffer_UsageFlags::AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
        stride: 0,
    };

    #[test]
    fn test_get_buffer_id() {
        let hardware_buffer = STREAM_CONFIG.create_hardware_buffer().unwrap();
        let buffer_id = hardware_buffer.id();

        let buffer = Buffer::new_unowned(hardware_buffer);
        assert_eq!(buffer_id, buffer.id());
    }
}
