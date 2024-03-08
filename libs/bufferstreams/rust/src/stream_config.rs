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

use nativewindow::*;

/// The configuration of the buffers published by a [BufferPublisher] or
/// expected by a [BufferSubscriber].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// Width in pixels of streaming buffers.
    pub width: u32,
    /// Height in pixels of streaming buffers.
    pub height: u32,
    /// Number of layers of streaming buffers.
    pub layers: u32,
    /// Format of streaming buffers.
    pub format: AHardwareBuffer_Format::Type,
    /// Usage of streaming buffers.
    pub usage: AHardwareBuffer_UsageFlags,
    /// Stride of streaming buffers.
    pub stride: u32,
}

impl StreamConfig {
    /// Tries to create a new HardwareBuffer from settings in a [StreamConfig].
    pub fn create_hardware_buffer(&self) -> Option<HardwareBuffer> {
        HardwareBuffer::new(self.width, self.height, self.layers, self.format, self.usage)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_create_hardware_buffer() {
        let config = StreamConfig {
            width: 123,
            height: 456,
            layers: 1,
            format: AHardwareBuffer_Format::AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
            usage: AHardwareBuffer_UsageFlags::AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN
                | AHardwareBuffer_UsageFlags::AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN,
            stride: 0,
        };

        let maybe_buffer = config.create_hardware_buffer();
        assert!(maybe_buffer.is_some());

        let buffer = maybe_buffer.unwrap();
        assert_eq!(config.width, buffer.width());
        assert_eq!(config.height, buffer.height());
        assert_eq!(config.format, buffer.format());
        assert_eq!(config.usage, buffer.usage());
    }
}
