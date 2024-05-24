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

use super::Buffer;

/// Trait that represents an owner of a buffer that might need to handle events such as a buffer
/// being dropped.
pub trait BufferOwner: Send + Sync {
    /// Called when a buffer is dropped.
    fn on_return(&self, buffer: &Buffer);
}

pub(super) struct NoBufferOwner;

impl BufferOwner for NoBufferOwner {
    fn on_return(&self, _buffer: &Buffer) {}
}
