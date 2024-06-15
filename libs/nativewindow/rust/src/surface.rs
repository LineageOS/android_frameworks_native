// Copyright (C) 2024 The Android Open Source Project
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

//! Rust wrapper for `ANativeWindow` and related types.

use binder::{
    binder_impl::{BorrowedParcel, UnstructuredParcelable},
    impl_deserialize_for_unstructured_parcelable, impl_serialize_for_unstructured_parcelable,
    unstable_api::{status_result, AsNative},
    StatusCode,
};
use nativewindow_bindgen::{
    AHardwareBuffer_Format, ANativeWindow, ANativeWindow_acquire, ANativeWindow_getFormat,
    ANativeWindow_getHeight, ANativeWindow_getWidth, ANativeWindow_readFromParcel,
    ANativeWindow_release, ANativeWindow_writeToParcel,
};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::ptr::{null_mut, NonNull};

/// Wrapper around an opaque C `ANativeWindow`.
#[derive(PartialEq, Eq)]
pub struct Surface(NonNull<ANativeWindow>);

impl Surface {
    /// Returns the current width in pixels of the window surface.
    pub fn width(&self) -> Result<u32, ErrorCode> {
        // SAFETY: The ANativeWindow pointer we pass is guaranteed to be non-null and valid because
        // it must have been allocated by `ANativeWindow_allocate` or `ANativeWindow_readFromParcel`
        // and we have not yet released it.
        let width = unsafe { ANativeWindow_getWidth(self.0.as_ptr()) };
        width.try_into().map_err(|_| ErrorCode(width))
    }

    /// Returns the current height in pixels of the window surface.
    pub fn height(&self) -> Result<u32, ErrorCode> {
        // SAFETY: The ANativeWindow pointer we pass is guaranteed to be non-null and valid because
        // it must have been allocated by `ANativeWindow_allocate` or `ANativeWindow_readFromParcel`
        // and we have not yet released it.
        let height = unsafe { ANativeWindow_getHeight(self.0.as_ptr()) };
        height.try_into().map_err(|_| ErrorCode(height))
    }

    /// Returns the current pixel format of the window surface.
    pub fn format(&self) -> Result<AHardwareBuffer_Format::Type, ErrorCode> {
        // SAFETY: The ANativeWindow pointer we pass is guaranteed to be non-null and valid because
        // it must have been allocated by `ANativeWindow_allocate` or `ANativeWindow_readFromParcel`
        // and we have not yet released it.
        let format = unsafe { ANativeWindow_getFormat(self.0.as_ptr()) };
        format.try_into().map_err(|_| ErrorCode(format))
    }
}

impl Drop for Surface {
    fn drop(&mut self) {
        // SAFETY: The ANativeWindow pointer we pass is guaranteed to be non-null and valid because
        // it must have been allocated by `ANativeWindow_allocate` or `ANativeWindow_readFromParcel`
        // and we have not yet released it.
        unsafe { ANativeWindow_release(self.0.as_ptr()) }
    }
}

impl Debug for Surface {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("Surface")
            .field("width", &self.width())
            .field("height", &self.height())
            .field("format", &self.format())
            .finish()
    }
}

impl Clone for Surface {
    fn clone(&self) -> Self {
        // SAFETY: The ANativeWindow pointer we pass is guaranteed to be non-null and valid because
        // it must have been allocated by `ANativeWindow_allocate` or `ANativeWindow_readFromParcel`
        // and we have not yet released it.
        unsafe { ANativeWindow_acquire(self.0.as_ptr()) };
        Self(self.0)
    }
}

impl UnstructuredParcelable for Surface {
    fn write_to_parcel(&self, parcel: &mut BorrowedParcel) -> Result<(), StatusCode> {
        let status =
        // SAFETY: The ANativeWindow pointer we pass is guaranteed to be non-null and valid because
        // it must have been allocated by `ANativeWindow_allocate` or `ANativeWindow_readFromParcel`
        // and we have not yet released it.
        unsafe { ANativeWindow_writeToParcel(self.0.as_ptr(), parcel.as_native_mut()) };
        status_result(status)
    }

    fn from_parcel(parcel: &BorrowedParcel) -> Result<Self, StatusCode> {
        let mut buffer = null_mut();

        let status =
        // SAFETY: Both pointers must be valid because they are obtained from references.
        // `ANativeWindow_readFromParcel` doesn't store them or do anything else special
        // with them. If it returns success then it will have allocated a new
        // `ANativeWindow` and incremented the reference count, so we can use it until we
        // release it.
            unsafe { ANativeWindow_readFromParcel(parcel.as_native(), &mut buffer) };

        status_result(status)?;

        Ok(Self(
            NonNull::new(buffer)
                .expect("ANativeWindow_readFromParcel returned success but didn't allocate buffer"),
        ))
    }
}

impl_deserialize_for_unstructured_parcelable!(Surface);
impl_serialize_for_unstructured_parcelable!(Surface);

// SAFETY: The underlying *ANativeWindow can be moved between threads.
unsafe impl Send for Surface {}

// SAFETY: The underlying *ANativeWindow can be used from multiple threads concurrently.
unsafe impl Sync for Surface {}

/// An error code returned by methods on [`Surface`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ErrorCode(i32);

impl Error for ErrorCode {}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Error {}", self.0)
    }
}
