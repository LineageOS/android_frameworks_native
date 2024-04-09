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

//! Rust wrapper for libgui AIDL types.

use binder::{
    binder_impl::{BorrowedParcel, UnstructuredParcelable},
    impl_deserialize_for_unstructured_parcelable, impl_serialize_for_unstructured_parcelable,
    StatusCode,
};

#[allow(dead_code)]
macro_rules! stub_unstructured_parcelable {
    ($name:ident) => {
        /// Unimplemented stub parcelable.
        #[allow(dead_code)]
        #[derive(Debug, Default)]
        pub struct $name(Option<()>);

        impl UnstructuredParcelable for $name {
            fn write_to_parcel(&self, _parcel: &mut BorrowedParcel) -> Result<(), StatusCode> {
                todo!()
            }

            fn from_parcel(_parcel: &BorrowedParcel) -> Result<Self, StatusCode> {
                todo!()
            }
        }

        impl_deserialize_for_unstructured_parcelable!($name);
        impl_serialize_for_unstructured_parcelable!($name);
    };
}

stub_unstructured_parcelable!(BitTube);
stub_unstructured_parcelable!(CaptureArgs);
stub_unstructured_parcelable!(DisplayCaptureArgs);
stub_unstructured_parcelable!(DisplayInfo);
stub_unstructured_parcelable!(LayerCaptureArgs);
stub_unstructured_parcelable!(LayerDebugInfo);
stub_unstructured_parcelable!(LayerMetadata);
stub_unstructured_parcelable!(ParcelableVsyncEventData);
stub_unstructured_parcelable!(ScreenCaptureResults);
stub_unstructured_parcelable!(VsyncEventData);
stub_unstructured_parcelable!(WindowInfo);
stub_unstructured_parcelable!(WindowInfosUpdate);
