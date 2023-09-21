/*
 * Copyright (C) 2022 The Android Open Source Project
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

use binder::binder_impl::BorrowedParcel;
use binder::{ParcelFileDescriptor, Parcelable, SpIBinder};
use binderReadParcelIface::aidl::parcelables::EmptyParcelable::EmptyParcelable;
use binderReadParcelIface::aidl::parcelables::GenericDataParcelable::GenericDataParcelable;
use binderReadParcelIface::aidl::parcelables::SingleDataParcelable::SingleDataParcelable;

macro_rules! read_parcel_interface {
    ($data_type:ty) => {
        |parcel: &BorrowedParcel<'_>| {
            let _res = parcel.read::<$data_type>();
        }
    };
}

#[derive(Debug, Default)]
pub struct SomeParcelable {
    pub data: i32,
}

impl binder::Parcelable for SomeParcelable {
    fn write_to_parcel(
        &self,
        parcel: &mut binder::binder_impl::BorrowedParcel,
    ) -> std::result::Result<(), binder::StatusCode> {
        parcel.sized_write(|subparcel| subparcel.write(&self.data))
    }

    fn read_from_parcel(
        &mut self,
        parcel: &binder::binder_impl::BorrowedParcel,
    ) -> std::result::Result<(), binder::StatusCode> {
        parcel.sized_read(|subparcel| match subparcel.read() {
            Ok(result) => {
                self.data = result;
                Ok(())
            }
            Err(e) => Err(e),
        })
    }
}

binder::impl_deserialize_for_parcelable!(SomeParcelable);

pub const READ_FUNCS: &[fn(&BorrowedParcel<'_>)] = &[
    //read basic types
    read_parcel_interface!(bool),
    read_parcel_interface!(i8),
    read_parcel_interface!(i32),
    read_parcel_interface!(i64),
    read_parcel_interface!(f32),
    read_parcel_interface!(f64),
    read_parcel_interface!(u16),
    read_parcel_interface!(u32),
    read_parcel_interface!(u64),
    read_parcel_interface!(String),
    //read vec of basic types
    read_parcel_interface!(Vec<i8>),
    read_parcel_interface!(Vec<i32>),
    read_parcel_interface!(Vec<i64>),
    read_parcel_interface!(Vec<f32>),
    read_parcel_interface!(Vec<f64>),
    read_parcel_interface!(Vec<u16>),
    read_parcel_interface!(Vec<u32>),
    read_parcel_interface!(Vec<u64>),
    read_parcel_interface!(Vec<String>),
    read_parcel_interface!(Option<Vec<i8>>),
    read_parcel_interface!(Option<Vec<i32>>),
    read_parcel_interface!(Option<Vec<i64>>),
    read_parcel_interface!(Option<Vec<f32>>),
    read_parcel_interface!(Option<Vec<f64>>),
    read_parcel_interface!(Option<Vec<u16>>),
    read_parcel_interface!(Option<Vec<u32>>),
    read_parcel_interface!(Option<Vec<u64>>),
    read_parcel_interface!(Option<Vec<String>>),
    read_parcel_interface!(ParcelFileDescriptor),
    read_parcel_interface!(Vec<ParcelFileDescriptor>),
    read_parcel_interface!(Vec<Option<ParcelFileDescriptor>>),
    read_parcel_interface!(Option<Vec<ParcelFileDescriptor>>),
    read_parcel_interface!(Option<Vec<Option<ParcelFileDescriptor>>>),
    read_parcel_interface!(SpIBinder),
    read_parcel_interface!(Vec<SpIBinder>),
    read_parcel_interface!(Vec<Option<SpIBinder>>),
    read_parcel_interface!(Option<Vec<SpIBinder>>),
    read_parcel_interface!(Option<Vec<Option<SpIBinder>>>),
    read_parcel_interface!(SomeParcelable),
    read_parcel_interface!(Vec<SomeParcelable>),
    read_parcel_interface!(Vec<Option<SomeParcelable>>),
    read_parcel_interface!(Option<Vec<SomeParcelable>>),
    read_parcel_interface!(Option<Vec<Option<SomeParcelable>>>),
    // Fuzz read_from_parcel for AIDL generated parcelables
    |parcel| {
        let mut empty_parcelable: EmptyParcelable = EmptyParcelable::default();
        match empty_parcelable.read_from_parcel(parcel) {
            Ok(result) => result,
            Err(e) => {
                println!("EmptyParcelable: error occurred while reading from a parcel: {:?}", e)
            }
        }
    },
    |parcel| {
        let mut single_parcelable: SingleDataParcelable = SingleDataParcelable::default();
        match single_parcelable.read_from_parcel(parcel) {
            Ok(result) => result,
            Err(e) => println!(
                "SingleDataParcelable: error occurred while reading from a parcel: {:?}",
                e
            ),
        }
    },
    |parcel| {
        let mut generic_parcelable: GenericDataParcelable = GenericDataParcelable::default();
        match generic_parcelable.read_from_parcel(parcel) {
            Ok(result) => result,
            Err(e) => println!(
                "GenericDataParcelable: error occurred while reading from a parcel: {:?}",
                e
            ),
        }
    },
];
