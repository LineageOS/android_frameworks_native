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

#![allow(missing_docs)]
#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

mod read_utils;

use crate::read_utils::get_read_funcs;
use binder::binder_impl::{
    Binder, BorrowedParcel, IBinderInternal, Parcel, Stability, TransactionCode,
};
use binder::{
    declare_binder_interface, BinderFeatures, Interface, Parcelable, ParcelableHolder, SpIBinder,
    StatusCode,
};
use binder_random_parcel_rs::create_random_parcel;
use libfuzzer_sys::arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
enum ReadOperations {
    SetDataPosition { pos: i32 },
    GetDataSize,
    ReadParcelableHolder { is_vintf: bool },
    ReadBasicTypes { indexes: Vec<usize> },
}

#[derive(Arbitrary, Debug)]
enum Operations<'a> {
    Transact { code: u32, flag: u32, data: &'a [u8] },
    Append { start: i32, len: i32, data1: &'a [u8], data2: &'a [u8], append_all: bool },
    Read { indexes: Vec<ReadOperations>, data: &'a [u8] },
}

/// Interface to fuzz transact with random parcel
pub trait BinderTransactTest: Interface {}

declare_binder_interface! {
    BinderTransactTest["Binder_Transact_Test"] {
        native: BnBinderTransactTest(on_transact),
        proxy: BpBinderTransactTest,
    }
}

impl BinderTransactTest for Binder<BnBinderTransactTest> {}

impl BinderTransactTest for BpBinderTransactTest {}

impl BinderTransactTest for () {}

fn on_transact(
    _service: &dyn BinderTransactTest,
    _code: TransactionCode,
    _parcel: &BorrowedParcel<'_>,
    _reply: &mut BorrowedParcel<'_>,
) -> Result<(), StatusCode> {
    Err(StatusCode::UNKNOWN_ERROR)
}

fn do_transact(code: u32, data: &[u8], flag: u32) {
    let p: Parcel = create_random_parcel(data);
    let spibinder: Option<SpIBinder> =
        Some(BnBinderTransactTest::new_binder((), BinderFeatures::default()).as_binder());
    let _reply = spibinder.submit_transact(code, p, flag);
}

fn do_append_fuzz(start: i32, len: i32, data1: &[u8], data2: &[u8], append_all: bool) {
    let mut p1 = create_random_parcel(data1);
    let p2 = create_random_parcel(data2);

    // Fuzz both append methods
    if append_all {
        match p1.append_all_from(&p2) {
            Ok(result) => result,
            Err(e) => {
                println!("Error occurred while appending a parcel using append_all_from: {:?}", e)
            }
        }
    } else {
        match p1.append_from(&p2, start, len) {
            Ok(result) => result,
            Err(e) => {
                println!("Error occurred while appending a parcel using append_from: {:?}", e)
            }
        }
    };
}

fn do_read_fuzz(read_operations: Vec<ReadOperations>, data: &[u8]) {
    let read_funcs = get_read_funcs();
    let parcel = create_random_parcel(data);

    for operation in read_operations {
        match operation {
            ReadOperations::SetDataPosition { pos } => {
                unsafe {
                    // Safety: Safe if pos is less than current size of the parcel.
                    // It relies on C++ code for bound checks
                    match parcel.set_data_position(pos) {
                        Ok(result) => result,
                        Err(e) => println!("error occurred while setting data position: {:?}", e),
                    }
                }
            }

            ReadOperations::GetDataSize => {
                let data_size = parcel.get_data_size();
                println!("data size from parcel: {:?}", data_size);
            }

            ReadOperations::ReadParcelableHolder { is_vintf } => {
                let stability = if is_vintf { Stability::Vintf } else { Stability::Local };
                let mut holder: ParcelableHolder = ParcelableHolder::new(stability);
                match holder.read_from_parcel(parcel.borrowed_ref()) {
                    Ok(result) => result,
                    Err(err) => {
                        println!("error occurred while reading from parcel: {:?}", err)
                    }
                }
            }

            ReadOperations::ReadBasicTypes { indexes } => {
                for index in indexes.iter() {
                    let read_index = index % read_funcs.len();
                    read_funcs[read_index](parcel.borrowed_ref());
                }
            }
        }
    }
}

fuzz_target!(|operations: Vec<Operations>| {
    for operation in operations {
        match operation {
            Operations::Transact { code, flag, data } => {
                do_transact(code, data, flag);
            }

            Operations::Append { start, len, data1, data2, append_all } => {
                do_append_fuzz(start, len, data1, data2, append_all);
            }

            Operations::Read { indexes, data } => {
                do_read_fuzz(indexes, data);
            }
        }
    }
});
