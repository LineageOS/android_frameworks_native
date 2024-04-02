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

//! # Debug Store Crate
/// The Debug Store Crate provides functionalities for storing debug events.
/// It allows logging and retrieval of debug events, and associated data.
mod core;
mod event;
mod event_type;
mod storage;

pub use core::*;
pub use event::*;

use cxx::{CxxString, CxxVector};

#[cxx::bridge(namespace = "android::debugstore")]
#[allow(unsafe_op_in_unsafe_fn)]
mod cxxffi {
    extern "Rust" {
        fn debug_store_to_string() -> String;
        fn debug_store_record(name: &CxxString, data: &CxxVector<CxxString>);
        fn debug_store_begin(name: &CxxString, data: &CxxVector<CxxString>) -> u64;
        fn debug_store_end(id: u64, data: &CxxVector<CxxString>);
    }

    #[namespace = "android"]
    unsafe extern "C++" {
        include!("utils/SystemClock.h");
        fn uptimeMillis() -> i64;
    }
}

fn debug_store_to_string() -> String {
    DebugStore::get_instance().to_string()
}

fn debug_store_record(name: &CxxString, data: &CxxVector<CxxString>) {
    DebugStore::get_instance().record(name.to_string_lossy().into_owned(), cxx_vec_to_pairs(data));
}

fn debug_store_begin(name: &CxxString, data: &CxxVector<CxxString>) -> u64 {
    DebugStore::get_instance().begin(name.to_string_lossy().into_owned(), cxx_vec_to_pairs(data))
}

fn debug_store_end(id: u64, data: &CxxVector<CxxString>) {
    DebugStore::get_instance().end(id, cxx_vec_to_pairs(data));
}

fn cxx_vec_to_pairs(vec: &CxxVector<CxxString>) -> Vec<(String, String)> {
    vec.iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .chunks(2)
        .filter_map(|chunk| match chunk {
            [k, v] => Some((k.clone(), v.clone())),
            _ => None,
        })
        .collect()
}
