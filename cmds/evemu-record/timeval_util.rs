/*
 * Copyright 2023 The Android Open Source Project
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

//! Utility methods for manipulating `libc::timeval`s.

use nix::libc::timeval;

fn timeval_to_microseconds(time: &timeval) -> i64 {
    time.tv_sec * 1_000_000 + time.tv_usec
}

fn microseconds_to_timeval(microseconds: i64) -> timeval {
    timeval { tv_sec: microseconds / 1_000_000, tv_usec: microseconds % 1_000_000 }
}

pub fn subtract(a: &timeval, b: &timeval) -> timeval {
    subtract_microseconds(a, timeval_to_microseconds(b))
}

pub fn subtract_microseconds(a: &timeval, microseconds: i64) -> timeval {
    microseconds_to_timeval(timeval_to_microseconds(a) - microseconds)
}
