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

//! Benchmark for libnativewindow AHardwareBuffer bindings

#![allow(dead_code)]
#![allow(missing_docs)]

use criterion::*;
use nativewindow::*;

#[inline]
fn create_720p_buffer() -> HardwareBuffer {
    HardwareBuffer::new(
        1280,
        720,
        1,
        AHardwareBuffer_Format::AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
        AHardwareBuffer_UsageFlags::AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
    )
    .unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("allocate_deallocate", |b| {
        b.iter(|| {
            let buffer = create_720p_buffer();
            drop(buffer);
        })
    });

    let buffer = create_720p_buffer();
    c.bench_with_input(BenchmarkId::new("id", "buffer"), &buffer, |b, buffer| {
        b.iter(|| {
            buffer.id();
        })
    });

    // This benchmark exercises getters that need to fetch data via an
    // underlying call to AHardwareBuffer_describe.
    c.bench_with_input(BenchmarkId::new("desc", "buffer"), &buffer, |b, buffer| {
        b.iter(|| {
            buffer.width();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
