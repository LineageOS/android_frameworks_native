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

//! The rust component of libinput.

mod input;
mod input_verifier;

pub use input::{DeviceId, MotionAction, MotionFlags, Source};
pub use input_verifier::InputVerifier;

#[cxx::bridge(namespace = "android::input")]
#[allow(unsafe_op_in_unsafe_fn)]
mod ffi {
    #[namespace = "android"]
    unsafe extern "C++" {
        include!("ffi/FromRustToCpp.h");
        fn shouldLog(tag: &str) -> bool;
    }

    #[namespace = "android::input::verifier"]
    extern "Rust" {
        /// Used to validate the incoming motion stream.
        /// This class is not thread-safe.
        /// State is stored in the "InputVerifier" object
        /// that can be created via the 'create' method.
        /// Usage:
        ///
        /// ```ignore
        /// Box<InputVerifier> verifier = create("inputChannel name");
        /// result = process_movement(verifier, ...);
        /// if (result) {
        ///    crash(result.error_message());
        /// }
        /// ```
        type InputVerifier;
        fn create(name: String) -> Box<InputVerifier>;
        fn process_movement(
            verifier: &mut InputVerifier,
            device_id: i32,
            source: u32,
            action: u32,
            pointer_properties: &[RustPointerProperties],
            flags: u32,
        ) -> String;
        fn reset_device(verifier: &mut InputVerifier, device_id: i32);
    }

    #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
    pub struct RustPointerProperties {
        pub id: i32,
    }
}

use crate::ffi::RustPointerProperties;

fn create(name: String) -> Box<InputVerifier> {
    Box::new(InputVerifier::new(&name, ffi::shouldLog("InputVerifierLogEvents")))
}

fn process_movement(
    verifier: &mut InputVerifier,
    device_id: i32,
    source: u32,
    action: u32,
    pointer_properties: &[RustPointerProperties],
    flags: u32,
) -> String {
    let result = verifier.process_movement(
        DeviceId(device_id),
        Source::from_bits(source).unwrap(),
        action,
        pointer_properties,
        MotionFlags::from_bits(flags).unwrap(),
    );
    match result {
        Ok(()) => "".to_string(),
        Err(e) => e,
    }
}

fn reset_device(verifier: &mut InputVerifier, device_id: i32) {
    verifier.reset_device(DeviceId(device_id));
}
