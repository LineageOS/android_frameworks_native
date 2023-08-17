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

//! # The rust component of InputFlinger
//!
//! We use cxxbridge to create IInputFlingerRust - the Rust component of inputflinger - and
//! pass it back to C++ as a local AIDL interface.

use binder::{
    unstable_api::{AIBinder, new_spibinder,},
    BinderFeatures, Interface, StatusCode, Strong,
};
use com_android_server_inputflinger::aidl::com::android::server::inputflinger::IInputFlingerRust::{
    BnInputFlingerRust, IInputFlingerRust,
    IInputFlingerRustBootstrapCallback::IInputFlingerRustBootstrapCallback,
};
use log::debug;

const LOG_TAG: &str = "inputflinger_bootstrap";

#[cxx::bridge]
mod ffi {
    extern "C++" {
        include!("InputFlingerBootstrap.h");
        type IInputFlingerRustBootstrapCallbackAIBinder;
    }

    extern "Rust" {
        unsafe fn create_inputflinger_rust(
            callback: *mut IInputFlingerRustBootstrapCallbackAIBinder,
        );
    }
}

/// Create the IInputFlingerRust implementation.
/// This is the singular entry point from C++ into Rust.
/// The `callback` parameter must be a valid pointer to an AIBinder implementation of
/// the `IInputFlingerRustBootstrapCallback` interface. The IInputFlingerRust implementation that
/// is created will be passed back through the callback from within this function.
/// NOTE: This function must not hold a strong reference to the callback beyond its scope.
///
/// # Safety
///
/// This function is safe iff `callback` is a valid pointer to an `AIBinder` interface of type
/// `IInputFlingerRustBootstrapCallback`. The pointer must have had its reference count manually
/// incremented using `AIBinder_incStrong`. See `binder::unstable_api::new_spibinder`.
unsafe fn create_inputflinger_rust(callback: *mut ffi::IInputFlingerRustBootstrapCallbackAIBinder) {
    logger::init(
        logger::Config::default().with_tag_on_device(LOG_TAG).with_min_level(log::Level::Trace),
    );

    let callback = callback as *mut AIBinder;
    if callback.is_null() {
        panic!("create_inputflinger_rust cannot be called with a null callback");
    }

    let Some(callback) = new_spibinder(callback) else {
            panic!("Failed to get SpAIBinder from raw callback pointer");
        };

    let callback: Result<Strong<dyn IInputFlingerRustBootstrapCallback>, StatusCode> =
        callback.into_interface();
    match callback {
        Ok(callback) => {
            debug!("Creating InputFlingerRust");
            let service =
                BnInputFlingerRust::new_binder(InputFlingerRust {}, BinderFeatures::default());
            callback.onProvideInputFlingerRust(&service).unwrap();
        }
        Err(status) => {
            panic!("Failed to convert AIBinder into the callback interface: {}", status);
        }
    }
}

struct InputFlingerRust {}

impl Interface for InputFlingerRust {}

impl IInputFlingerRust for InputFlingerRust {}

impl Drop for InputFlingerRust {
    fn drop(&mut self) {
        debug!("Destroying InputFlingerRust");
    }
}
