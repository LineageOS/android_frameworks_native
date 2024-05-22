/*
 * Copyright 2024 The Android Open Source Project
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

//! Contains the KeyboardClassifier, that tries to identify whether an Input device is an
//! alphabetic or non-alphabetic keyboard. It also tracks the KeyEvents produced by the device
//! in order to verify/change the inferred keyboard type.

use crate::input::{DeviceId, InputDevice, KeyboardType};
use crate::ModifierState;

/// The KeyboardClassifier is used to classify a keyboard device into non-keyboard, alphabetic
/// keyboard or non-alphabetic keyboard
#[derive(Default)]
pub struct KeyboardClassifier {}

impl KeyboardClassifier {
    /// Create a new KeyboardClassifier
    pub fn new() -> Self {
        Default::default()
    }

    /// Adds keyboard to KeyboardClassifier
    pub fn notify_keyboard_changed(&mut self, _device: InputDevice) {
        // TODO(b/263559234): Implement method
    }

    /// Get keyboard type for a tracked keyboard in KeyboardClassifier
    pub fn get_keyboard_type(&self, _device_id: DeviceId) -> KeyboardType {
        // TODO(b/263559234): Implement method
        KeyboardType::None
    }

    /// Tells if keyboard type classification is finalized. Once finalized the classification can't
    /// change until device is reconnected again.
    pub fn is_finalized(&self, _device_id: DeviceId) -> bool {
        // TODO(b/263559234): Implement method
        false
    }

    /// Process a key event and change keyboard type if required.
    pub fn process_key(
        &mut self,
        _device_id: DeviceId,
        _evdev_code: i32,
        _modifier_state: ModifierState,
    ) {
        // TODO(b/263559234): Implement method
    }
}
