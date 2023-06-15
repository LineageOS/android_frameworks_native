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

//! Validate the incoming motion stream.
//! This class is not thread-safe.
//! State is stored in the "InputVerifier" object
//! that can be created via the 'create' method.
//! Usage:
//! Box<InputVerifier> verifier = create("inputChannel name");
//! result = process_movement(verifier, ...);
//! if (result) {
//!    crash(result.error_message());
//! }

use std::collections::HashMap;
use std::collections::HashSet;

use bitflags::bitflags;
use log::info;

#[cxx::bridge(namespace = "android::input")]
mod ffi {
    #[namespace = "android"]
    unsafe extern "C++" {
        include!("ffi/FromRustToCpp.h");
        fn shouldLog(tag: &str) -> bool;
    }
    #[namespace = "android::input::verifier"]
    extern "Rust" {
        type InputVerifier;

        fn create(name: String) -> Box<InputVerifier>;
        fn process_movement(
            verifier: &mut InputVerifier,
            device_id: i32,
            action: u32,
            pointer_properties: &[RustPointerProperties],
            flags: i32,
        ) -> String;
    }

    pub struct RustPointerProperties {
        id: i32,
    }
}

use crate::ffi::shouldLog;
use crate::ffi::RustPointerProperties;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct DeviceId(i32);

fn process_movement(
    verifier: &mut InputVerifier,
    device_id: i32,
    action: u32,
    pointer_properties: &[RustPointerProperties],
    flags: i32,
) -> String {
    let result = verifier.process_movement(
        DeviceId(device_id),
        action,
        pointer_properties,
        Flags::from_bits(flags).unwrap(),
    );
    match result {
        Ok(()) => "".to_string(),
        Err(e) => e,
    }
}

fn create(name: String) -> Box<InputVerifier> {
    Box::new(InputVerifier::new(&name))
}

#[repr(u32)]
enum MotionAction {
    Down = input_bindgen::AMOTION_EVENT_ACTION_DOWN,
    Up = input_bindgen::AMOTION_EVENT_ACTION_UP,
    Move = input_bindgen::AMOTION_EVENT_ACTION_MOVE,
    Cancel = input_bindgen::AMOTION_EVENT_ACTION_CANCEL,
    Outside = input_bindgen::AMOTION_EVENT_ACTION_OUTSIDE,
    PointerDown { action_index: usize } = input_bindgen::AMOTION_EVENT_ACTION_POINTER_DOWN,
    PointerUp { action_index: usize } = input_bindgen::AMOTION_EVENT_ACTION_POINTER_UP,
    HoverEnter = input_bindgen::AMOTION_EVENT_ACTION_HOVER_ENTER,
    HoverMove = input_bindgen::AMOTION_EVENT_ACTION_HOVER_MOVE,
    HoverExit = input_bindgen::AMOTION_EVENT_ACTION_HOVER_EXIT,
    Scroll = input_bindgen::AMOTION_EVENT_ACTION_SCROLL,
    ButtonPress = input_bindgen::AMOTION_EVENT_ACTION_BUTTON_PRESS,
    ButtonRelease = input_bindgen::AMOTION_EVENT_ACTION_BUTTON_RELEASE,
}

fn get_action_index(action: u32) -> usize {
    let index = (action & input_bindgen::AMOTION_EVENT_ACTION_POINTER_INDEX_MASK)
        >> input_bindgen::AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
    index.try_into().unwrap()
}

impl From<u32> for MotionAction {
    fn from(action: u32) -> Self {
        let action_masked = action & input_bindgen::AMOTION_EVENT_ACTION_MASK;
        let action_index = get_action_index(action);
        match action_masked {
            input_bindgen::AMOTION_EVENT_ACTION_DOWN => MotionAction::Down,
            input_bindgen::AMOTION_EVENT_ACTION_UP => MotionAction::Up,
            input_bindgen::AMOTION_EVENT_ACTION_MOVE => MotionAction::Move,
            input_bindgen::AMOTION_EVENT_ACTION_CANCEL => MotionAction::Cancel,
            input_bindgen::AMOTION_EVENT_ACTION_OUTSIDE => MotionAction::Outside,
            input_bindgen::AMOTION_EVENT_ACTION_POINTER_DOWN => {
                MotionAction::PointerDown { action_index }
            }
            input_bindgen::AMOTION_EVENT_ACTION_POINTER_UP => {
                MotionAction::PointerUp { action_index }
            }
            input_bindgen::AMOTION_EVENT_ACTION_HOVER_ENTER => MotionAction::HoverEnter,
            input_bindgen::AMOTION_EVENT_ACTION_HOVER_MOVE => MotionAction::HoverMove,
            input_bindgen::AMOTION_EVENT_ACTION_HOVER_EXIT => MotionAction::HoverExit,
            input_bindgen::AMOTION_EVENT_ACTION_SCROLL => MotionAction::Scroll,
            input_bindgen::AMOTION_EVENT_ACTION_BUTTON_PRESS => MotionAction::ButtonPress,
            input_bindgen::AMOTION_EVENT_ACTION_BUTTON_RELEASE => MotionAction::ButtonRelease,
            _ => panic!("Unknown action: {}", action),
        }
    }
}

bitflags! {
    struct Flags: i32 {
        const CANCELED = input_bindgen::AMOTION_EVENT_FLAG_CANCELED;
    }
}

fn motion_action_to_string(action: u32) -> String {
    match action.into() {
        MotionAction::Down => "DOWN".to_string(),
        MotionAction::Up => "UP".to_string(),
        MotionAction::Move => "MOVE".to_string(),
        MotionAction::Cancel => "CANCEL".to_string(),
        MotionAction::Outside => "OUTSIDE".to_string(),
        MotionAction::PointerDown { action_index } => {
            format!("POINTER_DOWN({})", action_index)
        }
        MotionAction::PointerUp { action_index } => {
            format!("POINTER_UP({})", action_index)
        }
        MotionAction::HoverMove => "HOVER_MOVE".to_string(),
        MotionAction::Scroll => "SCROLL".to_string(),
        MotionAction::HoverEnter => "HOVER_ENTER".to_string(),
        MotionAction::HoverExit => "HOVER_EXIT".to_string(),
        MotionAction::ButtonPress => "BUTTON_PRESS".to_string(),
        MotionAction::ButtonRelease => "BUTTON_RELEASE".to_string(),
    }
}

/**
 * Log all of the movements that are sent to this verifier. Helps to identify the streams that lead
 * to inconsistent events.
 * Enable this via "adb shell setprop log.tag.InputVerifierLogEvents DEBUG"
 */
fn log_events() -> bool {
    shouldLog("InputVerifierLogEvents")
}

struct InputVerifier {
    name: String,
    touching_pointer_ids_by_device: HashMap<DeviceId, HashSet<i32>>,
}

impl InputVerifier {
    fn new(name: &str) -> Self {
        logger::init(
            logger::Config::default()
                .with_tag_on_device("InputVerifier")
                .with_min_level(log::Level::Trace),
        );
        Self { name: name.to_owned(), touching_pointer_ids_by_device: HashMap::new() }
    }

    fn process_movement(
        &mut self,
        device_id: DeviceId,
        action: u32,
        pointer_properties: &[RustPointerProperties],
        flags: Flags,
    ) -> Result<(), String> {
        if log_events() {
            info!(
                "Processing {} for device {:?} ({} pointer{}) on {}",
                motion_action_to_string(action),
                device_id,
                pointer_properties.len(),
                if pointer_properties.len() == 1 { "" } else { "s" },
                self.name
            );
        }

        match action.into() {
            MotionAction::Down => {
                let it = self
                    .touching_pointer_ids_by_device
                    .entry(device_id)
                    .or_insert_with(HashSet::new);
                let pointer_id = pointer_properties[0].id;
                if it.contains(&pointer_id) {
                    return Err(format!(
                        "{}: Invalid DOWN event - pointers already down for device {:?}: {:?}",
                        self.name, device_id, it
                    ));
                }
                it.insert(pointer_id);
            }
            MotionAction::PointerDown { action_index } => {
                if !self.touching_pointer_ids_by_device.contains_key(&device_id) {
                    return Err(format!(
                        "{}: Received POINTER_DOWN but no pointers are currently down \
                        for device {:?}",
                        self.name, device_id
                    ));
                }
                let it = self.touching_pointer_ids_by_device.get_mut(&device_id).unwrap();
                let pointer_id = pointer_properties[action_index].id;
                if it.contains(&pointer_id) {
                    return Err(format!(
                        "{}: Pointer with id={} not found in the properties",
                        self.name, pointer_id
                    ));
                }
                it.insert(pointer_id);
            }
            MotionAction::Move => {
                if !self.ensure_touching_pointers_match(device_id, pointer_properties) {
                    return Err(format!(
                        "{}: ACTION_MOVE touching pointers don't match",
                        self.name
                    ));
                }
            }
            MotionAction::PointerUp { action_index } => {
                if !self.touching_pointer_ids_by_device.contains_key(&device_id) {
                    return Err(format!(
                        "{}: Received POINTER_UP but no pointers are currently down for device \
                        {:?}",
                        self.name, device_id
                    ));
                }
                let it = self.touching_pointer_ids_by_device.get_mut(&device_id).unwrap();
                let pointer_id = pointer_properties[action_index].id;
                it.remove(&pointer_id);
            }
            MotionAction::Up => {
                if !self.touching_pointer_ids_by_device.contains_key(&device_id) {
                    return Err(format!(
                        "{} Received ACTION_UP but no pointers are currently down for device {:?}",
                        self.name, device_id
                    ));
                }
                let it = self.touching_pointer_ids_by_device.get_mut(&device_id).unwrap();
                if it.len() != 1 {
                    return Err(format!(
                        "{}: Got ACTION_UP, but we have pointers: {:?} for device {:?}",
                        self.name, it, device_id
                    ));
                }
                let pointer_id = pointer_properties[0].id;
                if !it.contains(&pointer_id) {
                    return Err(format!(
                        "{}: Got ACTION_UP, but pointerId {} is not touching. Touching pointers:\
                        {:?} for device {:?}",
                        self.name, pointer_id, it, device_id
                    ));
                }
                it.clear();
            }
            MotionAction::Cancel => {
                if flags.contains(Flags::CANCELED) {
                    return Err(format!(
                        "{}: For ACTION_CANCEL, must set FLAG_CANCELED",
                        self.name
                    ));
                }
                if !self.ensure_touching_pointers_match(device_id, pointer_properties) {
                    return Err(format!(
                        "{}: Got ACTION_CANCEL, but the pointers don't match. \
                        Existing pointers: {:?}",
                        self.name, self.touching_pointer_ids_by_device
                    ));
                }
                self.touching_pointer_ids_by_device.remove(&device_id);
            }
            _ => return Ok(()),
        }
        Ok(())
    }

    fn ensure_touching_pointers_match(
        &self,
        device_id: DeviceId,
        pointer_properties: &[RustPointerProperties],
    ) -> bool {
        let Some(pointers) = self.touching_pointer_ids_by_device.get(&device_id) else {
            return false;
        };

        for pointer_property in pointer_properties.iter() {
            let pointer_id = pointer_property.id;
            if !pointers.contains(&pointer_id) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::DeviceId;
    use crate::Flags;
    use crate::InputVerifier;
    use crate::RustPointerProperties;
    #[test]
    fn single_pointer_stream() {
        let mut verifier = InputVerifier::new("Test");
        let pointer_properties = Vec::from([RustPointerProperties { id: 0 }]);
        assert!(verifier
            .process_movement(
                DeviceId(1),
                input_bindgen::AMOTION_EVENT_ACTION_DOWN,
                &pointer_properties,
                Flags::empty(),
            )
            .is_ok());
        assert!(verifier
            .process_movement(
                DeviceId(1),
                input_bindgen::AMOTION_EVENT_ACTION_MOVE,
                &pointer_properties,
                Flags::empty(),
            )
            .is_ok());
        assert!(verifier
            .process_movement(
                DeviceId(1),
                input_bindgen::AMOTION_EVENT_ACTION_UP,
                &pointer_properties,
                Flags::empty(),
            )
            .is_ok());
    }

    #[test]
    fn multi_device_stream() {
        let mut verifier = InputVerifier::new("Test");
        let pointer_properties = Vec::from([RustPointerProperties { id: 0 }]);
        assert!(verifier
            .process_movement(
                DeviceId(1),
                input_bindgen::AMOTION_EVENT_ACTION_DOWN,
                &pointer_properties,
                Flags::empty(),
            )
            .is_ok());
        assert!(verifier
            .process_movement(
                DeviceId(1),
                input_bindgen::AMOTION_EVENT_ACTION_MOVE,
                &pointer_properties,
                Flags::empty(),
            )
            .is_ok());
        assert!(verifier
            .process_movement(
                DeviceId(2),
                input_bindgen::AMOTION_EVENT_ACTION_DOWN,
                &pointer_properties,
                Flags::empty(),
            )
            .is_ok());
        assert!(verifier
            .process_movement(
                DeviceId(2),
                input_bindgen::AMOTION_EVENT_ACTION_MOVE,
                &pointer_properties,
                Flags::empty(),
            )
            .is_ok());
        assert!(verifier
            .process_movement(
                DeviceId(1),
                input_bindgen::AMOTION_EVENT_ACTION_UP,
                &pointer_properties,
                Flags::empty(),
            )
            .is_ok());
    }

    #[test]
    fn test_invalid_up() {
        let mut verifier = InputVerifier::new("Test");
        let pointer_properties = Vec::from([RustPointerProperties { id: 0 }]);
        assert!(verifier
            .process_movement(
                DeviceId(1),
                input_bindgen::AMOTION_EVENT_ACTION_UP,
                &pointer_properties,
                Flags::empty(),
            )
            .is_err());
    }
}
