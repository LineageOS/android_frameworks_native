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

//! Common definitions of the Android Input Framework in rust.

use bitflags::bitflags;
use std::fmt;

/// The InputDevice ID.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DeviceId(pub i32);

#[repr(u32)]
pub enum SourceClass {
    None = input_bindgen::AINPUT_SOURCE_CLASS_NONE,
    Button = input_bindgen::AINPUT_SOURCE_CLASS_BUTTON,
    Pointer = input_bindgen::AINPUT_SOURCE_CLASS_POINTER,
    Navigation = input_bindgen::AINPUT_SOURCE_CLASS_NAVIGATION,
    Position = input_bindgen::AINPUT_SOURCE_CLASS_POSITION,
    Joystick = input_bindgen::AINPUT_SOURCE_CLASS_JOYSTICK,
}

bitflags! {
    /// Source of the input device or input events.
    #[derive(Debug, PartialEq)]
    pub struct Source: u32 {
        // Constants from SourceClass, added here for compatibility reasons
        /// SourceClass::Button
        const SourceClassButton = SourceClass::Button as u32;
        /// SourceClass::Pointer
        const SourceClassPointer = SourceClass::Pointer as u32;
        /// SourceClass::Navigation
        const SourceClassNavigation = SourceClass::Navigation as u32;
        /// SourceClass::Position
        const SourceClassPosition = SourceClass::Position as u32;
        /// SourceClass::Joystick
        const SourceClassJoystick = SourceClass::Joystick as u32;

        /// SOURCE_UNKNOWN
        const Unknown = input_bindgen::AINPUT_SOURCE_UNKNOWN;
        /// SOURCE_KEYBOARD
        const Keyboard = input_bindgen::AINPUT_SOURCE_KEYBOARD;
        /// SOURCE_DPAD
        const Dpad = input_bindgen::AINPUT_SOURCE_DPAD;
        /// SOURCE_GAMEPAD
        const Gamepad = input_bindgen::AINPUT_SOURCE_GAMEPAD;
        /// SOURCE_TOUCHSCREEN
        const Touchscreen = input_bindgen::AINPUT_SOURCE_TOUCHSCREEN;
        /// SOURCE_MOUSE
        const Mouse = input_bindgen::AINPUT_SOURCE_MOUSE;
        /// SOURCE_STYLUS
        const Stylus = input_bindgen::AINPUT_SOURCE_STYLUS;
        /// SOURCE_BLUETOOTH_STYLUS
        const BluetoothStylus = input_bindgen::AINPUT_SOURCE_BLUETOOTH_STYLUS;
        /// SOURCE_TRACKBALL
        const Trackball = input_bindgen::AINPUT_SOURCE_TRACKBALL;
        /// SOURCE_MOUSE_RELATIVE
        const MouseRelative = input_bindgen::AINPUT_SOURCE_MOUSE_RELATIVE;
        /// SOURCE_TOUCHPAD
        const Touchpad = input_bindgen::AINPUT_SOURCE_TOUCHPAD;
        /// SOURCE_TOUCH_NAVIGATION
        const TouchNavigation = input_bindgen::AINPUT_SOURCE_TOUCH_NAVIGATION;
        /// SOURCE_JOYSTICK
        const Joystick = input_bindgen::AINPUT_SOURCE_JOYSTICK;
        /// SOURCE_HDMI
        const HDMI = input_bindgen::AINPUT_SOURCE_HDMI;
        /// SOURCE_SENSOR
        const Sensor = input_bindgen::AINPUT_SOURCE_SENSOR;
        /// SOURCE_ROTARY_ENCODER
        const RotaryEncoder = input_bindgen::AINPUT_SOURCE_ROTARY_ENCODER;
    }
}

/// A rust enum representation of a MotionEvent action.
#[repr(u32)]
pub enum MotionAction {
    /// ACTION_DOWN
    Down = input_bindgen::AMOTION_EVENT_ACTION_DOWN,
    /// ACTION_UP
    Up = input_bindgen::AMOTION_EVENT_ACTION_UP,
    /// ACTION_MOVE
    Move = input_bindgen::AMOTION_EVENT_ACTION_MOVE,
    /// ACTION_CANCEL
    Cancel = input_bindgen::AMOTION_EVENT_ACTION_CANCEL,
    /// ACTION_OUTSIDE
    Outside = input_bindgen::AMOTION_EVENT_ACTION_OUTSIDE,
    /// ACTION_POINTER_DOWN
    PointerDown {
        /// The index of the affected pointer.
        action_index: usize,
    } = input_bindgen::AMOTION_EVENT_ACTION_POINTER_DOWN,
    /// ACTION_POINTER_UP
    PointerUp {
        /// The index of the affected pointer.
        action_index: usize,
    } = input_bindgen::AMOTION_EVENT_ACTION_POINTER_UP,
    /// ACTION_HOVER_ENTER
    HoverEnter = input_bindgen::AMOTION_EVENT_ACTION_HOVER_ENTER,
    /// ACTION_HOVER_MOVE
    HoverMove = input_bindgen::AMOTION_EVENT_ACTION_HOVER_MOVE,
    /// ACTION_HOVER_EXIT
    HoverExit = input_bindgen::AMOTION_EVENT_ACTION_HOVER_EXIT,
    /// ACTION_SCROLL
    Scroll = input_bindgen::AMOTION_EVENT_ACTION_SCROLL,
    /// ACTION_BUTTON_PRESS
    ButtonPress = input_bindgen::AMOTION_EVENT_ACTION_BUTTON_PRESS,
    /// ACTION_BUTTON_RELEASE
    ButtonRelease = input_bindgen::AMOTION_EVENT_ACTION_BUTTON_RELEASE,
}

impl fmt::Display for MotionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MotionAction::Down => write!(f, "DOWN"),
            MotionAction::Up => write!(f, "UP"),
            MotionAction::Move => write!(f, "MOVE"),
            MotionAction::Cancel => write!(f, "CANCEL"),
            MotionAction::Outside => write!(f, "OUTSIDE"),
            MotionAction::PointerDown { action_index } => {
                write!(f, "POINTER_DOWN({})", action_index)
            }
            MotionAction::PointerUp { action_index } => write!(f, "POINTER_UP({})", action_index),
            MotionAction::HoverMove => write!(f, "HOVER_MOVE"),
            MotionAction::Scroll => write!(f, "SCROLL"),
            MotionAction::HoverEnter => write!(f, "HOVER_ENTER"),
            MotionAction::HoverExit => write!(f, "HOVER_EXIT"),
            MotionAction::ButtonPress => write!(f, "BUTTON_PRESS"),
            MotionAction::ButtonRelease => write!(f, "BUTTON_RELEASE"),
        }
    }
}

impl From<u32> for MotionAction {
    fn from(action: u32) -> Self {
        let (action_masked, action_index) = MotionAction::breakdown_action(action);
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

impl MotionAction {
    fn breakdown_action(action: u32) -> (u32, usize) {
        let action_masked = action & input_bindgen::AMOTION_EVENT_ACTION_MASK;
        let index = (action & input_bindgen::AMOTION_EVENT_ACTION_POINTER_INDEX_MASK)
            >> input_bindgen::AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
        (action_masked, index.try_into().unwrap())
    }
}

bitflags! {
    /// MotionEvent flags.
    #[derive(Debug)]
    pub struct MotionFlags: u32 {
        /// FLAG_CANCELED
        const CANCELED = input_bindgen::AMOTION_EVENT_FLAG_CANCELED as u32;
        /// FLAG_WINDOW_IS_OBSCURED
        const WINDOW_IS_OBSCURED = input_bindgen::AMOTION_EVENT_FLAG_WINDOW_IS_OBSCURED;
        /// FLAG_WINDOW_IS_PARTIALLY_OBSCURED
        const WINDOW_IS_PARTIALLY_OBSCURED =
                input_bindgen::AMOTION_EVENT_FLAG_WINDOW_IS_PARTIALLY_OBSCURED;
        /// FLAG_IS_ACCESSIBILITY_EVENT
        const IS_ACCESSIBILITY_EVENT =
                input_bindgen::AMOTION_EVENT_FLAG_IS_ACCESSIBILITY_EVENT;
        /// FLAG_NO_FOCUS_CHANGE
        const NO_FOCUS_CHANGE = input_bindgen::AMOTION_EVENT_FLAG_NO_FOCUS_CHANGE;
    }
}

impl Source {
    /// Return true if this source is from the provided class
    pub fn is_from_class(&self, source_class: SourceClass) -> bool {
        let class_bits = source_class as u32;
        self.bits() & class_bits == class_bits
    }
}

#[cfg(test)]
mod tests {
    use crate::input::SourceClass;
    use crate::Source;
    #[test]
    fn convert_source_class_pointer() {
        let source = Source::from_bits(input_bindgen::AINPUT_SOURCE_CLASS_POINTER).unwrap();
        assert!(source.is_from_class(SourceClass::Pointer));
    }
}
