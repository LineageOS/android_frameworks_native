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

//! InputFilter manages all the filtering components that can intercept events, modify the events,
//! block events, etc depending on the situation. This will be used support Accessibility features
//! like Slow keys, Bounce keys, etc.

use binder::{Interface, Strong};
use com_android_server_inputflinger::aidl::com::android::server::inputflinger::{
    IInputFilter::{IInputFilter, IInputFilterCallbacks::IInputFilterCallbacks},
    KeyEvent::KeyEvent,
};

/// The rust implementation of InputFilter
pub struct InputFilter {
    callbacks: Strong<dyn IInputFilterCallbacks>,
}

impl Interface for InputFilter {}

impl InputFilter {
    /// Create a new InputFilter instance.
    pub fn new(callbacks: Strong<dyn IInputFilterCallbacks>) -> InputFilter {
        Self { callbacks }
    }
}

impl IInputFilter for InputFilter {
    fn isEnabled(&self) -> binder::Result<bool> {
        // TODO(b/294546335): Return true if any filters are to be applied, false otherwise
        Result::Ok(false)
    }
    fn notifyKey(&self, event: &KeyEvent) -> binder::Result<()> {
        // TODO(b/294546335): Handle key event and modify key events here
        // Just send back the event without processing for now.
        let _ = self.callbacks.sendKeyEvent(event);
        Result::Ok(())
    }
    fn notifyInputDevicesChanged(&self, _device_ids: &[i32]) -> binder::Result<()> {
        // TODO(b/294546335): Update data based on device changes here
        Result::Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::input_filter::InputFilter;
    use binder::{Interface, Strong};
    use com_android_server_inputflinger::aidl::com::android::server::inputflinger::{
        IInputFilter::IInputFilter, IInputFilter::IInputFilterCallbacks::IInputFilterCallbacks,
        KeyEvent::KeyEvent,
    };

    struct FakeCallbacks {}

    impl Interface for FakeCallbacks {}

    impl IInputFilterCallbacks for FakeCallbacks {
        fn sendKeyEvent(&self, _event: &KeyEvent) -> binder::Result<()> {
            Result::Ok(())
        }
    }

    #[test]
    fn test_is_enabled() {
        let fake_callbacks: Strong<dyn IInputFilterCallbacks> =
            Strong::new(Box::new(FakeCallbacks {}));
        let filter: Box<dyn IInputFilter> = Box::new(InputFilter::new(fake_callbacks));
        let result = filter.isEnabled();
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_notify_key() {
        let fake_callbacks: Strong<dyn IInputFilterCallbacks> =
            Strong::new(Box::new(FakeCallbacks {}));
        let filter: Box<dyn IInputFilter> = Box::new(InputFilter::new(fake_callbacks));
        let event = create_key_event();
        assert!(filter.notifyKey(&event).is_ok());
    }

    #[test]
    fn test_notify_devices_changed() {
        let fake_callbacks: Strong<dyn IInputFilterCallbacks> =
            Strong::new(Box::new(FakeCallbacks {}));
        let filter: Box<dyn IInputFilter> = Box::new(InputFilter::new(fake_callbacks));
        let result = filter.notifyInputDevicesChanged(&[0]);
        assert!(result.is_ok());
    }

    fn create_key_event() -> KeyEvent {
        KeyEvent {
            id: 1,
            deviceId: 1,
            downTime: 0,
            readTime: 0,
            eventTime: 0,
            source: 0,
            displayId: 0,
            policyFlags: 0,
            action: 0,
            flags: 0,
            keyCode: 0,
            scanCode: 0,
            metaState: 0,
        }
    }
}
