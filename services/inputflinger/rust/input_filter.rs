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
//! like Sticky keys, Slow keys, Bounce keys, etc.

use binder::{Interface, Strong};
use com_android_server_inputflinger::aidl::com::android::server::inputflinger::{
    DeviceInfo::DeviceInfo,
    IInputFilter::{IInputFilter, IInputFilterCallbacks::IInputFilterCallbacks},
    InputFilterConfiguration::InputFilterConfiguration,
    KeyEvent::KeyEvent,
};

use crate::bounce_keys_filter::BounceKeysFilter;
use log::{error, info};
use std::sync::{Arc, Mutex, RwLock};

/// Interface for all the sub input filters
pub trait Filter {
    fn notify_key(&mut self, event: &KeyEvent);
    fn notify_devices_changed(&mut self, device_infos: &[DeviceInfo]);
}

struct InputFilterState {
    first_filter: Box<dyn Filter + Send + Sync>,
    enabled: bool,
}

/// The rust implementation of InputFilter
pub struct InputFilter {
    // In order to have multiple immutable references to the callbacks that is thread safe need to
    // wrap the callbacks in Arc<RwLock<...>>
    callbacks: Arc<RwLock<Strong<dyn IInputFilterCallbacks>>>,
    // Access to mutable references to mutable state (includes access to filters, enabled, etc.) is
    // guarded by Mutex for thread safety
    state: Mutex<InputFilterState>,
}

impl Interface for InputFilter {}

impl InputFilter {
    /// Create a new InputFilter instance.
    pub fn new(callbacks: Strong<dyn IInputFilterCallbacks>) -> InputFilter {
        let ref_callbacks = Arc::new(RwLock::new(callbacks));
        let base_filter = Box::new(BaseFilter::new(ref_callbacks.clone()));
        Self::create_input_filter(base_filter, ref_callbacks)
    }

    /// Create test instance of InputFilter
    fn create_input_filter(
        first_filter: Box<dyn Filter + Send + Sync>,
        callbacks: Arc<RwLock<Strong<dyn IInputFilterCallbacks>>>,
    ) -> InputFilter {
        Self { callbacks, state: Mutex::new(InputFilterState { first_filter, enabled: false }) }
    }
}

impl IInputFilter for InputFilter {
    fn isEnabled(&self) -> binder::Result<bool> {
        Result::Ok(self.state.lock().unwrap().enabled)
    }

    fn notifyKey(&self, event: &KeyEvent) -> binder::Result<()> {
        let first_filter = &mut self.state.lock().unwrap().first_filter;
        first_filter.notify_key(event);
        Result::Ok(())
    }

    fn notifyInputDevicesChanged(&self, device_infos: &[DeviceInfo]) -> binder::Result<()> {
        let first_filter = &mut self.state.lock().unwrap().first_filter;
        first_filter.notify_devices_changed(device_infos);
        Result::Ok(())
    }

    fn notifyConfigurationChanged(&self, config: &InputFilterConfiguration) -> binder::Result<()> {
        let mut state = self.state.lock().unwrap();
        let mut first_filter: Box<dyn Filter + Send + Sync> =
            Box::new(BaseFilter::new(self.callbacks.clone()));
        if config.bounceKeysThresholdNs > 0 {
            first_filter =
                Box::new(BounceKeysFilter::new(first_filter, config.bounceKeysThresholdNs));
            state.enabled = true;
            info!("Bounce keys filter is installed");
        }
        state.first_filter = first_filter;
        Result::Ok(())
    }
}

struct BaseFilter {
    callbacks: Arc<RwLock<Strong<dyn IInputFilterCallbacks>>>,
}

impl BaseFilter {
    fn new(callbacks: Arc<RwLock<Strong<dyn IInputFilterCallbacks>>>) -> BaseFilter {
        Self { callbacks }
    }
}

impl Filter for BaseFilter {
    fn notify_key(&mut self, event: &KeyEvent) {
        match self.callbacks.read().unwrap().sendKeyEvent(event) {
            Ok(_) => (),
            _ => error!("Failed to send key event back to native C++"),
        }
    }

    fn notify_devices_changed(&mut self, _device_infos: &[DeviceInfo]) {
        // do nothing
    }
}

#[cfg(test)]
mod tests {
    use crate::input_filter::{test_filter::TestFilter, Filter, InputFilter};
    use android_hardware_input_common::aidl::android::hardware::input::common::Source::Source;
    use binder::{Interface, Strong};
    use com_android_server_inputflinger::aidl::com::android::server::inputflinger::{
        DeviceInfo::DeviceInfo, IInputFilter::IInputFilter,
        IInputFilter::IInputFilterCallbacks::IInputFilterCallbacks,
        InputFilterConfiguration::InputFilterConfiguration, KeyEvent::KeyEvent,
        KeyEventAction::KeyEventAction,
    };
    use std::sync::{Arc, RwLock};

    struct FakeCallbacks {}

    impl Interface for FakeCallbacks {}

    impl IInputFilterCallbacks for FakeCallbacks {
        fn sendKeyEvent(&self, _event: &KeyEvent) -> binder::Result<()> {
            Result::Ok(())
        }
    }

    #[test]
    fn test_not_enabled_with_default_filter() {
        let fake_callbacks: Strong<dyn IInputFilterCallbacks> =
            Strong::new(Box::new(FakeCallbacks {}));
        let input_filter = InputFilter::new(fake_callbacks);
        let result = input_filter.isEnabled();
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_notify_key_with_no_filters() {
        let fake_callbacks: Strong<dyn IInputFilterCallbacks> =
            Strong::new(Box::new(FakeCallbacks {}));
        let input_filter = InputFilter::new(fake_callbacks);
        let event = create_key_event();
        assert!(input_filter.notifyKey(&event).is_ok());
    }

    #[test]
    fn test_notify_key_with_filter() {
        let test_filter = TestFilter::new();
        let input_filter = create_input_filter(Box::new(test_filter.clone()));
        let event = create_key_event();
        assert!(input_filter.notifyKey(&event).is_ok());
        assert_eq!(test_filter.last_event().unwrap(), event);
    }

    #[test]
    fn test_notify_devices_changed() {
        let test_filter = TestFilter::new();
        let input_filter = create_input_filter(Box::new(test_filter.clone()));
        assert!(input_filter
            .notifyInputDevicesChanged(&[DeviceInfo { deviceId: 0, external: true }])
            .is_ok());
        assert!(test_filter.is_device_changed_called());
    }

    #[test]
    fn test_notify_configuration_changed_enabled_bounce_keys() {
        let fake_callbacks: Strong<dyn IInputFilterCallbacks> =
            Strong::new(Box::new(FakeCallbacks {}));
        let input_filter = InputFilter::new(fake_callbacks);
        let result = input_filter
            .notifyConfigurationChanged(&InputFilterConfiguration { bounceKeysThresholdNs: 100 });
        assert!(result.is_ok());
        let result = input_filter.isEnabled();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    fn create_input_filter(filter: Box<dyn Filter + Send + Sync>) -> InputFilter {
        let fake_callbacks: Strong<dyn IInputFilterCallbacks> =
            Strong::new(Box::new(FakeCallbacks {}));
        InputFilter::create_input_filter(filter, Arc::new(RwLock::new(fake_callbacks)))
    }

    fn create_key_event() -> KeyEvent {
        KeyEvent {
            id: 1,
            deviceId: 1,
            downTime: 0,
            readTime: 0,
            eventTime: 0,
            source: Source::KEYBOARD,
            displayId: 0,
            policyFlags: 0,
            action: KeyEventAction::DOWN,
            flags: 0,
            keyCode: 0,
            scanCode: 0,
            metaState: 0,
        }
    }
}

#[cfg(test)]
pub mod test_filter {
    use crate::input_filter::Filter;
    use com_android_server_inputflinger::aidl::com::android::server::inputflinger::{
        DeviceInfo::DeviceInfo, KeyEvent::KeyEvent,
    };
    use std::sync::{Arc, RwLock, RwLockWriteGuard};

    #[derive(Default)]
    struct TestFilterInner {
        is_device_changed_called: bool,
        last_event: Option<KeyEvent>,
    }

    #[derive(Default, Clone)]
    pub struct TestFilter(Arc<RwLock<TestFilterInner>>);

    impl TestFilter {
        pub fn new() -> Self {
            Default::default()
        }

        fn inner(&mut self) -> RwLockWriteGuard<'_, TestFilterInner> {
            self.0.write().unwrap()
        }

        pub fn last_event(&self) -> Option<KeyEvent> {
            self.0.read().unwrap().last_event
        }

        pub fn clear(&mut self) {
            self.inner().last_event = None
        }

        pub fn is_device_changed_called(&self) -> bool {
            self.0.read().unwrap().is_device_changed_called
        }
    }

    impl Filter for TestFilter {
        fn notify_key(&mut self, event: &KeyEvent) {
            self.inner().last_event = Some(*event);
        }
        fn notify_devices_changed(&mut self, _device_infos: &[DeviceInfo]) {
            self.inner().is_device_changed_called = true;
        }
    }
}
