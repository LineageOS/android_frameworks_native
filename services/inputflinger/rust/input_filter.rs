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
    IInputThread::{IInputThread, IInputThreadCallback::IInputThreadCallback},
    InputFilterConfiguration::InputFilterConfiguration,
    KeyEvent::KeyEvent,
};

use crate::bounce_keys_filter::BounceKeysFilter;
use crate::input_filter_thread::InputFilterThread;
use crate::slow_keys_filter::SlowKeysFilter;
use crate::sticky_keys_filter::StickyKeysFilter;
use log::{error, info};
use std::sync::{Arc, Mutex, RwLock};

/// Interface for all the sub input filters
pub trait Filter {
    fn notify_key(&mut self, event: &KeyEvent);
    fn notify_devices_changed(&mut self, device_infos: &[DeviceInfo]);
    fn destroy(&mut self);
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
    input_filter_thread: InputFilterThread,
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
        Self {
            callbacks: callbacks.clone(),
            state: Mutex::new(InputFilterState { first_filter, enabled: false }),
            input_filter_thread: InputFilterThread::new(InputFilterThreadCreator::new(callbacks)),
        }
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
        {
            let mut state = self.state.lock().unwrap();
            state.first_filter.destroy();
            let mut first_filter: Box<dyn Filter + Send + Sync> =
                Box::new(BaseFilter::new(self.callbacks.clone()));
            if config.stickyKeysEnabled {
                first_filter = Box::new(StickyKeysFilter::new(
                    first_filter,
                    ModifierStateListener::new(self.callbacks.clone()),
                ));
                state.enabled = true;
                info!("Sticky keys filter is installed");
            }
            if config.slowKeysThresholdNs > 0 {
                first_filter = Box::new(SlowKeysFilter::new(
                    first_filter,
                    config.slowKeysThresholdNs,
                    self.input_filter_thread.clone(),
                ));
                state.enabled = true;
                info!("Slow keys filter is installed");
            }
            if config.bounceKeysThresholdNs > 0 {
                first_filter =
                    Box::new(BounceKeysFilter::new(first_filter, config.bounceKeysThresholdNs));
                state.enabled = true;
                info!("Bounce keys filter is installed");
            }
            state.first_filter = first_filter;
        }
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

    fn destroy(&mut self) {
        // do nothing
    }
}

/// This struct wraps around IInputFilterCallbacks restricting access to only
/// {@code onModifierStateChanged()} method of the callback.
#[derive(Clone)]
pub struct ModifierStateListener(Arc<RwLock<Strong<dyn IInputFilterCallbacks>>>);

impl ModifierStateListener {
    pub fn new(callbacks: Arc<RwLock<Strong<dyn IInputFilterCallbacks>>>) -> ModifierStateListener {
        Self(callbacks)
    }

    pub fn modifier_state_changed(&self, modifier_state: u32, locked_modifier_state: u32) {
        let _ = self
            .0
            .read()
            .unwrap()
            .onModifierStateChanged(modifier_state as i32, locked_modifier_state as i32);
    }
}

/// This struct wraps around IInputFilterCallbacks restricting access to only
/// {@code createInputFilterThread()} method of the callback.
#[derive(Clone)]
pub struct InputFilterThreadCreator(Arc<RwLock<Strong<dyn IInputFilterCallbacks>>>);

impl InputFilterThreadCreator {
    pub fn new(
        callbacks: Arc<RwLock<Strong<dyn IInputFilterCallbacks>>>,
    ) -> InputFilterThreadCreator {
        Self(callbacks)
    }

    pub fn create(
        &self,
        input_thread_callback: &Strong<dyn IInputThreadCallback>,
    ) -> Strong<dyn IInputThread> {
        self.0.read().unwrap().createInputFilterThread(input_thread_callback).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::input_filter::{
        test_callbacks::TestCallbacks, test_filter::TestFilter, InputFilter,
    };
    use android_hardware_input_common::aidl::android::hardware::input::common::Source::Source;
    use binder::Strong;
    use com_android_server_inputflinger::aidl::com::android::server::inputflinger::{
        DeviceInfo::DeviceInfo, IInputFilter::IInputFilter,
        InputFilterConfiguration::InputFilterConfiguration, KeyEvent::KeyEvent,
        KeyEventAction::KeyEventAction,
    };
    use std::sync::{Arc, RwLock};

    #[test]
    fn test_not_enabled_with_default_filter() {
        let test_callbacks = TestCallbacks::new();
        let input_filter = InputFilter::new(Strong::new(Box::new(test_callbacks)));
        let result = input_filter.isEnabled();
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_notify_key_with_no_filters() {
        let test_callbacks = TestCallbacks::new();
        let input_filter = InputFilter::new(Strong::new(Box::new(test_callbacks.clone())));
        let event = create_key_event();
        assert!(input_filter.notifyKey(&event).is_ok());
        assert_eq!(test_callbacks.last_event().unwrap(), event);
    }

    #[test]
    fn test_notify_key_with_filter() {
        let test_filter = TestFilter::new();
        let test_callbacks = TestCallbacks::new();
        let input_filter = InputFilter::create_input_filter(
            Box::new(test_filter.clone()),
            Arc::new(RwLock::new(Strong::new(Box::new(test_callbacks)))),
        );
        let event = create_key_event();
        assert!(input_filter.notifyKey(&event).is_ok());
        assert_eq!(test_filter.last_event().unwrap(), event);
    }

    #[test]
    fn test_notify_devices_changed() {
        let test_filter = TestFilter::new();
        let test_callbacks = TestCallbacks::new();
        let input_filter = InputFilter::create_input_filter(
            Box::new(test_filter.clone()),
            Arc::new(RwLock::new(Strong::new(Box::new(test_callbacks)))),
        );
        assert!(input_filter
            .notifyInputDevicesChanged(&[DeviceInfo { deviceId: 0, external: true }])
            .is_ok());
        assert!(test_filter.is_device_changed_called());
    }

    #[test]
    fn test_notify_configuration_changed_enabled_bounce_keys() {
        let test_callbacks = TestCallbacks::new();
        let input_filter = InputFilter::new(Strong::new(Box::new(test_callbacks)));
        let result = input_filter.notifyConfigurationChanged(&InputFilterConfiguration {
            bounceKeysThresholdNs: 100,
            ..Default::default()
        });
        assert!(result.is_ok());
        let result = input_filter.isEnabled();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_notify_configuration_changed_enabled_sticky_keys() {
        let test_callbacks = TestCallbacks::new();
        let input_filter = InputFilter::new(Strong::new(Box::new(test_callbacks)));
        let result = input_filter.notifyConfigurationChanged(&InputFilterConfiguration {
            stickyKeysEnabled: true,
            ..Default::default()
        });
        assert!(result.is_ok());
        let result = input_filter.isEnabled();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_notify_configuration_changed_enabled_slow_keys() {
        let test_callbacks = TestCallbacks::new();
        let input_filter = InputFilter::new(Strong::new(Box::new(test_callbacks)));
        let result = input_filter.notifyConfigurationChanged(&InputFilterConfiguration {
            slowKeysThresholdNs: 100,
            ..Default::default()
        });
        assert!(result.is_ok());
        let result = input_filter.isEnabled();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_notify_configuration_changed_destroys_existing_filters() {
        let test_filter = TestFilter::new();
        let test_callbacks = TestCallbacks::new();
        let input_filter = InputFilter::create_input_filter(
            Box::new(test_filter.clone()),
            Arc::new(RwLock::new(Strong::new(Box::new(test_callbacks)))),
        );
        let _ = input_filter
            .notifyConfigurationChanged(&InputFilterConfiguration { ..Default::default() });
        assert!(test_filter.is_destroy_called());
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
        is_destroy_called: bool,
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

        pub fn is_destroy_called(&self) -> bool {
            self.0.read().unwrap().is_destroy_called
        }
    }

    impl Filter for TestFilter {
        fn notify_key(&mut self, event: &KeyEvent) {
            self.inner().last_event = Some(*event);
        }
        fn notify_devices_changed(&mut self, _device_infos: &[DeviceInfo]) {
            self.inner().is_device_changed_called = true;
        }
        fn destroy(&mut self) {
            self.inner().is_destroy_called = true;
        }
    }
}

#[cfg(test)]
pub mod test_callbacks {
    use binder::{BinderFeatures, Interface, Strong};
    use com_android_server_inputflinger::aidl::com::android::server::inputflinger::{
        IInputFilter::IInputFilterCallbacks::IInputFilterCallbacks,
        IInputThread::{BnInputThread, IInputThread, IInputThreadCallback::IInputThreadCallback},
        KeyEvent::KeyEvent,
    };
    use std::sync::{Arc, RwLock, RwLockWriteGuard};

    #[derive(Default)]
    struct TestCallbacksInner {
        last_modifier_state: u32,
        last_locked_modifier_state: u32,
        last_event: Option<KeyEvent>,
        test_thread: Option<TestThread>,
    }

    #[derive(Default, Clone)]
    pub struct TestCallbacks(Arc<RwLock<TestCallbacksInner>>);

    impl Interface for TestCallbacks {}

    impl TestCallbacks {
        pub fn new() -> Self {
            Default::default()
        }

        fn inner(&self) -> RwLockWriteGuard<'_, TestCallbacksInner> {
            self.0.write().unwrap()
        }

        pub fn last_event(&self) -> Option<KeyEvent> {
            self.0.read().unwrap().last_event
        }

        pub fn clear(&mut self) {
            self.inner().last_event = None;
            self.inner().last_modifier_state = 0;
            self.inner().last_locked_modifier_state = 0;
        }

        pub fn get_last_modifier_state(&self) -> u32 {
            self.0.read().unwrap().last_modifier_state
        }

        pub fn get_last_locked_modifier_state(&self) -> u32 {
            self.0.read().unwrap().last_locked_modifier_state
        }

        pub fn is_thread_created(&self) -> bool {
            self.0.read().unwrap().test_thread.is_some()
        }

        pub fn is_thread_finished(&self) -> bool {
            if let Some(test_thread) = &self.0.read().unwrap().test_thread {
                return test_thread.is_finish_called();
            }
            false
        }
    }

    impl IInputFilterCallbacks for TestCallbacks {
        fn sendKeyEvent(&self, event: &KeyEvent) -> binder::Result<()> {
            self.inner().last_event = Some(*event);
            Result::Ok(())
        }

        fn onModifierStateChanged(
            &self,
            modifier_state: i32,
            locked_modifier_state: i32,
        ) -> std::result::Result<(), binder::Status> {
            self.inner().last_modifier_state = modifier_state as u32;
            self.inner().last_locked_modifier_state = locked_modifier_state as u32;
            Result::Ok(())
        }

        fn createInputFilterThread(
            &self,
            _callback: &Strong<dyn IInputThreadCallback>,
        ) -> std::result::Result<Strong<dyn IInputThread>, binder::Status> {
            let test_thread = TestThread::new();
            self.inner().test_thread = Some(test_thread.clone());
            Result::Ok(BnInputThread::new_binder(test_thread, BinderFeatures::default()))
        }
    }

    #[derive(Default)]
    struct TestThreadInner {
        is_finish_called: bool,
    }

    #[derive(Default, Clone)]
    struct TestThread(Arc<RwLock<TestThreadInner>>);

    impl Interface for TestThread {}

    impl TestThread {
        pub fn new() -> Self {
            Default::default()
        }

        fn inner(&self) -> RwLockWriteGuard<'_, TestThreadInner> {
            self.0.write().unwrap()
        }

        pub fn is_finish_called(&self) -> bool {
            self.0.read().unwrap().is_finish_called
        }
    }

    impl IInputThread for TestThread {
        fn finish(&self) -> binder::Result<()> {
            self.inner().is_finish_called = true;
            Result::Ok(())
        }
    }
}
