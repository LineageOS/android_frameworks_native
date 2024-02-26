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

//! Slow keys input filter implementation.
//! Slow keys is an accessibility feature to aid users who have physical disabilities, that allows
//! the user to specify the duration for which one must press-and-hold a key before the system
//! accepts the keypress.
use crate::input_filter::Filter;
use crate::input_filter_thread::{InputFilterThread, ThreadCallback};
use android_hardware_input_common::aidl::android::hardware::input::common::Source::Source;
use com_android_server_inputflinger::aidl::com::android::server::inputflinger::{
    DeviceInfo::DeviceInfo, KeyEvent::KeyEvent, KeyEventAction::KeyEventAction,
};
use log::debug;
use std::collections::HashSet;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

// Policy flags from Input.h
const POLICY_FLAG_DISABLE_KEY_REPEAT: i32 = 0x08000000;

#[derive(Debug)]
struct OngoingKeyDown {
    scancode: i32,
    device_id: i32,
    down_time: i64,
}

struct SlowKeysFilterInner {
    next: Box<dyn Filter + Send + Sync>,
    slow_key_threshold_ns: i64,
    external_devices: HashSet<i32>,
    // This tracks KeyEvents that are blocked by Slow keys filter and will be passed through if the
    // press duration exceeds the slow keys threshold.
    pending_down_events: Vec<KeyEvent>,
    // This tracks KeyEvent streams that have press duration greater than the slow keys threshold,
    // hence any future ACTION_DOWN (if repeats are handled on HW side) or ACTION_UP are allowed to
    // pass through without waiting.
    ongoing_down_events: Vec<OngoingKeyDown>,
    input_filter_thread: InputFilterThread,
}

#[derive(Clone)]
pub struct SlowKeysFilter(Arc<RwLock<SlowKeysFilterInner>>);

impl SlowKeysFilter {
    /// Create a new SlowKeysFilter instance.
    pub fn new(
        next: Box<dyn Filter + Send + Sync>,
        slow_key_threshold_ns: i64,
        input_filter_thread: InputFilterThread,
    ) -> SlowKeysFilter {
        let filter = Self(Arc::new(RwLock::new(SlowKeysFilterInner {
            next,
            slow_key_threshold_ns,
            external_devices: HashSet::new(),
            pending_down_events: Vec::new(),
            ongoing_down_events: Vec::new(),
            input_filter_thread: input_filter_thread.clone(),
        })));
        input_filter_thread.register_thread_callback(Box::new(filter.clone()));
        filter
    }

    fn read_inner(&self) -> RwLockReadGuard<'_, SlowKeysFilterInner> {
        self.0.read().unwrap()
    }

    fn write_inner(&self) -> RwLockWriteGuard<'_, SlowKeysFilterInner> {
        self.0.write().unwrap()
    }

    fn request_next_callback(&self) {
        let slow_filter = &self.read_inner();
        if slow_filter.pending_down_events.is_empty() {
            return;
        }
        if let Some(event) = slow_filter.pending_down_events.iter().min_by_key(|x| x.downTime) {
            slow_filter.input_filter_thread.request_timeout_at_time(event.downTime);
        }
    }
}

impl Filter for SlowKeysFilter {
    fn notify_key(&mut self, event: &KeyEvent) {
        {
            // acquire write lock
            let mut slow_filter = self.write_inner();
            if !(slow_filter.external_devices.contains(&event.deviceId)
                && event.source == Source::KEYBOARD)
            {
                slow_filter.next.notify_key(event);
                return;
            }
            // Pass all events through if key down has already been processed
            // Do update the downtime before sending the events through
            if let Some(index) = slow_filter
                .ongoing_down_events
                .iter()
                .position(|x| x.device_id == event.deviceId && x.scancode == event.scanCode)
            {
                let mut new_event = *event;
                new_event.downTime = slow_filter.ongoing_down_events[index].down_time;
                slow_filter.next.notify_key(&new_event);
                if event.action == KeyEventAction::UP {
                    slow_filter.ongoing_down_events.remove(index);
                }
                return;
            }
            match event.action {
                KeyEventAction::DOWN => {
                    if slow_filter
                        .pending_down_events
                        .iter()
                        .any(|x| x.deviceId == event.deviceId && x.scanCode == event.scanCode)
                    {
                        debug!("Dropping key down event since another pending down event exists");
                        return;
                    }
                    let mut pending_event = *event;
                    pending_event.downTime += slow_filter.slow_key_threshold_ns;
                    pending_event.eventTime = pending_event.downTime;
                    // Currently a slow keys user ends up repeating the presses key quite often
                    // since default repeat thresholds are very low, so blocking repeat for events
                    // when slow keys is enabled.
                    // TODO(b/322327461): Allow key repeat with slow keys, once repeat key rate and
                    //  thresholds can be modified in the settings.
                    pending_event.policyFlags |= POLICY_FLAG_DISABLE_KEY_REPEAT;
                    slow_filter.pending_down_events.push(pending_event);
                }
                KeyEventAction::UP => {
                    debug!("Dropping key up event due to insufficient press duration");
                    if let Some(index) = slow_filter
                        .pending_down_events
                        .iter()
                        .position(|x| x.deviceId == event.deviceId && x.scanCode == event.scanCode)
                    {
                        slow_filter.pending_down_events.remove(index);
                    }
                }
                _ => (),
            }
        } // release write lock
        self.request_next_callback();
    }

    fn notify_devices_changed(&mut self, device_infos: &[DeviceInfo]) {
        let mut slow_filter = self.write_inner();
        slow_filter
            .pending_down_events
            .retain(|event| device_infos.iter().any(|x| event.deviceId == x.deviceId));
        slow_filter
            .ongoing_down_events
            .retain(|event| device_infos.iter().any(|x| event.device_id == x.deviceId));
        slow_filter.external_devices.clear();
        for device_info in device_infos {
            if device_info.external {
                slow_filter.external_devices.insert(device_info.deviceId);
            }
        }
        slow_filter.next.notify_devices_changed(device_infos);
    }

    fn destroy(&mut self) {
        let mut slow_filter = self.write_inner();
        slow_filter.input_filter_thread.unregister_thread_callback(Box::new(self.clone()));
        slow_filter.next.destroy();
    }
}

impl ThreadCallback for SlowKeysFilter {
    fn notify_timeout_expired(&self, when_nanos: i64) {
        {
            // acquire write lock
            let slow_filter = &mut self.write_inner();
            for event in slow_filter.pending_down_events.clone() {
                if event.downTime <= when_nanos {
                    slow_filter.next.notify_key(&event);
                    slow_filter.ongoing_down_events.push(OngoingKeyDown {
                        scancode: event.scanCode,
                        device_id: event.deviceId,
                        down_time: event.downTime,
                    });
                }
            }
            slow_filter.pending_down_events.retain(|event| event.downTime > when_nanos);
        } // release write lock
        self.request_next_callback();
    }

    fn name(&self) -> &str {
        "slow_keys_filter"
    }
}

#[cfg(test)]
mod tests {
    use crate::input_filter::{test_callbacks::TestCallbacks, test_filter::TestFilter, Filter};
    use crate::input_filter_thread::test_thread::TestThread;
    use crate::slow_keys_filter::{SlowKeysFilter, POLICY_FLAG_DISABLE_KEY_REPEAT};
    use android_hardware_input_common::aidl::android::hardware::input::common::Source::Source;
    use com_android_server_inputflinger::aidl::com::android::server::inputflinger::{
        DeviceInfo::DeviceInfo, KeyEvent::KeyEvent, KeyEventAction::KeyEventAction,
    };

    static BASE_KEY_EVENT: KeyEvent = KeyEvent {
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
        keyCode: 1,
        scanCode: 0,
        metaState: 0,
    };

    #[test]
    fn test_is_notify_key_for_internal_keyboard_not_blocked() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = TestThread::new(test_callbacks.clone());
        let next = TestFilter::new();
        let mut filter = setup_filter_with_internal_device(
            Box::new(next.clone()),
            test_thread.clone(),
            1,   /* device_id */
            100, /* threshold */
        );
        test_thread.start_looper();

        let event = KeyEvent { action: KeyEventAction::DOWN, ..BASE_KEY_EVENT };
        filter.notify_key(&event);
        assert_eq!(next.last_event().unwrap(), event);
    }

    #[test]
    fn test_is_notify_key_for_external_stylus_not_blocked() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = TestThread::new(test_callbacks.clone());
        let next = TestFilter::new();
        let mut filter = setup_filter_with_external_device(
            Box::new(next.clone()),
            test_thread.clone(),
            1,   /* device_id */
            100, /* threshold */
        );
        test_thread.start_looper();

        let event =
            KeyEvent { action: KeyEventAction::DOWN, source: Source::STYLUS, ..BASE_KEY_EVENT };
        filter.notify_key(&event);
        assert_eq!(next.last_event().unwrap(), event);
    }

    #[test]
    fn test_notify_key_for_external_keyboard_when_key_pressed_for_threshold_time() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = TestThread::new(test_callbacks.clone());
        let next = TestFilter::new();
        let mut filter = setup_filter_with_external_device(
            Box::new(next.clone()),
            test_thread.clone(),
            1,   /* device_id */
            100, /* threshold */
        );
        test_thread.start_looper();

        filter.notify_key(&KeyEvent { action: KeyEventAction::DOWN, ..BASE_KEY_EVENT });
        assert!(next.last_event().is_none());
        test_thread.dispatch_next();

        test_thread.move_time_forward(100);

        test_thread.stop_looper();
        assert_eq!(
            next.last_event().unwrap(),
            KeyEvent {
                action: KeyEventAction::DOWN,
                downTime: 100,
                eventTime: 100,
                policyFlags: POLICY_FLAG_DISABLE_KEY_REPEAT,
                ..BASE_KEY_EVENT
            }
        );
    }

    #[test]
    fn test_notify_key_for_external_keyboard_when_key_not_pressed_for_threshold_time() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = TestThread::new(test_callbacks.clone());
        let next = TestFilter::new();
        let mut filter = setup_filter_with_external_device(
            Box::new(next.clone()),
            test_thread.clone(),
            1,   /* device_id */
            100, /* threshold */
        );
        test_thread.start_looper();

        filter.notify_key(&KeyEvent { action: KeyEventAction::DOWN, ..BASE_KEY_EVENT });
        test_thread.dispatch_next();

        test_thread.move_time_forward(10);

        filter.notify_key(&KeyEvent { action: KeyEventAction::UP, ..BASE_KEY_EVENT });
        test_thread.dispatch_next();

        test_thread.stop_looper();
        assert!(next.last_event().is_none());
    }

    #[test]
    fn test_notify_key_for_external_keyboard_when_device_removed_before_threshold_time() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = TestThread::new(test_callbacks.clone());
        let next = TestFilter::new();
        let mut filter = setup_filter_with_external_device(
            Box::new(next.clone()),
            test_thread.clone(),
            1,   /* device_id */
            100, /* threshold */
        );
        test_thread.start_looper();

        filter.notify_key(&KeyEvent { action: KeyEventAction::DOWN, ..BASE_KEY_EVENT });
        assert!(next.last_event().is_none());
        test_thread.dispatch_next();

        filter.notify_devices_changed(&[]);
        test_thread.dispatch_next();

        test_thread.move_time_forward(100);

        test_thread.stop_looper();
        assert!(next.last_event().is_none());
    }

    fn setup_filter_with_external_device(
        next: Box<dyn Filter + Send + Sync>,
        test_thread: TestThread,
        device_id: i32,
        threshold: i64,
    ) -> SlowKeysFilter {
        setup_filter_with_devices(
            next,
            test_thread,
            &[DeviceInfo { deviceId: device_id, external: true }],
            threshold,
        )
    }

    fn setup_filter_with_internal_device(
        next: Box<dyn Filter + Send + Sync>,
        test_thread: TestThread,
        device_id: i32,
        threshold: i64,
    ) -> SlowKeysFilter {
        setup_filter_with_devices(
            next,
            test_thread,
            &[DeviceInfo { deviceId: device_id, external: false }],
            threshold,
        )
    }

    fn setup_filter_with_devices(
        next: Box<dyn Filter + Send + Sync>,
        test_thread: TestThread,
        devices: &[DeviceInfo],
        threshold: i64,
    ) -> SlowKeysFilter {
        let mut filter = SlowKeysFilter::new(next, threshold, test_thread.get_input_thread());
        filter.notify_devices_changed(devices);
        filter
    }
}
