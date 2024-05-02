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

//! Input filter thread implementation in rust.
//! Using IInputFilter.aidl interface to create ever looping thread with JNI support, rest of
//! thread handling is done from rust side.
//!
//! NOTE: Tried using rust provided threading infrastructure but that uses std::thread which doesn't
//! have JNI support and can't call into Java policy that we use currently. libutils provided
//! Thread.h also recommends against using std::thread and using the provided infrastructure that
//! already provides way of attaching JniEnv to the created thread. So, we are using an AIDL
//! interface to expose the InputThread infrastructure to rust.

use crate::input_filter::InputFilterThreadCreator;
use binder::{BinderFeatures, Interface, Strong};
use com_android_server_inputflinger::aidl::com::android::server::inputflinger::IInputThread::{
    IInputThread, IInputThreadCallback::BnInputThreadCallback,
    IInputThreadCallback::IInputThreadCallback,
};
use log::{debug, error};
use nix::{sys::time::TimeValLike, time::clock_gettime, time::ClockId};
use std::sync::{Arc, RwLock, RwLockWriteGuard};

/// Interface to receive callback from Input filter thread
pub trait ThreadCallback {
    /// Calls back after the requested timeout expires.
    /// {@see InputFilterThread.request_timeout_at_time(...)}
    ///
    /// NOTE: In case of multiple requests, the timeout request which is earliest in time, will be
    /// fulfilled and notified to all the listeners. It's up to the listeners to re-request another
    /// timeout in the future.
    fn notify_timeout_expired(&self, when_nanos: i64);
    /// Unique name for the listener, which will be used to uniquely identify the listener.
    fn name(&self) -> &str;
}

#[derive(Clone)]
pub struct InputFilterThread {
    thread_creator: InputFilterThreadCreator,
    thread_callback_handler: ThreadCallbackHandler,
    inner: Arc<RwLock<InputFilterThreadInner>>,
    looper: Arc<RwLock<Looper>>,
}

struct InputFilterThreadInner {
    next_timeout: i64,
    is_finishing: bool,
}

struct Looper {
    cpp_thread: Option<Strong<dyn IInputThread>>,
}

impl InputFilterThread {
    /// Create a new InputFilterThread instance.
    /// NOTE: This will create a new thread. Clone the existing instance to reuse the same thread.
    pub fn new(thread_creator: InputFilterThreadCreator) -> InputFilterThread {
        Self {
            thread_creator,
            thread_callback_handler: ThreadCallbackHandler::new(),
            inner: Arc::new(RwLock::new(InputFilterThreadInner {
                next_timeout: i64::MAX,
                is_finishing: false,
            })),
            looper: Arc::new(RwLock::new(Looper { cpp_thread: None })),
        }
    }

    /// Listener requesting a timeout in future will receive a callback at or before the requested
    /// time on the input filter thread.
    /// {@see ThreadCallback.notify_timeout_expired(...)}
    pub fn request_timeout_at_time(&self, when_nanos: i64) {
        let mut need_wake = false;
        {
            // acquire filter lock
            let filter_thread = &mut self.filter_thread();
            if when_nanos < filter_thread.next_timeout {
                filter_thread.next_timeout = when_nanos;
                need_wake = true;
            }
        } // release filter lock
        if need_wake {
            self.wake();
        }
    }

    /// Registers a callback listener.
    ///
    /// NOTE: If a listener with the same name already exists when registering using
    /// {@see InputFilterThread.register_thread_callback(...)}, we will ignore the listener. You
    /// must clear any previously registered listeners using
    /// {@see InputFilterThread.unregister_thread_callback(...) before registering the new listener.
    ///
    /// NOTE: Also, registering a callback will start the looper if not already started.
    pub fn register_thread_callback(&self, callback: Box<dyn ThreadCallback + Send + Sync>) {
        self.thread_callback_handler.register_thread_callback(callback);
        self.start();
    }

    /// Unregisters a callback listener.
    ///
    /// NOTE: Unregistering a callback will stop the looper if not other callback registered.
    pub fn unregister_thread_callback(&self, callback: Box<dyn ThreadCallback + Send + Sync>) {
        self.thread_callback_handler.unregister_thread_callback(callback);
        // Stop the thread if no registered callbacks exist. We will recreate the thread when new
        // callbacks are registered.
        let has_callbacks = self.thread_callback_handler.has_callbacks();
        if !has_callbacks {
            self.stop();
        }
    }

    fn start(&self) {
        debug!("InputFilterThread: start thread");
        {
            // acquire looper lock
            let looper = &mut self.looper();
            if looper.cpp_thread.is_none() {
                looper.cpp_thread = Some(self.thread_creator.create(
                    &BnInputThreadCallback::new_binder(self.clone(), BinderFeatures::default()),
                ));
            }
        } // release looper lock
        self.set_finishing(false);
    }

    fn stop(&self) {
        debug!("InputFilterThread: stop thread");
        self.set_finishing(true);
        self.wake();
        {
            // acquire looper lock
            let looper = &mut self.looper();
            if let Some(cpp_thread) = &looper.cpp_thread {
                let _ = cpp_thread.finish();
            }
            // Clear all references
            looper.cpp_thread = None;
        } // release looper lock
    }

    fn set_finishing(&self, is_finishing: bool) {
        let filter_thread = &mut self.filter_thread();
        filter_thread.is_finishing = is_finishing;
    }

    fn loop_once(&self, now: i64) {
        let mut wake_up_time = i64::MAX;
        let mut timeout_expired = false;
        {
            // acquire thread lock
            let filter_thread = &mut self.filter_thread();
            if filter_thread.is_finishing {
                // Thread is finishing so don't block processing on it and let it loop.
                return;
            }
            if filter_thread.next_timeout != i64::MAX {
                if filter_thread.next_timeout <= now {
                    timeout_expired = true;
                    filter_thread.next_timeout = i64::MAX;
                } else {
                    wake_up_time = filter_thread.next_timeout;
                }
            }
        } // release thread lock
        if timeout_expired {
            self.thread_callback_handler.notify_timeout_expired(now);
        }
        self.sleep_until(wake_up_time);
    }

    fn filter_thread(&self) -> RwLockWriteGuard<'_, InputFilterThreadInner> {
        self.inner.write().unwrap()
    }

    fn sleep_until(&self, when_nanos: i64) {
        let looper = self.looper.read().unwrap();
        if let Some(cpp_thread) = &looper.cpp_thread {
            let _ = cpp_thread.sleepUntil(when_nanos);
        }
    }

    fn wake(&self) {
        let looper = self.looper.read().unwrap();
        if let Some(cpp_thread) = &looper.cpp_thread {
            let _ = cpp_thread.wake();
        }
    }

    fn looper(&self) -> RwLockWriteGuard<'_, Looper> {
        self.looper.write().unwrap()
    }
}

impl Interface for InputFilterThread {}

impl IInputThreadCallback for InputFilterThread {
    fn loopOnce(&self) -> binder::Result<()> {
        self.loop_once(clock_gettime(ClockId::CLOCK_MONOTONIC).unwrap().num_nanoseconds());
        Result::Ok(())
    }
}

#[derive(Default, Clone)]
struct ThreadCallbackHandler(Arc<RwLock<ThreadCallbackHandlerInner>>);

#[derive(Default)]
struct ThreadCallbackHandlerInner {
    callbacks: Vec<Box<dyn ThreadCallback + Send + Sync>>,
}

impl ThreadCallbackHandler {
    fn new() -> Self {
        Default::default()
    }

    fn has_callbacks(&self) -> bool {
        !&self.0.read().unwrap().callbacks.is_empty()
    }

    fn register_thread_callback(&self, callback: Box<dyn ThreadCallback + Send + Sync>) {
        let callbacks = &mut self.0.write().unwrap().callbacks;
        if callbacks.iter().any(|x| x.name() == callback.name()) {
            error!(
                "InputFilterThread: register_thread_callback, callback {:?} already exists!",
                callback.name()
            );
            return;
        }
        debug!(
            "InputFilterThread: register_thread_callback, callback {:?} added!",
            callback.name()
        );
        callbacks.push(callback);
    }

    fn unregister_thread_callback(&self, callback: Box<dyn ThreadCallback + Send + Sync>) {
        let callbacks = &mut self.0.write().unwrap().callbacks;
        if let Some(index) = callbacks.iter().position(|x| x.name() == callback.name()) {
            callbacks.remove(index);
            debug!(
                "InputFilterThread: unregister_thread_callback, callback {:?} removed!",
                callback.name()
            );
            return;
        }
        error!(
            "InputFilterThread: unregister_thread_callback, callback {:?} doesn't exist",
            callback.name()
        );
    }

    fn notify_timeout_expired(&self, when_nanos: i64) {
        let callbacks = &self.0.read().unwrap().callbacks;
        for callback in callbacks.iter() {
            callback.notify_timeout_expired(when_nanos);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::input_filter::{test_callbacks::TestCallbacks, InputFilterThreadCreator};
    use crate::input_filter_thread::{test_thread_callback::TestThreadCallback, InputFilterThread};
    use binder::Strong;
    use nix::{sys::time::TimeValLike, time::clock_gettime, time::ClockId};
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    #[test]
    fn test_register_callback_creates_cpp_thread() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = get_thread(test_callbacks.clone());
        let test_thread_callback = TestThreadCallback::new();
        test_thread.register_thread_callback(Box::new(test_thread_callback));
        assert!(test_callbacks.is_thread_running());
    }

    #[test]
    fn test_unregister_callback_finishes_cpp_thread() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = get_thread(test_callbacks.clone());
        let test_thread_callback = TestThreadCallback::new();
        test_thread.register_thread_callback(Box::new(test_thread_callback.clone()));
        test_thread.unregister_thread_callback(Box::new(test_thread_callback));
        assert!(!test_callbacks.is_thread_running());
    }

    #[test]
    fn test_notify_timeout_called_after_timeout_expired() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = get_thread(test_callbacks.clone());
        let test_thread_callback = TestThreadCallback::new();
        test_thread.register_thread_callback(Box::new(test_thread_callback.clone()));

        let now = clock_gettime(ClockId::CLOCK_MONOTONIC).unwrap().num_milliseconds();
        test_thread.request_timeout_at_time((now + 10) * 1000000);

        std::thread::sleep(Duration::from_millis(100));
        assert!(test_thread_callback.is_notify_timeout_called());
    }

    #[test]
    fn test_notify_timeout_not_called_before_timeout_expired() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = get_thread(test_callbacks.clone());
        let test_thread_callback = TestThreadCallback::new();
        test_thread.register_thread_callback(Box::new(test_thread_callback.clone()));

        let now = clock_gettime(ClockId::CLOCK_MONOTONIC).unwrap().num_milliseconds();
        test_thread.request_timeout_at_time((now + 100) * 1000000);

        std::thread::sleep(Duration::from_millis(10));
        assert!(!test_thread_callback.is_notify_timeout_called());
    }

    fn get_thread(callbacks: TestCallbacks) -> InputFilterThread {
        InputFilterThread::new(InputFilterThreadCreator::new(Arc::new(RwLock::new(Strong::new(
            Box::new(callbacks),
        )))))
    }
}

#[cfg(test)]
pub mod test_thread_callback {
    use crate::input_filter_thread::ThreadCallback;
    use std::sync::{Arc, RwLock, RwLockWriteGuard};

    #[derive(Default)]
    struct TestThreadCallbackInner {
        is_notify_timeout_called: bool,
    }

    #[derive(Default, Clone)]
    pub struct TestThreadCallback(Arc<RwLock<TestThreadCallbackInner>>);

    impl TestThreadCallback {
        pub fn new() -> Self {
            Default::default()
        }

        fn inner(&self) -> RwLockWriteGuard<'_, TestThreadCallbackInner> {
            self.0.write().unwrap()
        }

        pub fn is_notify_timeout_called(&self) -> bool {
            self.0.read().unwrap().is_notify_timeout_called
        }
    }

    impl ThreadCallback for TestThreadCallback {
        fn notify_timeout_expired(&self, _when_nanos: i64) {
            self.inner().is_notify_timeout_called = true;
        }
        fn name(&self) -> &str {
            "TestThreadCallback"
        }
    }
}
