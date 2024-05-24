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
use std::time::Duration;
use std::{thread, thread::Thread};

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
}

struct InputFilterThreadInner {
    cpp_thread: Option<Strong<dyn IInputThread>>,
    looper: Option<Thread>,
    next_timeout: i64,
    is_finishing: bool,
}

impl InputFilterThread {
    /// Create a new InputFilterThread instance.
    /// NOTE: This will create a new thread. Clone the existing instance to reuse the same thread.
    pub fn new(thread_creator: InputFilterThreadCreator) -> InputFilterThread {
        Self {
            thread_creator,
            thread_callback_handler: ThreadCallbackHandler::new(),
            inner: Arc::new(RwLock::new(InputFilterThreadInner {
                cpp_thread: None,
                looper: None,
                next_timeout: i64::MAX,
                is_finishing: false,
            })),
        }
    }

    /// Listener requesting a timeout in future will receive a callback at or before the requested
    /// time on the input filter thread.
    /// {@see ThreadCallback.notify_timeout_expired(...)}
    pub fn request_timeout_at_time(&self, when_nanos: i64) {
        let filter_thread = &mut self.filter_thread();
        if when_nanos < filter_thread.next_timeout {
            filter_thread.next_timeout = when_nanos;
            if let Some(looper) = &filter_thread.looper {
                looper.unpark();
            }
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
        let filter_thread = &mut self.filter_thread();
        if filter_thread.cpp_thread.is_none() {
            filter_thread.cpp_thread = Some(self.thread_creator.create(
                &BnInputThreadCallback::new_binder(self.clone(), BinderFeatures::default()),
            ));
            filter_thread.looper = None;
            filter_thread.is_finishing = false;
        }
    }

    fn stop(&self) {
        debug!("InputFilterThread: stop thread");
        let filter_thread = &mut self.filter_thread();
        filter_thread.is_finishing = true;
        if let Some(looper) = &filter_thread.looper {
            looper.unpark();
        }
        if let Some(cpp_thread) = &filter_thread.cpp_thread {
            let _ = cpp_thread.finish();
        }
        // Clear all references
        filter_thread.cpp_thread = None;
        filter_thread.looper = None;
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
            if filter_thread.looper.is_none() {
                filter_thread.looper = Some(std::thread::current());
            }
        } // release thread lock
        if timeout_expired {
            self.thread_callback_handler.notify_timeout_expired(now);
        }
        if wake_up_time == i64::MAX {
            thread::park();
        } else {
            let duration_now = Duration::from_nanos(now as u64);
            let duration_wake_up = Duration::from_nanos(wake_up_time as u64);
            thread::park_timeout(duration_wake_up - duration_now);
        }
    }

    fn filter_thread(&self) -> RwLockWriteGuard<'_, InputFilterThreadInner> {
        self.inner.write().unwrap()
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
    use crate::input_filter::test_callbacks::TestCallbacks;
    use crate::input_filter_thread::{
        test_thread::TestThread, test_thread_callback::TestThreadCallback,
    };

    #[test]
    fn test_register_callback_creates_cpp_thread() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = TestThread::new(test_callbacks.clone());
        let test_thread_callback = TestThreadCallback::new();
        test_thread.register_thread_callback(test_thread_callback);
        assert!(test_callbacks.is_thread_created());
    }

    #[test]
    fn test_unregister_callback_finishes_cpp_thread() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = TestThread::new(test_callbacks.clone());
        let test_thread_callback = TestThreadCallback::new();
        test_thread.register_thread_callback(test_thread_callback.clone());
        test_thread.unregister_thread_callback(test_thread_callback);
        assert!(test_callbacks.is_thread_finished());
    }

    #[test]
    fn test_notify_timeout_called_after_timeout_expired() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = TestThread::new(test_callbacks.clone());
        let test_thread_callback = TestThreadCallback::new();
        test_thread.register_thread_callback(test_thread_callback.clone());
        test_thread.start_looper();

        test_thread.request_timeout_at_time(500);
        test_thread.dispatch_next();

        test_thread.move_time_forward(500);

        test_thread.stop_looper();
        assert!(test_thread_callback.is_notify_timeout_called());
    }

    #[test]
    fn test_notify_timeout_not_called_before_timeout_expired() {
        let test_callbacks = TestCallbacks::new();
        let test_thread = TestThread::new(test_callbacks.clone());
        let test_thread_callback = TestThreadCallback::new();
        test_thread.register_thread_callback(test_thread_callback.clone());
        test_thread.start_looper();

        test_thread.request_timeout_at_time(500);
        test_thread.dispatch_next();

        test_thread.move_time_forward(100);

        test_thread.stop_looper();
        assert!(!test_thread_callback.is_notify_timeout_called());
    }
}

#[cfg(test)]
pub mod test_thread {

    use crate::input_filter::{test_callbacks::TestCallbacks, InputFilterThreadCreator};
    use crate::input_filter_thread::{test_thread_callback::TestThreadCallback, InputFilterThread};
    use binder::Strong;
    use std::sync::{
        atomic::AtomicBool, atomic::AtomicI64, atomic::Ordering, Arc, RwLock, RwLockWriteGuard,
    };
    use std::time::Duration;

    #[derive(Clone)]
    pub struct TestThread {
        input_thread: InputFilterThread,
        inner: Arc<RwLock<TestThreadInner>>,
        exit_flag: Arc<AtomicBool>,
        now: Arc<AtomicI64>,
    }

    struct TestThreadInner {
        join_handle: Option<std::thread::JoinHandle<()>>,
    }

    impl TestThread {
        pub fn new(callbacks: TestCallbacks) -> TestThread {
            Self {
                input_thread: InputFilterThread::new(InputFilterThreadCreator::new(Arc::new(
                    RwLock::new(Strong::new(Box::new(callbacks))),
                ))),
                inner: Arc::new(RwLock::new(TestThreadInner { join_handle: None })),
                exit_flag: Arc::new(AtomicBool::new(false)),
                now: Arc::new(AtomicI64::new(0)),
            }
        }

        fn inner(&self) -> RwLockWriteGuard<'_, TestThreadInner> {
            self.inner.write().unwrap()
        }

        pub fn get_input_thread(&self) -> InputFilterThread {
            self.input_thread.clone()
        }

        pub fn register_thread_callback(&self, thread_callback: TestThreadCallback) {
            self.input_thread.register_thread_callback(Box::new(thread_callback));
        }

        pub fn unregister_thread_callback(&self, thread_callback: TestThreadCallback) {
            self.input_thread.unregister_thread_callback(Box::new(thread_callback));
        }

        pub fn start_looper(&self) {
            self.exit_flag.store(false, Ordering::Relaxed);
            let clone = self.clone();
            let join_handle = std::thread::Builder::new()
                .name("test_thread".to_string())
                .spawn(move || {
                    while !clone.exit_flag.load(Ordering::Relaxed) {
                        clone.loop_once();
                    }
                })
                .unwrap();
            self.inner().join_handle = Some(join_handle);
            // Sleep until the looper thread starts
            std::thread::sleep(Duration::from_millis(10));
        }

        pub fn stop_looper(&self) {
            self.exit_flag.store(true, Ordering::Relaxed);
            {
                let mut inner = self.inner();
                if let Some(join_handle) = &inner.join_handle {
                    join_handle.thread().unpark();
                }
                inner.join_handle.take().map(std::thread::JoinHandle::join);
                inner.join_handle = None;
            }
            self.exit_flag.store(false, Ordering::Relaxed);
        }

        pub fn move_time_forward(&self, value: i64) {
            let _ = self.now.fetch_add(value, Ordering::Relaxed);
            self.dispatch_next();
        }

        pub fn dispatch_next(&self) {
            if let Some(join_handle) = &self.inner().join_handle {
                join_handle.thread().unpark();
            }
            // Sleep until the looper thread runs a loop
            std::thread::sleep(Duration::from_millis(10));
        }

        fn loop_once(&self) {
            self.input_thread.loop_once(self.now.load(Ordering::Relaxed));
        }

        pub fn request_timeout_at_time(&self, when_nanos: i64) {
            self.input_thread.request_timeout_at_time(when_nanos);
        }
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
