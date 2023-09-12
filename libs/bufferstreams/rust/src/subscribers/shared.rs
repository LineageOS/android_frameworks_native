// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module provides [BufferSubscriber] implementations and helpers.

use std::sync::{Arc, Mutex};

use crate::*;

/// A [BufferSubscriber] wrapper that provides shared access.
///
/// Normally, [BufferSubscriber]s are fully owned by the publisher that they are attached to. With
/// [SharedSubscriber], a
///
/// # Panics
///
/// [BufferSubscriber::on_subscribe] on a [SharedSubscriber] can only be called once, otherwise it
/// will panic. This is to prevent accidental and unsupported sharing between multiple publishers to
/// reflect the usual behavior where a publisher takes full ownership of a subscriber.
pub struct SharedSubscriber<S: BufferSubscriber>(Arc<Mutex<SharedSubscriberInner<S>>>);

struct SharedSubscriberInner<S: BufferSubscriber> {
    subscriber: S,
    is_subscribed: bool,
}

impl<S: BufferSubscriber> SharedSubscriber<S> {
    /// Create a new wrapper around a [BufferSubscriber].
    pub fn new(subscriber: S) -> Self {
        Self(Arc::new(Mutex::new(SharedSubscriberInner { subscriber, is_subscribed: false })))
    }

    /// Provides access to an immutable reference to the wrapped [BufferSubscriber].
    pub fn map_inner<R, F: FnOnce(&S) -> R>(&self, f: F) -> R {
        let inner = self.0.lock().unwrap();
        f(&inner.subscriber)
    }

    /// Provides access to a mutable reference to the wrapped [BufferSubscriber].
    pub fn map_inner_mut<R, F: FnOnce(&mut S) -> R>(&self, f: F) -> R {
        let mut inner = self.0.lock().unwrap();
        f(&mut inner.subscriber)
    }
}

impl<S: BufferSubscriber> Clone for SharedSubscriber<S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<S: BufferSubscriber> BufferSubscriber for SharedSubscriber<S> {
    fn get_subscriber_stream_config(&self) -> StreamConfig {
        let inner = self.0.lock().unwrap();
        inner.subscriber.get_subscriber_stream_config()
    }

    fn on_subscribe(&mut self, subscription: Box<dyn BufferSubscription>) {
        let mut inner = self.0.lock().unwrap();
        assert!(
            !inner.is_subscribed,
            "A SharedSubscriber can not be shared between two BufferPublishers"
        );
        inner.is_subscribed = true;

        inner.subscriber.on_subscribe(subscription);
    }

    fn on_next(&mut self, frame: Frame) {
        let mut inner = self.0.lock().unwrap();
        inner.subscriber.on_next(frame);
    }

    fn on_error(&mut self, error: BufferError) {
        let mut inner = self.0.lock().unwrap();
        inner.subscriber.on_error(error);
    }

    fn on_complete(&mut self) {
        let mut inner = self.0.lock().unwrap();
        inner.subscriber.on_complete();
    }
}
