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

//! Provides useful publishers for testing specifically. These should not be used in normal code.

use crate::{subscriptions::SharedBufferSubscription, *};

/// A [BufferPublisher] specifically for testing.
///
/// Provides users the ability to send events and read the state of the subscription.
pub struct TestPublisher {
    config: StreamConfig,
    subscriber: Option<Box<dyn BufferSubscriber>>,
    subscription: SharedBufferSubscription,
}

impl TestPublisher {
    /// Create a new [TestPublisher].
    pub fn new(config: StreamConfig) -> Self {
        Self { config, subscriber: None, subscription: SharedBufferSubscription::new() }
    }

    /// Send a [BufferSubscriber::on_next] event to an owned [BufferSubscriber] if it has any
    /// requested and returns true. Drops the frame and returns false otherwise.
    ///
    /// # Panics
    ///
    /// This will panic if there is no owned subscriber.
    pub fn send_frame(&mut self, frame: Frame) -> bool {
        let subscriber =
            self.subscriber.as_deref_mut().expect("Tried to send_frame with no subscriber");

        if self.subscription.take_request() {
            subscriber.on_next(frame);
            true
        } else {
            false
        }
    }

    /// Send a [BufferSubscriber::on_complete] event to an owned [BufferSubscriber].
    ///
    /// # Panics
    ///
    /// This will panic if there is no owned subscriber.
    pub fn send_complete(&mut self) {
        let subscriber =
            self.subscriber.as_deref_mut().expect("Tried to send_complete with no subscriber");
        subscriber.on_complete();
    }

    /// Send a [BufferSubscriber::on_error] event to an owned [BufferSubscriber].
    ///
    /// # Panics
    ///
    /// This will panic if there is no owned subscriber.
    pub fn send_error(&mut self, error: BufferError) {
        let subscriber =
            self.subscriber.as_deref_mut().expect("Tried to send_error with no subscriber");
        subscriber.on_error(error);
    }

    /// Returns whether this [BufferPublisher] owns a subscriber.
    pub fn has_subscriber(&self) -> bool {
        self.subscriber.is_some()
    }

    /// Returns the nummber of frames requested by the [BufferSubscriber].
    pub fn pending_requests(&self) -> u64 {
        self.subscription.pending_requests()
    }

    /// Returns whether the [BufferSubscriber] has cancelled the subscription.
    pub fn is_cancelled(&self) -> bool {
        self.subscription.is_cancelled()
    }
}

impl BufferPublisher for TestPublisher {
    fn get_publisher_stream_config(&self) -> crate::StreamConfig {
        self.config
    }

    fn subscribe(&mut self, subscriber: impl BufferSubscriber + 'static) {
        assert!(self.subscriber.is_none(), "TestingPublishers can only take one subscriber");
        self.subscriber = Some(Box::new(subscriber));

        if let Some(ref mut subscriber) = self.subscriber {
            subscriber.on_subscribe(self.subscription.clone_for_subscriber());
        }
    }
}
