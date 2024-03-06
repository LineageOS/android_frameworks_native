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

//! Provides useful subscribers for testing specifically. These should not be used in normal code.

use crate::*;

/// Represents a callback called by a [BufferPublisher] on a [BufferSubscriber].
pub enum TestingSubscriberEvent {
    /// Represents a call to [BufferSubscriber::on_subscribe].
    Subscribe,
    /// Represents a call to [BufferSubscriber::on_next].
    Next(Frame),
    /// Represents a call to [BufferSubscriber::on_error].
    Error(BufferError),
    /// Represents a call to [BufferSubscriber::on_complete].
    Complete,
}

/// A [BufferSubscriber] specifically for testing. Logs events as they happen which can be retrieved
/// by the test to ensure appropriate behavior.
pub struct TestSubscriber {
    config: StreamConfig,
    subscription: Option<Box<dyn BufferSubscription>>,
    events: Vec<TestingSubscriberEvent>,
}

impl TestSubscriber {
    /// Create a new [TestSubscriber].
    pub fn new(config: StreamConfig) -> Self {
        Self { config, subscription: None, events: Vec::new() }
    }

    /// Returns true if this [BufferSubscriber] has an active subscription.
    pub fn has_subscription(&self) -> bool {
        self.subscription.is_some()
    }

    /// Make a request on behalf of this test subscriber.
    ///
    /// This will panic if there is no owned subscription.
    pub fn request(&self, n: u64) {
        let subscription = self
            .subscription
            .as_deref()
            .expect("Tried to request on a TestSubscriber with no subscription");
        subscription.request(n);
    }

    /// Cancel on behalf of this test subscriber.
    ///
    /// # Panics
    ///
    /// This will panic if there is no owned subscription.
    pub fn cancel(&self) {
        let subscription = self
            .subscription
            .as_deref()
            .expect("Tried to cancel a TestSubscriber with no subscription");
        subscription.cancel();
    }

    /// Gets all of the events that have happened to this [BufferSubscriber] since the last call
    /// to this function or it was created.
    pub fn take_events(&mut self) -> Vec<TestingSubscriberEvent> {
        let mut out = Vec::new();
        out.append(&mut self.events);
        out
    }
}

impl BufferSubscriber for TestSubscriber {
    fn get_subscriber_stream_config(&self) -> StreamConfig {
        self.config
    }

    fn on_subscribe(&mut self, subscription: Box<dyn BufferSubscription>) {
        assert!(self.subscription.is_none(), "TestSubscriber must only be subscribed to once");
        self.subscription = Some(subscription);

        self.events.push(TestingSubscriberEvent::Subscribe);
    }

    fn on_next(&mut self, frame: Frame) {
        self.events.push(TestingSubscriberEvent::Next(frame));
    }

    fn on_error(&mut self, error: BufferError) {
        self.events.push(TestingSubscriberEvent::Error(error));
    }

    fn on_complete(&mut self) {
        self.events.push(TestingSubscriberEvent::Complete);
    }
}
