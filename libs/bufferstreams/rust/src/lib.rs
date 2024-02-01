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

//! libbufferstreams: Reactive Streams for Graphics Buffers

pub mod buffers;
pub mod publishers;
mod stream_config;
pub mod subscribers;
pub mod subscriptions;

use buffers::Buffer;
pub use stream_config::*;

/// This function will print Hello World.
#[no_mangle]
pub extern "C" fn hello() -> bool {
    println!("Hello world.");
    true
}

/// BufferPublishers provide buffers to BufferSusbscribers. Depending on the
/// particular object in question, these could be allocated locally or provided
/// over IPC.
///
/// BufferPublishers are required to adhere to the following, based on the
/// reactive streams specification:
/// * The total number of on_next´s signalled by a Publisher to a Subscriber
/// MUST be less than or equal to the total number of elements requested by that
/// Subscriber´s Subscription at all times.
/// * A Publisher MAY signal fewer on_next than requested and terminate the
/// Subscription by calling on_complete or on_error.
/// * on_subscribe, on_next, on_error and on_complete signaled to a Subscriber
/// MUST be signaled serially.
/// * If a Publisher fails it MUST signal an on_error.
/// * If a Publisher terminates successfully (finite stream) it MUST signal an
/// on_complete.
/// * If a Publisher signals either on_error or on_complete on a Subscriber,
/// that Subscriber’s Subscription MUST be considered cancelled.
/// * Once a terminal state has been signaled (on_error, on_complete) it is
/// REQUIRED that no further signals occur.
/// * If a Subscription is cancelled its Subscriber MUST eventually stop being
///  signaled.
/// * A Publisher MAY support multiple Subscribers and decides whether each
/// Subscription is unicast or multicast.
pub trait BufferPublisher {
    /// Returns the StreamConfig of buffers that publisher creates.
    fn get_publisher_stream_config(&self) -> StreamConfig;
    /// This function will create the subscription between the publisher and
    /// the subscriber.
    fn subscribe(&mut self, subscriber: impl BufferSubscriber + 'static);
}

/// BufferSubscribers can subscribe to BufferPublishers. They can request Frames
/// via the BufferSubscription they get from the publisher, then receive Frames
/// via on_next.
///
/// BufferSubcribers are required to adhere to the following, based on the
/// reactive streams specification:
/// * The total number of on_next´s signalled by a Publisher to a Subscriber
/// MUST be less than or equal to the total number of elements requested by that
/// Subscriber´s Subscription at all times.
/// * A Publisher MAY signal fewer on_next than requested and terminate the
/// Subscription by calling on_complete or on_error.
/// * on_subscribe, on_next, on_error and on_complete signaled to a Subscriber
/// MUST be signaled serially.
/// * If a Publisher fails it MUST signal an on_error.
/// * If a Publisher terminates successfully (finite stream) it MUST signal an
/// on_complete.
/// * If a Publisher signals either on_error or on_complete on a Subscriber,
/// that Subscriber’s Subscription MUST be considered cancelled.
/// * Once a terminal state has been signaled (on_error, on_complete) it is
/// REQUIRED that no further signals occur.
/// * If a Subscription is cancelled its Subscriber MUST eventually stop being
/// signaled.
/// * Publisher.subscribe MAY be called as many times as wanted but MUST be
/// with a different Subscriber each time.
/// * A Publisher MAY support multiple Subscribers and decides whether each
/// Subscription is unicast or multicast.
pub trait BufferSubscriber {
    /// The StreamConfig of buffers that this subscriber expects.
    fn get_subscriber_stream_config(&self) -> StreamConfig;
    /// This function will be called at the beginning of the subscription.
    fn on_subscribe(&mut self, subscription: Box<dyn BufferSubscription>);
    /// This function will be called for buffer that comes in.
    fn on_next(&mut self, frame: Frame);
    /// This function will be called in case of an error.
    fn on_error(&mut self, error: BufferError);
    /// This function will be called on finite streams when done.
    fn on_complete(&mut self);
}

/// BufferSubscriptions serve as the bridge between BufferPublishers and
/// BufferSubscribers. BufferSubscribers receive a BufferSubscription when they
/// subscribe to a BufferPublisher via on_subscribe.
///
/// This object is used by the BufferSubscriber to cancel its subscription
/// or request more buffers.
///
/// BufferSubcriptions are required to adhere to the following, based on the
/// reactive streams specification:
/// * Subscription.request and Subscription.cancel MUST only be called inside
/// of its Subscriber context.
/// * The Subscription MUST allow the Subscriber to call Subscription.request
/// synchronously from within on_next or on_subscribe.
/// * Subscription.request MUST place an upper bound on possible synchronous
/// recursion between Publisher and Subscriber.
/// * Subscription.request SHOULD respect the responsivity of its caller by
/// returning in a timely manner.
/// * Subscription.cancel MUST respect the responsivity of its caller by
/// returning in a timely manner, MUST be idempotent and MUST be thread-safe.
/// * After the Subscription is cancelled, additional
/// Subscription.request(n: u64) MUST be NOPs.
/// * After the Subscription is cancelled, additional Subscription.cancel()
/// MUST be NOPs.
/// * While the Subscription is not cancelled, Subscription.request(n: u64)
/// MUST register the given number of additional elements to be produced to the
/// respective subscriber.
/// * While the Subscription is not cancelled, Subscription.request(n: u64)
/// MUST signal on_error if the argument is <= 0. The cause message SHOULD
/// explain that non-positive request signals are illegal.
/// * While the Subscription is not cancelled, Subscription.request(n: u64)
/// MAY synchronously call on_next on this (or other) subscriber(s).
/// * While the Subscription is not cancelled, Subscription.request(n: u64)
/// MAY synchronously call on_complete or on_error on this (or other)
/// subscriber(s).
/// * While the Subscription is not cancelled, Subscription.cancel() MUST
/// request the Publisher to eventually stop signaling its Subscriber. The
/// operation is NOT REQUIRED to affect the Subscription immediately.
/// * While the Subscription is not cancelled, Subscription.cancel() MUST
/// request the Publisher to eventually drop any references to the corresponding
/// subscriber.
/// * While the Subscription is not cancelled, calling Subscription.cancel MAY
/// cause the Publisher, if stateful, to transition into the shut-down state if
/// no other Subscription exists at this point.
/// * Calling Subscription.cancel MUST return normally.
/// * Calling Subscription.request MUST return normally.
pub trait BufferSubscription: Send + Sync + 'static {
    /// request
    fn request(&self, n: u64);
    /// cancel
    fn cancel(&self);
}

/// Type used to describe errors produced by subscriptions.
pub type BufferError = anyhow::Error;

/// Struct used to contain the buffer.
pub struct Frame {
    /// A buffer to be used this frame.
    pub buffer: Buffer,
    /// The time at which this buffer is expected to be displayed.
    pub present_time: i64,
    /// A fence used for reading/writing safely.
    pub fence: i32,
}

#[cfg(test)]
mod test {
    #![allow(warnings, unused)]
    use super::*;

    use anyhow::anyhow;
    use buffers::Buffer;
    use nativewindow::{AHardwareBuffer_Format, AHardwareBuffer_UsageFlags};
    use std::{borrow::BorrowMut, error::Error, ops::Add, sync::Arc};

    use crate::{
        publishers::testing::*,
        subscribers::{testing::*, SharedSubscriber},
    };

    const STREAM_CONFIG: StreamConfig = StreamConfig {
        width: 1,
        height: 1,
        layers: 1,
        format: AHardwareBuffer_Format::AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
        usage: AHardwareBuffer_UsageFlags::AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
        stride: 0,
    };

    fn make_frame() -> Frame {
        Frame {
            buffer: Buffer::new_unowned(
                STREAM_CONFIG
                    .create_hardware_buffer()
                    .expect("Unable to create hardware buffer for test"),
            ),
            present_time: 1,
            fence: 0,
        }
    }

    #[test]
    fn test_test_implementations_next() {
        let subscriber = SharedSubscriber::new(TestSubscriber::new(STREAM_CONFIG));
        let mut publisher = TestPublisher::new(STREAM_CONFIG);

        publisher.subscribe(subscriber.clone());
        assert!(subscriber.map_inner(|s| s.has_subscription()));
        assert!(publisher.has_subscriber());

        publisher.send_frame(make_frame());
        let events = subscriber.map_inner_mut(|s| s.take_events());
        assert!(!matches!(events.last().unwrap(), TestingSubscriberEvent::Next(_)));

        subscriber.map_inner(|s| s.request(1));
        assert_eq!(publisher.pending_requests(), 1);

        publisher.send_frame(make_frame());
        let events = subscriber.map_inner_mut(|s| s.take_events());
        assert!(matches!(events.last().unwrap(), TestingSubscriberEvent::Next(_)));
        assert_eq!(publisher.pending_requests(), 0);
    }

    #[test]
    fn test_test_implementations_complete() {
        let subscriber = SharedSubscriber::new(TestSubscriber::new(STREAM_CONFIG));
        let mut publisher = TestPublisher::new(STREAM_CONFIG);

        publisher.subscribe(subscriber.clone());
        assert!(subscriber.map_inner(|s| s.has_subscription()));
        assert!(publisher.has_subscriber());

        publisher.send_complete();
        let events = subscriber.map_inner_mut(|s| s.take_events());
        assert!(matches!(events.last().unwrap(), TestingSubscriberEvent::Complete));
    }

    #[test]
    fn test_test_implementations_error() {
        let subscriber = SharedSubscriber::new(TestSubscriber::new(STREAM_CONFIG));
        let mut publisher = TestPublisher::new(STREAM_CONFIG);

        publisher.subscribe(subscriber.clone());
        assert!(subscriber.map_inner(|s| s.has_subscription()));
        assert!(publisher.has_subscriber());

        publisher.send_error(anyhow!("error"));
        let events = subscriber.map_inner_mut(|s| s.take_events());
        assert!(matches!(events.last().unwrap(), TestingSubscriberEvent::Error(_)));
    }
}
