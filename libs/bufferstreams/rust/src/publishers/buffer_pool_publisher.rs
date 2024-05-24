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

use crate::{
    buffers::BufferPool, subscriptions::SharedBufferSubscription, BufferPublisher,
    BufferSubscriber, Frame, StreamConfig,
};

/// The [BufferPoolPublisher] submits buffers from a pool over to the subscriber.
pub struct BufferPoolPublisher {
    stream_config: StreamConfig,
    buffer_pool: BufferPool,
    subscription: SharedBufferSubscription,
    subscriber: Option<Box<dyn BufferSubscriber>>,
}

impl BufferPoolPublisher {
    /// The [BufferPoolPublisher] needs to initialize a [BufferPool], the [BufferPool] will create
    /// all buffers at initialization using the stream_config.
    pub fn new(stream_config: StreamConfig, size: usize) -> Option<Self> {
        BufferPool::new(size, stream_config).map(|buffer_pool| Self {
            stream_config,
            buffer_pool,
            subscription: SharedBufferSubscription::new(),
            subscriber: None,
        })
    }

    /// If the [SharedBufferSubscription] is ready for a [Frame], a buffer will be requested from
    /// [BufferPool] and sent over to the [BufferSubscriber].
    pub fn send_next_frame(&mut self, present_time: i64) -> bool {
        if let Some(subscriber) = self.subscriber.as_mut() {
            if self.subscription.take_request() {
                if let Some(buffer) = self.buffer_pool.next_buffer() {
                    let frame = Frame { buffer, present_time, fence: 0 };

                    subscriber.on_next(frame);
                    return true;
                }
            }
        }
        false
    }
}

impl BufferPublisher for BufferPoolPublisher {
    fn get_publisher_stream_config(&self) -> StreamConfig {
        self.stream_config
    }

    fn subscribe(&mut self, subscriber: impl BufferSubscriber + 'static) {
        assert!(self.subscriber.is_none());

        self.subscriber = Some(Box::new(subscriber));
        self.subscriber.as_mut().unwrap().on_subscribe(self.subscription.clone_for_subscriber());
    }
}

#[cfg(test)]
mod test {
    use nativewindow::{AHardwareBuffer_Format, AHardwareBuffer_UsageFlags};

    use super::*;

    use crate::{
        subscribers::{
            testing::{TestSubscriber, TestingSubscriberEvent},
            SharedSubscriber,
        },
        StreamConfig,
    };

    const STREAM_CONFIG: StreamConfig = StreamConfig {
        width: 1,
        height: 1,
        layers: 1,
        format: AHardwareBuffer_Format::AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM,
        usage: AHardwareBuffer_UsageFlags::AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
        stride: 0,
    };

    #[test]
    fn test_send_next_frame() {
        let subscriber = SharedSubscriber::new(TestSubscriber::new(STREAM_CONFIG));

        let mut buffer_pool_publisher = BufferPoolPublisher::new(STREAM_CONFIG, 1).unwrap();
        buffer_pool_publisher.subscribe(subscriber.clone());

        subscriber.map_inner(|s| s.request(1));

        assert!(buffer_pool_publisher.send_next_frame(1));

        let events = subscriber.map_inner_mut(|s| s.take_events());
        assert!(matches!(events.last().unwrap(), TestingSubscriberEvent::Next(_)));
        assert_eq!(buffer_pool_publisher.subscription.pending_requests(), 0);
    }
}
