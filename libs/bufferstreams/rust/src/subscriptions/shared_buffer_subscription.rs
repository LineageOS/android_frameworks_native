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

use std::sync::{Arc, Mutex};

use crate::*;

/// A simple sharable helper that can be used as a [BufferSubscription] by a [BufferSubscriber] and
/// as a state tracker by a [BufferPublisher].
#[derive(Clone, Debug)]
pub struct SharedBufferSubscription(Arc<Mutex<BufferSubscriptionData>>);

#[derive(Debug, Default)]
struct BufferSubscriptionData {
    requests: u64,
    is_cancelled: bool,
}

impl SharedBufferSubscription {
    /// Create a new [SharedBufferSubscription].
    pub fn new() -> Self {
        SharedBufferSubscription::default()
    }

    /// Clone this [SharedBufferSubscription] so it can be passed into
    /// [BufferSubscriber::on_subscribe].
    pub fn clone_for_subscriber(&self) -> Box<dyn BufferSubscription> {
        Box::new(self.clone()) as Box<dyn BufferSubscription>
    }

    /// If possible (not cancelled and with requests pending), take
    pub fn take_request(&self) -> bool {
        let mut data = self.0.lock().unwrap();

        if data.is_cancelled || data.requests == 0 {
            false
        } else {
            data.requests -= 1;
            true
        }
    }

    /// Get the number of pending requests made by the [BufferSubscriber] via
    /// [BufferSubscription::request].
    pub fn pending_requests(&self) -> u64 {
        self.0.lock().unwrap().requests
    }

    /// Get get whether the [BufferSubscriber] has called [BufferSubscription::cancel].
    pub fn is_cancelled(&self) -> bool {
        self.0.lock().unwrap().is_cancelled
    }
}

impl Default for SharedBufferSubscription {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(BufferSubscriptionData::default())))
    }
}

impl BufferSubscription for SharedBufferSubscription {
    fn request(&self, n: u64) {
        let mut data = self.0.lock().unwrap();
        if !data.is_cancelled {
            data.requests = data.requests.saturating_add(n);
        }
    }

    fn cancel(&self) {
        let mut data = self.0.lock().unwrap();
        data.is_cancelled = true;
    }
}
