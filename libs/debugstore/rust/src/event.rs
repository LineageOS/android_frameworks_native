/*
 * Copyright (C) 2024 The Android Open Source Project
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

use super::event_type::EventType;
use std::fmt;

/// Represents a single debug event within the Debug Store system.
///
/// It contains all the necessary information for a debug event.
#[derive(Clone)]
pub struct Event {
    /// The unique identifier for this event.
    pub id: u64,
    /// The optional name of the event.
    pub name: Option<String>,
    /// The system uptime when the event occurred.
    pub timestamp: i64,
    /// The type of the event.
    pub event_type: EventType,
    /// Additional data associated with the event, stored in the given order as key-value pairs.
    data: Vec<(String, String)>,
}

impl Event {
    /// Constructs a new `Event`.
    ///
    /// - `id`: The unique identifier for the event.
    /// - `name`: An optional name for the event.
    /// - `timestamp`: The system uptime when the event occurred.
    /// - `event_type`: The type of the event.
    /// - `data`: Additional data for the event, represented as ordered key-value pairs.
    pub fn new(
        id: u64,
        name: Option<String>,
        timestamp: i64,
        event_type: EventType,
        data: Vec<(String, String)>,
    ) -> Self {
        Self { id, name, timestamp, event_type, data }
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ID:{},C:{},T:{}", self.id, self.event_type, self.timestamp)?;

        if let Some(ref name) = self.name {
            write!(f, ",N:{}", name)?;
        }

        if !self.data.is_empty() {
            let data_str =
                self.data.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(";");
            write!(f, ",D:{}", data_str)?;
        }

        Ok(())
    }
}
