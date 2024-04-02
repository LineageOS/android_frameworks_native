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
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Marks the an unknown or invalid event, for convenient mapping to a protobuf enum.
    Invalid,
    /// Marks the beginning of a duration-based event, indicating the start of a timed operation.
    DurationStart,
    /// Marks the end of a duration-based event, indicating the end of a timed operation.
    DurationEnd,
    /// Represents a single, instantaneous event with no duration.
    Point,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                EventType::Invalid => "I",
                EventType::DurationStart => "S",
                EventType::DurationEnd => "E",
                EventType::Point => "P",
            }
        )
    }
}
