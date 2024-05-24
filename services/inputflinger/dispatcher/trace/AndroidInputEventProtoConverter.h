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

#pragma once

#include <perfetto/trace/android/android_input_event.pbzero.h>

#include "InputTracingBackendInterface.h"

namespace proto = perfetto::protos::pbzero;

namespace android::inputdispatcher::trace {

/**
 * Write traced events into Perfetto protos.
 */
class AndroidInputEventProtoConverter {
public:
    static void toProtoMotionEvent(const TracedMotionEvent& event,
                                   proto::AndroidMotionEvent& outProto);
    static void toProtoKeyEvent(const TracedKeyEvent& event, proto::AndroidKeyEvent& outProto);
    static void toProtoWindowDispatchEvent(const InputTracingBackendInterface::WindowDispatchArgs&,
                                           proto::AndroidWindowInputDispatchEvent& outProto);
};

} // namespace android::inputdispatcher::trace
