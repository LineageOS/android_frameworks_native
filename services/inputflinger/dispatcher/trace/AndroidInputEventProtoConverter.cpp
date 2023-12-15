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

#include "AndroidInputEventProtoConverter.h"

#include <android-base/logging.h>
#include <perfetto/trace/android/android_input_event.pbzero.h>

namespace android::inputdispatcher::trace {

void AndroidInputEventProtoConverter::toProtoMotionEvent(const TracedMotionEvent& event,
                                                         proto::AndroidMotionEvent& outProto) {
    outProto.set_event_id(event.id);
    outProto.set_event_time_nanos(event.eventTime);
    outProto.set_down_time_nanos(event.downTime);
    outProto.set_source(event.source);
    outProto.set_action(event.action);
    outProto.set_device_id(event.deviceId);
    outProto.set_display_id(event.displayId);
    outProto.set_classification(static_cast<int32_t>(event.classification));
    outProto.set_cursor_position_x(event.xCursorPosition);
    outProto.set_cursor_position_y(event.yCursorPosition);
    outProto.set_flags(event.flags);
    outProto.set_policy_flags(event.policyFlags);

    for (uint32_t i = 0; i < event.pointerProperties.size(); i++) {
        auto* pointer = outProto.add_pointer();

        const auto& props = event.pointerProperties[i];
        pointer->set_pointer_id(props.id);
        pointer->set_tool_type(static_cast<int32_t>(props.toolType));

        const auto& coords = event.pointerCoords[i];
        auto bits = BitSet64(coords.bits);
        for (int32_t axisIndex = 0; !bits.isEmpty(); axisIndex++) {
            const auto axis = bits.clearFirstMarkedBit();
            auto axisEntry = pointer->add_axis_value();
            axisEntry->set_axis(axis);
            axisEntry->set_value(coords.values[axisIndex]);
        }
    }
}

void AndroidInputEventProtoConverter::toProtoKeyEvent(const TracedKeyEvent& event,
                                                      proto::AndroidKeyEvent& outProto) {
    outProto.set_event_id(event.id);
    outProto.set_event_time_nanos(event.eventTime);
    outProto.set_down_time_nanos(event.downTime);
    outProto.set_source(event.source);
    outProto.set_action(event.action);
    outProto.set_device_id(event.deviceId);
    outProto.set_display_id(event.displayId);
    outProto.set_key_code(event.keyCode);
    outProto.set_scan_code(event.scanCode);
    outProto.set_meta_state(event.metaState);
    outProto.set_repeat_count(event.repeatCount);
    outProto.set_flags(event.flags);
    outProto.set_policy_flags(event.policyFlags);
}

void AndroidInputEventProtoConverter::toProtoWindowDispatchEvent(
        const InputTracingBackendInterface::WindowDispatchArgs& args,
        proto::AndroidWindowInputDispatchEvent& outProto) {
    std::visit([&](auto entry) { outProto.set_event_id(entry.id); }, args.eventEntry);
    outProto.set_vsync_id(args.vsyncId);
    outProto.set_window_id(args.windowId);
    outProto.set_resolved_flags(args.resolvedFlags);

    if (auto* motion = std::get_if<TracedMotionEvent>(&args.eventEntry); motion != nullptr) {
        for (size_t i = 0; i < motion->pointerProperties.size(); i++) {
            auto* pointerProto = outProto.add_dispatched_pointer();
            pointerProto->set_pointer_id(motion->pointerProperties[i].id);
            const auto rawXY =
                    MotionEvent::calculateTransformedXY(motion->source, args.rawTransform,
                                                        motion->pointerCoords[i].getXYValue());
            pointerProto->set_x_in_display(rawXY.x);
            pointerProto->set_y_in_display(rawXY.y);

            const auto& coords = motion->pointerCoords[i];
            const auto coordsInWindow =
                    MotionEvent::calculateTransformedCoords(motion->source, args.transform, coords);
            auto bits = BitSet64(coords.bits);
            for (int32_t axisIndex = 0; !bits.isEmpty(); axisIndex++) {
                const uint32_t axis = bits.clearFirstMarkedBit();
                const float axisValueInWindow = coordsInWindow.values[axisIndex];
                if (coords.values[axisIndex] != axisValueInWindow) {
                    auto* axisEntry = pointerProto->add_axis_value_in_window();
                    axisEntry->set_axis(axis);
                    axisEntry->set_value(axisValueInWindow);
                }
            }
        }
    }
}

} // namespace android::inputdispatcher::trace
