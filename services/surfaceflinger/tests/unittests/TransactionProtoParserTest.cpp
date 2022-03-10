/*
 * Copyright 2021 The Android Open Source Project
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <limits> // std::numeric_limits

#include <gui/SurfaceComposerClient.h>

#include "Tracing/TransactionProtoParser.h"

using namespace android::surfaceflinger;

namespace android {

TEST(TransactionProtoParserTest, parse) {
    const sp<IBinder> layerHandle = new BBinder();
    const sp<IBinder> displayHandle = new BBinder();
    TransactionState t1;
    t1.originPid = 1;
    t1.originUid = 2;
    t1.frameTimelineInfo.vsyncId = 3;
    t1.frameTimelineInfo.inputEventId = 4;
    t1.postTime = 5;

    layer_state_t layer;
    layer.layerId = 6;
    layer.what = std::numeric_limits<uint64_t>::max();
    layer.what &= ~static_cast<uint64_t>(layer_state_t::eBufferChanged);
    layer.x = 7;
    layer.matrix.dsdx = 15;

    size_t layerCount = 2;
    t1.states.reserve(layerCount);
    for (uint32_t i = 0; i < layerCount; i++) {
        ComposerState s;
        if (i == 1) {
            layer.parentSurfaceControlForChild =
                    new SurfaceControl(SurfaceComposerClient::getDefault(), layerHandle, nullptr,
                                       42);
        }
        s.state = layer;
        t1.states.add(s);
    }

    size_t displayCount = 2;
    t1.displays.reserve(displayCount);
    for (uint32_t i = 0; i < displayCount; i++) {
        DisplayState display;
        display.what = std::numeric_limits<uint32_t>::max();
        if (i == 0) {
            display.token = displayHandle;
        } else {
            display.token = nullptr;
        }
        display.width = 85;
        t1.displays.add(display);
    }

    class TestMapper : public TransactionProtoParser::FlingerDataMapper {
    public:
        sp<IBinder> layerHandle;
        sp<IBinder> displayHandle;

        TestMapper(sp<IBinder> layerHandle, sp<IBinder> displayHandle)
              : layerHandle(layerHandle), displayHandle(displayHandle) {}

        sp<IBinder> getLayerHandle(int32_t id) const override {
            return (id == 42) ? layerHandle : nullptr;
        }
        int64_t getLayerId(const sp<IBinder>& handle) const override {
            return (handle == layerHandle) ? 42 : -1;
        }
        sp<IBinder> getDisplayHandle(int32_t id) const {
            return (id == 43) ? displayHandle : nullptr;
        }
        int32_t getDisplayId(const sp<IBinder>& handle) const {
            return (handle == displayHandle) ? 43 : -1;
        }
    };

    TransactionProtoParser parser(std::make_unique<TestMapper>(layerHandle, displayHandle));

    proto::TransactionState proto = parser.toProto(t1);
    TransactionState t2 = parser.fromProto(proto);

    ASSERT_EQ(t1.originPid, t2.originPid);
    ASSERT_EQ(t1.originUid, t2.originUid);
    ASSERT_EQ(t1.frameTimelineInfo.vsyncId, t2.frameTimelineInfo.vsyncId);
    ASSERT_EQ(t1.frameTimelineInfo.inputEventId, t2.frameTimelineInfo.inputEventId);
    ASSERT_EQ(t1.postTime, t2.postTime);
    ASSERT_EQ(t1.states.size(), t2.states.size());
    ASSERT_EQ(t1.states[0].state.x, t2.states[0].state.x);
    ASSERT_EQ(t1.states[0].state.matrix.dsdx, t2.states[0].state.matrix.dsdx);
    ASSERT_EQ(t1.states[1].state.parentSurfaceControlForChild->getHandle(),
              t2.states[1].state.parentSurfaceControlForChild->getHandle());

    ASSERT_EQ(t1.displays.size(), t2.displays.size());
    ASSERT_EQ(t1.displays[1].width, t2.displays[1].width);
    ASSERT_EQ(t1.displays[0].token, t2.displays[0].token);
}

} // namespace android
