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
#include <ui/Rotation.h>
#include "LayerProtoHelper.h"

#include "Tracing/TransactionProtoParser.h"

using namespace android::surfaceflinger;

namespace android {

TEST(TransactionProtoParserTest, parse) {
    const sp<IBinder> displayHandle = sp<BBinder>::make();
    TransactionState t1;
    t1.originPid = 1;
    t1.originUid = 2;
    t1.frameTimelineInfo.vsyncId = 3;
    t1.frameTimelineInfo.inputEventId = 4;
    t1.postTime = 5;

    layer_state_t layer;
    layer.what = std::numeric_limits<uint64_t>::max();
    layer.what &= ~static_cast<uint64_t>(layer_state_t::eBufferChanged);
    layer.x = 7;
    layer.matrix.dsdx = 15;

    size_t layerCount = 2;
    t1.states.reserve(layerCount);
    for (uint32_t i = 0; i < layerCount; i++) {
        ResolvedComposerState s;
        if (i == 1) {
            s.parentId = 42;
        }
        s.layerId = 6 + i;
        s.state = layer;
        t1.states.emplace_back(s);
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
        sp<IBinder> displayHandle;

        TestMapper(sp<IBinder> displayHandle) : displayHandle(displayHandle) {}

        sp<IBinder> getDisplayHandle(int32_t id) const {
            return (id == 43) ? displayHandle : nullptr;
        }
        int32_t getDisplayId(const sp<IBinder>& handle) const {
            return (handle == displayHandle) ? 43 : -1;
        }
    };

    TransactionProtoParser parser(std::make_unique<TestMapper>(displayHandle));

    perfetto::protos::TransactionState proto = parser.toProto(t1);
    TransactionState t2 = parser.fromProto(proto);

    ASSERT_EQ(t1.originPid, t2.originPid);
    ASSERT_EQ(t1.originUid, t2.originUid);
    ASSERT_EQ(t1.frameTimelineInfo.vsyncId, t2.frameTimelineInfo.vsyncId);
    ASSERT_EQ(t1.frameTimelineInfo.inputEventId, t2.frameTimelineInfo.inputEventId);
    ASSERT_EQ(t1.postTime, t2.postTime);
    ASSERT_EQ(t1.states.size(), t2.states.size());
    ASSERT_EQ(t1.states[0].state.x, t2.states[0].state.x);
    ASSERT_EQ(t1.states[0].state.matrix.dsdx, t2.states[0].state.matrix.dsdx);
    ASSERT_EQ(t1.states[1].layerId, t2.states[1].layerId);
    ASSERT_EQ(t1.states[1].parentId, t2.states[1].parentId);

    ASSERT_EQ(t1.displays.size(), t2.displays.size());
    ASSERT_EQ(t1.displays[1].width, t2.displays[1].width);
    ASSERT_EQ(t1.displays[0].token, t2.displays[0].token);
}

TEST(TransactionProtoParserTest, parseDisplayInfo) {
    frontend::DisplayInfo d1;
    d1.info.displayId = ui::LogicalDisplayId{42};
    d1.info.logicalWidth = 43;
    d1.info.logicalHeight = 44;
    d1.info.transform.set(1, 2, 3, 4);
    d1.transform = d1.info.transform.inverse();
    d1.receivesInput = true;
    d1.isSecure = false;
    d1.isPrimary = true;
    d1.isVirtual = false;
    d1.rotationFlags = ui::Transform::ROT_180;
    d1.transformHint = ui::Transform::ROT_90;

    const uint32_t layerStack = 2;
    google::protobuf::RepeatedPtrField<perfetto::protos::DisplayInfo> displayProtos;
    auto displayInfoProto = displayProtos.Add();
    *displayInfoProto = TransactionProtoParser::toProto(d1, layerStack);
    frontend::DisplayInfos displayInfos;
    TransactionProtoParser::fromProto(displayProtos, displayInfos);

    ASSERT_TRUE(displayInfos.contains(ui::LayerStack::fromValue(layerStack)));
    frontend::DisplayInfo d2 = displayInfos.get(ui::LayerStack::fromValue(layerStack))->get();
    EXPECT_EQ(d1.info.displayId, d2.info.displayId);
    EXPECT_EQ(d1.info.logicalWidth, d2.info.logicalWidth);
    EXPECT_EQ(d1.info.logicalHeight, d2.info.logicalHeight);

    EXPECT_EQ(d1.info.transform.dsdx(), d2.info.transform.dsdx());
    EXPECT_EQ(d1.info.transform.dsdy(), d2.info.transform.dsdy());
    EXPECT_EQ(d1.info.transform.dtdx(), d2.info.transform.dtdx());
    EXPECT_EQ(d1.info.transform.dtdy(), d2.info.transform.dtdy());

    EXPECT_EQ(d1.transform.dsdx(), d2.transform.dsdx());
    EXPECT_EQ(d1.transform.dsdy(), d2.transform.dsdy());
    EXPECT_EQ(d1.transform.dtdx(), d2.transform.dtdx());
    EXPECT_EQ(d1.transform.dtdy(), d2.transform.dtdy());

    EXPECT_EQ(d1.receivesInput, d2.receivesInput);
    EXPECT_EQ(d1.isSecure, d2.isSecure);
    EXPECT_EQ(d1.isVirtual, d2.isVirtual);
    EXPECT_EQ(d1.rotationFlags, d2.rotationFlags);
    EXPECT_EQ(d1.transformHint, d2.transformHint);
}

} // namespace android
