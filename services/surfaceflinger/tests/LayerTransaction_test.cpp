/*
 * Copyright (C) 2019 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#include <thread>
#include "LayerTransactionTest.h"

namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

TEST_F(LayerTransactionTest, SetTransformToDisplayInverse_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    Transaction().setTransformToDisplayInverse(layer, false).apply();

    ASSERT_NO_FATAL_FAILURE(fillBufferLayerColor(layer, Color::GREEN, 32, 32));

    Transaction().setTransformToDisplayInverse(layer, true).apply();
}

TEST_F(LayerTransactionTest, SetSidebandStreamNull_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    // verify this doesn't cause a crash
    Transaction().setSidebandStream(layer, nullptr).apply();
}

TEST_F(LayerTransactionTest, ReparentToSelf) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));
    Transaction().reparent(layer, layer).apply();

    {
        // We expect the transaction to be silently dropped, but for SurfaceFlinger
        // to still be functioning.
        SCOPED_TRACE("after reparent to self");
        const Rect rect(0, 0, 32, 32);
        auto shot = screenshot();
        shot->expectColor(rect, Color::RED);
        shot->expectBorder(rect, Color::BLACK);
    }
}

// This test ensures that when we drop an app buffer in SurfaceFlinger, we merge
// the dropped buffer's damage region into the next buffer's damage region. If
// we don't do this, we'll report an incorrect damage region to hardware
// composer, resulting in broken rendering. This test checks the BufferQueue
// case.
//
// Unfortunately, we don't currently have a way to inspect the damage region
// SurfaceFlinger sends to hardware composer from a test, so this test requires
// the dev to manually watch the device's screen during the test to spot broken
// rendering. Because the results can't be automatically verified, this test is
// marked disabled.
TEST_F(LayerTransactionTest, DISABLED_BufferQueueLayerMergeDamageRegionWhenDroppingBuffers) {
    const int width = mDisplayWidth;
    const int height = mDisplayHeight;
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", width, height));
    const auto producer = layer->getIGraphicBufferProducer();
    const sp<IProducerListener> stubListener(sp<StubProducerListener>::make());
    IGraphicBufferProducer::QueueBufferOutput queueBufferOutput;
    ASSERT_EQ(OK, producer->connect(stubListener, NATIVE_WINDOW_API_CPU, true, &queueBufferOutput));

    std::map<int, sp<GraphicBuffer>> slotMap;
    auto slotToBuffer = [&](int slot, sp<GraphicBuffer>* buf) {
        ASSERT_NE(nullptr, buf);
        const auto iter = slotMap.find(slot);
        ASSERT_NE(slotMap.end(), iter);
        *buf = iter->second;
    };

    auto dequeue = [&](int* outSlot) {
        ASSERT_NE(nullptr, outSlot);
        *outSlot = -1;
        int slot;
        sp<Fence> fence;
        uint64_t age;
        FrameEventHistoryDelta timestamps;
        const status_t dequeueResult =
                producer->dequeueBuffer(&slot, &fence, width, height, PIXEL_FORMAT_RGBA_8888,
                                        GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                                        &age, &timestamps);
        if (dequeueResult == IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION) {
            sp<GraphicBuffer> newBuf;
            ASSERT_EQ(OK, producer->requestBuffer(slot, &newBuf));
            ASSERT_NE(nullptr, newBuf.get());
            slotMap[slot] = newBuf;
        } else {
            ASSERT_EQ(OK, dequeueResult);
        }
        *outSlot = slot;
    };

    auto queue = [&](int slot, const Region& damage, nsecs_t displayTime) {
        IGraphicBufferProducer::QueueBufferInput input(
                /*timestamp=*/displayTime, /*isAutoTimestamp=*/false, HAL_DATASPACE_UNKNOWN,
                /*crop=*/Rect::EMPTY_RECT, NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW,
                /*transform=*/0, Fence::NO_FENCE);
        input.setSurfaceDamage(damage);
        IGraphicBufferProducer::QueueBufferOutput output;
        ASSERT_EQ(OK, producer->queueBuffer(slot, input, &output));
    };

    auto fillAndPostBuffers = [&](const Color& color) {
        int slot1;
        ASSERT_NO_FATAL_FAILURE(dequeue(&slot1));
        int slot2;
        ASSERT_NO_FATAL_FAILURE(dequeue(&slot2));

        sp<GraphicBuffer> buf1;
        ASSERT_NO_FATAL_FAILURE(slotToBuffer(slot1, &buf1));
        sp<GraphicBuffer> buf2;
        ASSERT_NO_FATAL_FAILURE(slotToBuffer(slot2, &buf2));
        TransactionUtils::fillGraphicBufferColor(buf1, Rect(width, height), color);
        TransactionUtils::fillGraphicBufferColor(buf2, Rect(width, height), color);

        const auto displayTime = systemTime() + milliseconds_to_nanoseconds(100);
        ASSERT_NO_FATAL_FAILURE(queue(slot1, Region::INVALID_REGION, displayTime));
        ASSERT_NO_FATAL_FAILURE(
                queue(slot2, Region(Rect(width / 3, height / 3, 2 * width / 3, 2 * height / 3)),
                      displayTime));
    };

    const auto startTime = systemTime();
    const std::array<Color, 3> colors = {Color::RED, Color::GREEN, Color::BLUE};
    int colorIndex = 0;
    while (nanoseconds_to_seconds(systemTime() - startTime) < 10) {
        ASSERT_NO_FATAL_FAILURE(fillAndPostBuffers(colors[colorIndex++ % colors.size()]));
        std::this_thread::sleep_for(1s);
    }

    ASSERT_EQ(OK, producer->disconnect(NATIVE_WINDOW_API_CPU));
}

// b/245052266 - we possible could support blur and a buffer at the same layer but
// might break existing assumptions at higher level. This test captures the current
// expectations. A layer drawing a buffer will not support blur.
TEST_F(LayerTransactionTest, BufferTakesPriorityOverBlur) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferLayerColor(layer, Color::RED, 32, 32));
    Transaction().setBackgroundBlurRadius(layer, 5).apply();
    {
        SCOPED_TRACE("BufferTakesPriorityOverBlur");
        const Rect rect(0, 0, 32, 32);
        auto shot = screenshot();
        shot->expectColor(rect, Color::RED);
    }
}

TEST_F(LayerTransactionTest, BufferTakesPriorityOverColor) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferLayerColor(layer, Color::RED, 32, 32));
    Transaction().setColor(layer, {Color::GREEN.r, Color::GREEN.g, Color::GREEN.b}).apply();
    {
        SCOPED_TRACE("BufferTakesPriorityOverColor");
        const Rect rect(0, 0, 32, 32);
        auto shot = screenshot();
        shot->expectColor(rect, Color::RED);
    }
}

TEST_F(LayerTransactionTest, CommitCallbackCalledOnce) {
    auto callCount = 0;
    auto commitCallback =
            [&callCount](void* /* context */, nsecs_t /* latchTime */,
                         const sp<Fence>& /* presentFence */,
                         const std::vector<SurfaceControlStats>& /* stats */) mutable {
                callCount++;
            };

    // Create two transactions that both contain the same callback id.
    Transaction t1;
    t1.addTransactionCommittedCallback(commitCallback, nullptr);
    Parcel parcel;
    t1.writeToParcel(&parcel);
    parcel.setDataPosition(0);
    Transaction t2;
    t2.readFromParcel(&parcel);

    // Apply the two transactions. There is a race here as we can't guarantee that the two
    // transactions will be applied within the same SurfaceFlinger commit. If the transactions are
    // applied within the same commit then we verify that callback ids are deduplicated within a
    // single commit. Otherwise, we verify that commit callbacks are deduplicated across separate
    // commits.
    t1.apply();
    t2.apply(/*synchronous=*/true);

    ASSERT_EQ(callCount, 1);
}

TEST_F(LayerTransactionTest, AddRemoveLayers) {
    for (int i = 0; i < 100; i++) {
        sp<SurfaceControl> layer;
        ASSERT_NO_FATAL_FAILURE(
                layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
        layer.clear();
    }
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
