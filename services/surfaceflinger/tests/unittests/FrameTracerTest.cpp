/*
 * Copyright 2019 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <FrameTracer/FrameTracer.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <perfetto/trace/trace.pb.h>

#include "libsurfaceflinger_unittest_main.h"

using namespace google::protobuf;

namespace android {
namespace {

class FrameTracerTest : public testing::Test {
public:
    FrameTracerTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Setting up for %s.%s\n", test_info->test_case_name(), test_info->name());

        // Need to initialize tracing in process for testing, and only once per test suite.
        static bool wasInitialized = false;
        if (!wasInitialized) {
            perfetto::TracingInitArgs args;
            args.backends = perfetto::kInProcessBackend;
            perfetto::Tracing::Initialize(args);
            wasInitialized = true;
        }
    }

    ~FrameTracerTest() {
        const ::testing::TestInfo* const test_info =
                ::testing::UnitTest::GetInstance()->current_test_info();
        ALOGD("**** Tearing down after %s.%s\n", test_info->test_case_name(), test_info->name());
    }

    void SetUp() override {
        mFrameTracer = std::make_unique<FrameTracer>();
        mFrameTracer->registerDataSource();
    }

    void TearDown() override { mFrameTracer.reset(); }

    // Each tracing session can be used for a single block of Start -> Stop.
    static std::unique_ptr<perfetto::TracingSession> getTracingSessionForTest() {
        perfetto::TraceConfig cfg;
        cfg.set_duration_ms(500);
        cfg.add_buffers()->set_size_kb(1024);
        auto* ds_cfg = cfg.add_data_sources()->mutable_config();
        ds_cfg->set_name(FrameTracer::kFrameTracerDataSource);

        auto tracingSession = perfetto::Tracing::NewTrace(perfetto::kInProcessBackend);
        tracingSession->Setup(cfg);
        return tracingSession;
    }

    std::unique_ptr<FrameTracer> mFrameTracer;
    FenceToFenceTimeMap fenceFactory;
};

TEST_F(FrameTracerTest, traceNewLayerStartsTrackingLayerWhenTracing) {
    EXPECT_EQ(mFrameTracer->miniDump(),
              "FrameTracer miniDump:\nNumber of layers currently being traced is 0\n");

    const std::string layerName = "co.layername#0";
    const int32_t layerId = 5;
    mFrameTracer->traceNewLayer(layerId, layerName);

    EXPECT_EQ(mFrameTracer->miniDump(),
              "FrameTracer miniDump:\nNumber of layers currently being traced is 0\n");

    auto tracingSession = getTracingSessionForTest();
    tracingSession->StartBlocking();
    EXPECT_EQ(mFrameTracer->miniDump(),
              "FrameTracer miniDump:\nNumber of layers currently being traced is 0\n");
    mFrameTracer->traceNewLayer(layerId, layerName);
    EXPECT_EQ(mFrameTracer->miniDump(),
              "FrameTracer miniDump:\nNumber of layers currently being traced is 1\n");
    tracingSession->StopBlocking();
}

TEST_F(FrameTracerTest, onDestroyRemovesTheTrackedLayer) {
    EXPECT_EQ(mFrameTracer->miniDump(),
              "FrameTracer miniDump:\nNumber of layers currently being traced is 0\n");

    const std::string layerName = "co.layername#0";
    const int32_t layerId = 5;
    const int32_t secondlayerId = 6;

    auto tracingSession = getTracingSessionForTest();
    tracingSession->StartBlocking();
    mFrameTracer->traceNewLayer(layerId, layerName);
    mFrameTracer->traceNewLayer(secondlayerId, layerName);
    EXPECT_EQ(mFrameTracer->miniDump(),
              "FrameTracer miniDump:\nNumber of layers currently being traced is 2\n");
    tracingSession->StopBlocking();

    mFrameTracer->onDestroy(layerId);
    EXPECT_EQ(mFrameTracer->miniDump(),
              "FrameTracer miniDump:\nNumber of layers currently being traced is 1\n");
    mFrameTracer->onDestroy(layerId);
    EXPECT_EQ(mFrameTracer->miniDump(),
              "FrameTracer miniDump:\nNumber of layers currently being traced is 1\n");
    mFrameTracer->onDestroy(secondlayerId);
    EXPECT_EQ(mFrameTracer->miniDump(),
              "FrameTracer miniDump:\nNumber of layers currently being traced is 0\n");
}

TEST_F(FrameTracerTest, canTraceAfterAddingLayer) {
    const std::string layerName = "co.layername#0";
    const int32_t layerId = 1;
    const uint32_t bufferID = 2;
    const uint64_t frameNumber = 3;
    const nsecs_t timestamp = 4;
    const nsecs_t duration = 5;
    const auto type = FrameTracer::FrameEvent::POST;

    {
        auto tracingSession = getTracingSessionForTest();

        tracingSession->StartBlocking();
        // Clean up irrelevant traces.
        tracingSession->ReadTraceBlocking();

        mFrameTracer->traceTimestamp(layerId, bufferID, frameNumber, timestamp, type, duration);
        // Create second trace packet to finalize the previous one.
        mFrameTracer->traceTimestamp(layerId, 0, 0, 0, FrameTracer::FrameEvent::UNSPECIFIED);
        tracingSession->StopBlocking();

        std::vector<char> raw_trace = tracingSession->ReadTraceBlocking();
        EXPECT_EQ(raw_trace.size(), 0);
    }

    {
        auto tracingSession = getTracingSessionForTest();

        tracingSession->StartBlocking();
        // Clean up irrelevant traces.
        tracingSession->ReadTraceBlocking();

        mFrameTracer->traceNewLayer(layerId, layerName);
        mFrameTracer->traceTimestamp(layerId, bufferID, frameNumber, timestamp, type, duration);
        // Create second trace packet to finalize the previous one.
        mFrameTracer->traceTimestamp(layerId, 0, 0, 0, FrameTracer::FrameEvent::UNSPECIFIED);
        tracingSession->StopBlocking();

        std::vector<char> raw_trace = tracingSession->ReadTraceBlocking();
        ASSERT_GT(raw_trace.size(), 0);

        perfetto::protos::Trace trace;
        ASSERT_TRUE(trace.ParseFromArray(raw_trace.data(), int(raw_trace.size())));
        ASSERT_FALSE(trace.packet().empty());
        EXPECT_EQ(trace.packet().size(), 1);

        const auto& packet = trace.packet().Get(0);
        ASSERT_TRUE(packet.has_timestamp());
        EXPECT_EQ(packet.timestamp(), timestamp);
        ASSERT_TRUE(packet.has_graphics_frame_event());
        const auto& frame_event = packet.graphics_frame_event();
        ASSERT_TRUE(frame_event.has_buffer_event());
        const auto& buffer_event = frame_event.buffer_event();
        ASSERT_TRUE(buffer_event.has_buffer_id());
        EXPECT_EQ(buffer_event.buffer_id(), bufferID);
        ASSERT_TRUE(buffer_event.has_frame_number());
        EXPECT_EQ(buffer_event.frame_number(), frameNumber);
        ASSERT_TRUE(buffer_event.has_type());
        EXPECT_EQ(buffer_event.type(), perfetto::protos::GraphicsFrameEvent_BufferEventType(type));
        ASSERT_TRUE(buffer_event.has_duration_ns());
        EXPECT_EQ(buffer_event.duration_ns(), duration);
    }
}

TEST_F(FrameTracerTest, traceFenceTriggersOnNextTraceAfterFenceFired) {
    const std::string layerName = "co.layername#0";
    const int32_t layerId = 5;
    const uint32_t bufferID = 4;
    const uint64_t frameNumber = 3;
    const auto type = FrameTracer::FrameEvent::ACQUIRE_FENCE;

    {
        auto fenceTime = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
        fenceFactory.signalAllForTest(Fence::NO_FENCE, Fence::SIGNAL_TIME_PENDING);
        auto tracingSession = getTracingSessionForTest();
        tracingSession->StartBlocking();
        // Clean up irrelevant traces.
        tracingSession->ReadTraceBlocking();
        // Trace.
        mFrameTracer->traceNewLayer(layerId, layerName);
        mFrameTracer->traceFence(layerId, bufferID, frameNumber, fenceTime, type);
        // Create extra trace packet to (hopefully not) trigger and finalize the fence packet.
        mFrameTracer->traceTimestamp(layerId, bufferID, 0, 0, FrameTracer::FrameEvent::UNSPECIFIED);
        tracingSession->StopBlocking();
        std::vector<char> raw_trace = tracingSession->ReadTraceBlocking();
        EXPECT_EQ(raw_trace.size(), 0);
    }

    {
        auto fenceTime = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
        auto tracingSession = getTracingSessionForTest();
        tracingSession->StartBlocking();
        // Clean up irrelevant traces.
        tracingSession->ReadTraceBlocking();
        mFrameTracer->traceNewLayer(layerId, layerName);
        mFrameTracer->traceFence(layerId, bufferID, frameNumber, fenceTime, type);
        const nsecs_t timestamp = systemTime();
        fenceFactory.signalAllForTest(Fence::NO_FENCE, timestamp);
        // Create extra trace packet to trigger and finalize fence trace packets.
        mFrameTracer->traceTimestamp(layerId, bufferID, 0, 0, FrameTracer::FrameEvent::UNSPECIFIED);
        tracingSession->StopBlocking();

        std::vector<char> raw_trace = tracingSession->ReadTraceBlocking();
        ASSERT_GT(raw_trace.size(), 0);

        perfetto::protos::Trace trace;
        ASSERT_TRUE(trace.ParseFromArray(raw_trace.data(), int(raw_trace.size())));
        ASSERT_FALSE(trace.packet().empty());
        EXPECT_EQ(trace.packet().size(), 2); // Two packets because of the extra trace made above.

        const auto& packet = trace.packet().Get(1);
        ASSERT_TRUE(packet.has_timestamp());
        EXPECT_EQ(packet.timestamp(), timestamp);
        ASSERT_TRUE(packet.has_graphics_frame_event());
        const auto& frame_event = packet.graphics_frame_event();
        ASSERT_TRUE(frame_event.has_buffer_event());
        const auto& buffer_event = frame_event.buffer_event();
        ASSERT_TRUE(buffer_event.has_buffer_id());
        EXPECT_EQ(buffer_event.buffer_id(), bufferID);
        ASSERT_TRUE(buffer_event.has_frame_number());
        EXPECT_EQ(buffer_event.frame_number(), frameNumber);
        ASSERT_TRUE(buffer_event.has_type());
        EXPECT_EQ(buffer_event.type(), perfetto::protos::GraphicsFrameEvent_BufferEventType(type));
        EXPECT_FALSE(buffer_event.has_duration_ns());
    }
}

TEST_F(FrameTracerTest, traceFenceWithStartTimeAfterSignalTime_ShouldHaveNoDuration) {
    const std::string layerName = "co.layername#0";
    const int32_t layerId = 5;
    const uint32_t bufferID = 4;
    const uint64_t frameNumber = 3;
    const auto type = FrameTracer::FrameEvent::ACQUIRE_FENCE;

    auto tracingSession = getTracingSessionForTest();

    tracingSession->StartBlocking();
    // Clean up irrelevant traces.
    tracingSession->ReadTraceBlocking();
    mFrameTracer->traceNewLayer(layerId, layerName);

    // traceFence called after fence signalled.
    const nsecs_t signalTime1 = systemTime();
    const nsecs_t startTime1 = signalTime1 + 100000;
    auto fence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    fenceFactory.signalAllForTest(Fence::NO_FENCE, signalTime1);
    mFrameTracer->traceFence(layerId, bufferID, frameNumber, fence1, type, startTime1);

    // traceFence called before fence signalled.
    const nsecs_t signalTime2 = systemTime();
    const nsecs_t startTime2 = signalTime2 + 100000;
    auto fence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    mFrameTracer->traceFence(layerId, bufferID, frameNumber, fence2, type, startTime2);
    fenceFactory.signalAllForTest(Fence::NO_FENCE, signalTime2);

    // Create extra trace packet to trigger and finalize fence trace packets.
    mFrameTracer->traceTimestamp(layerId, bufferID, 0, 0, FrameTracer::FrameEvent::UNSPECIFIED);
    tracingSession->StopBlocking();

    std::vector<char> raw_trace = tracingSession->ReadTraceBlocking();
    ASSERT_GT(raw_trace.size(), 0);

    perfetto::protos::Trace trace;
    ASSERT_TRUE(trace.ParseFromArray(raw_trace.data(), int(raw_trace.size())));
    ASSERT_FALSE(trace.packet().empty());
    EXPECT_EQ(trace.packet().size(), 2);

    const auto& packet1 = trace.packet().Get(0);
    ASSERT_TRUE(packet1.has_timestamp());
    EXPECT_EQ(packet1.timestamp(), signalTime1);
    ASSERT_TRUE(packet1.has_graphics_frame_event());
    ASSERT_TRUE(packet1.graphics_frame_event().has_buffer_event());
    ASSERT_FALSE(packet1.graphics_frame_event().buffer_event().has_duration_ns());

    const auto& packet2 = trace.packet().Get(1);
    ASSERT_TRUE(packet2.has_timestamp());
    EXPECT_EQ(packet2.timestamp(), signalTime2);
    ASSERT_TRUE(packet2.has_graphics_frame_event());
    ASSERT_TRUE(packet2.graphics_frame_event().has_buffer_event());
    ASSERT_FALSE(packet2.graphics_frame_event().buffer_event().has_duration_ns());
}

TEST_F(FrameTracerTest, traceFenceOlderThanDeadline_ShouldBeIgnored) {
    const std::string layerName = "co.layername#0";
    const int32_t layerId = 5;
    const uint32_t bufferID = 4;
    const uint64_t frameNumber = 3;
    const auto type = FrameTracer::FrameEvent::ACQUIRE_FENCE;
    const nsecs_t signalTime = systemTime() - FrameTracer::kFenceSignallingDeadline;

    auto tracingSession = getTracingSessionForTest();
    auto fence = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);

    tracingSession->StartBlocking();
    // Clean up irrelevant traces.
    tracingSession->ReadTraceBlocking();
    mFrameTracer->traceNewLayer(layerId, layerName);
    mFrameTracer->traceFence(layerId, bufferID, frameNumber, fence, type);
    fenceFactory.signalAllForTest(Fence::NO_FENCE, signalTime);
    // Create extra trace packet to trigger and finalize any previous fence packets.
    mFrameTracer->traceTimestamp(layerId, bufferID, 0, 0, FrameTracer::FrameEvent::UNSPECIFIED);
    tracingSession->StopBlocking();

    std::vector<char> raw_trace = tracingSession->ReadTraceBlocking();
    EXPECT_EQ(raw_trace.size(), 0);
}

TEST_F(FrameTracerTest, traceFenceWithValidStartTime_ShouldHaveCorrectDuration) {
    const std::string layerName = "co.layername#0";
    const int32_t layerId = 5;
    const uint32_t bufferID = 4;
    const uint64_t frameNumber = 3;
    const auto type = FrameTracer::FrameEvent::ACQUIRE_FENCE;
    const nsecs_t duration = 1234;

    auto tracingSession = getTracingSessionForTest();

    tracingSession->StartBlocking();
    // Clean up irrelevant traces.
    tracingSession->ReadTraceBlocking();
    mFrameTracer->traceNewLayer(layerId, layerName);

    // traceFence called after fence signalled.
    const nsecs_t signalTime1 = systemTime();
    const nsecs_t startTime1 = signalTime1 - duration;
    auto fence1 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    fenceFactory.signalAllForTest(Fence::NO_FENCE, signalTime1);
    mFrameTracer->traceFence(layerId, bufferID, frameNumber, fence1, type, startTime1);

    // traceFence called before fence signalled.
    const nsecs_t signalTime2 = systemTime();
    const nsecs_t startTime2 = signalTime2 - duration;
    auto fence2 = fenceFactory.createFenceTimeForTest(Fence::NO_FENCE);
    mFrameTracer->traceFence(layerId, bufferID, frameNumber, fence2, type, startTime2);
    fenceFactory.signalAllForTest(Fence::NO_FENCE, signalTime2);

    // Create extra trace packet to trigger and finalize fence trace packets.
    mFrameTracer->traceTimestamp(layerId, bufferID, 0, 0, FrameTracer::FrameEvent::UNSPECIFIED);
    tracingSession->StopBlocking();

    std::vector<char> raw_trace = tracingSession->ReadTraceBlocking();
    ASSERT_GT(raw_trace.size(), 0);

    perfetto::protos::Trace trace;
    ASSERT_TRUE(trace.ParseFromArray(raw_trace.data(), int(raw_trace.size())));
    ASSERT_FALSE(trace.packet().empty());
    EXPECT_EQ(trace.packet().size(), 2);

    const auto& packet1 = trace.packet().Get(0);
    ASSERT_TRUE(packet1.has_timestamp());
    EXPECT_EQ(packet1.timestamp(), startTime1);
    ASSERT_TRUE(packet1.has_graphics_frame_event());
    ASSERT_TRUE(packet1.graphics_frame_event().has_buffer_event());
    ASSERT_TRUE(packet1.graphics_frame_event().buffer_event().has_duration_ns());
    const auto& buffer_event1 = packet1.graphics_frame_event().buffer_event();
    EXPECT_EQ(buffer_event1.duration_ns(), duration);

    const auto& packet2 = trace.packet().Get(1);
    ASSERT_TRUE(packet2.has_timestamp());
    EXPECT_EQ(packet2.timestamp(), startTime2);
    ASSERT_TRUE(packet2.has_graphics_frame_event());
    ASSERT_TRUE(packet2.graphics_frame_event().has_buffer_event());
    ASSERT_TRUE(packet2.graphics_frame_event().buffer_event().has_duration_ns());
    const auto& buffer_event2 = packet2.graphics_frame_event().buffer_event();
    EXPECT_EQ(buffer_event2.duration_ns(), duration);
}

} // namespace
} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
