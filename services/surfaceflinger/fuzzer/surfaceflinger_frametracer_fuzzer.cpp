/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <FrameTracer/FrameTracer.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <perfetto/trace/trace.pb.h>

namespace android::fuzz {

using namespace google::protobuf;

constexpr size_t kMaxStringSize = 256;
constexpr size_t kMinLayerIds = 1;
constexpr size_t kMaxLayerIds = 10;
constexpr int32_t kMinRange = 0;
constexpr int32_t kConfigDuration = 500;
constexpr int32_t kBufferSize = 1024;
constexpr int32_t kTimeOffset = 100000;

class FrameTracerFuzzer {
public:
    FrameTracerFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {
        // Fuzzer is single-threaded, so no need to be thread-safe.
        static bool wasInitialized = false;
        if (!wasInitialized) {
            perfetto::TracingInitArgs args;
            args.backends = perfetto::kInProcessBackend;
            perfetto::Tracing::Initialize(args);
            wasInitialized = true;
        }
        mFrameTracer = std::make_unique<android::FrameTracer>();
    }
    ~FrameTracerFuzzer() { mFrameTracer.reset(); }
    void process();

private:
    void traceTimestamp();
    void traceTimestamp(std::vector<int32_t> layerIds, size_t numLayerIds);
    void traceFence(std::vector<int32_t> layerIds, size_t numLayerIds);
    std::unique_ptr<perfetto::TracingSession> getTracingSessionForTest();
    std::unique_ptr<android::FrameTracer> mFrameTracer = nullptr;
    std::vector<int32_t> generateLayerIds(size_t numLayerIds);
    android::FenceToFenceTimeMap mFenceFactory;
    FuzzedDataProvider mFdp;
};

std::unique_ptr<perfetto::TracingSession> FrameTracerFuzzer::getTracingSessionForTest() {
    perfetto::TraceConfig cfg;
    cfg.set_duration_ms(mFdp.ConsumeIntegralInRange<int32_t>(kMinRange, kConfigDuration));
    cfg.add_buffers()->set_size_kb(mFdp.ConsumeIntegralInRange<int32_t>(kMinRange, kBufferSize));
    auto* dsCfg = cfg.add_data_sources()->mutable_config();
    dsCfg->set_name(android::FrameTracer::kFrameTracerDataSource);

    auto tracingSession = perfetto::Tracing::NewTrace(perfetto::kInProcessBackend);
    tracingSession->Setup(cfg);
    return tracingSession;
}

std::vector<int32_t> FrameTracerFuzzer::generateLayerIds(size_t numLayerIds) {
    std::vector<int32_t> layerIds;
    for (size_t i = 0; i < numLayerIds; ++i) {
        layerIds.push_back(mFdp.ConsumeIntegral<int32_t>());
    }
    return layerIds;
}

void FrameTracerFuzzer::traceTimestamp(std::vector<int32_t> layerIds, size_t numLayerIds) {
    uint32_t layerId = layerIds.at(mFdp.ConsumeIntegralInRange<size_t>(0, numLayerIds - 1));
    android::FrameTracer::FrameEvent::BufferEventType type = static_cast<
            android::FrameTracer::FrameEvent::BufferEventType>(
            mFdp.ConsumeIntegralInRange<uint32_t>(android::FrameTracer::FrameEvent::UNSPECIFIED,
                                                  android::FrameTracer::FrameEvent::CANCEL));
    mFrameTracer->traceTimestamp(layerId, mFdp.ConsumeIntegral<uint64_t>() /*bufferID*/,
                                 mFdp.ConsumeIntegral<uint64_t>() /*frameNumber*/,
                                 mFdp.ConsumeIntegral<nsecs_t>() /*timestamp*/, type,
                                 mFdp.ConsumeIntegral<nsecs_t>() /*duration*/);
}

void FrameTracerFuzzer::traceFence(std::vector<int32_t> layerIds, size_t numLayerIds) {
    const nsecs_t signalTime =
            mFdp.ConsumeBool() ? android::Fence::SIGNAL_TIME_PENDING : systemTime();
    const nsecs_t startTime = (signalTime == android::Fence::SIGNAL_TIME_PENDING)
            ? signalTime - kTimeOffset
            : signalTime + kTimeOffset;
    auto fence = mFenceFactory.createFenceTimeForTest(android::Fence::NO_FENCE);
    mFenceFactory.signalAllForTest(android::Fence::NO_FENCE, signalTime);
    int32_t layerId = layerIds.at(mFdp.ConsumeIntegralInRange<size_t>(0, numLayerIds - 1));
    mFrameTracer->traceFence(layerId, mFdp.ConsumeIntegral<uint64_t>() /*bufferID*/,
                             mFdp.ConsumeIntegral<uint64_t>() /*frameNumber*/, fence,
                             android::FrameTracer::FrameEvent::ACQUIRE_FENCE, startTime);
}

void FrameTracerFuzzer::process() {
    std::vector<int32_t> layerIds =
            generateLayerIds(mFdp.ConsumeIntegralInRange<size_t>(kMinLayerIds, kMaxLayerIds));

    std::unique_ptr<perfetto::TracingSession> tracingSession;
    while (mFdp.remaining_bytes()) {
        auto invokeFrametracerAPI = mFdp.PickValueInArray<const std::function<void()>>({
                [&]() { mFrameTracer->registerDataSource(); },
                [&]() {
                    if (tracingSession) {
                        tracingSession->StopBlocking();
                    }
                    tracingSession = getTracingSessionForTest();
                    tracingSession->StartBlocking();
                },
                [&]() { traceTimestamp(layerIds, layerIds.size()); },
                [&]() { traceFence(layerIds, layerIds.size()); },
                [&]() {
                    for (auto it = layerIds.begin(); it != layerIds.end(); ++it) {
                        mFrameTracer->traceNewLayer(*it /*layerId*/,
                                                    mFdp.ConsumeRandomLengthString(
                                                            kMaxStringSize) /*layerName*/);
                    }
                },
                [&]() { mFenceFactory.signalAllForTest(android::Fence::NO_FENCE, systemTime()); },
        });
        invokeFrametracerAPI();
    }

    for (auto it = layerIds.begin(); it != layerIds.end(); ++it) {
        mFrameTracer->onDestroy(*it);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FrameTracerFuzzer frameTracerFuzzer(data, size);
    frameTracerFuzzer.process();
    return 0;
}

} // namespace android::fuzz
