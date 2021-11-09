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

#include <fuzzer/FuzzedDataProvider.h>
#include "dispatcher/LatencyTracker.h"

namespace android {

namespace inputdispatcher {

/**
 * A processor of InputEventTimelines that does nothing with the provided data.
 */
class EmptyProcessor : public InputEventTimelineProcessor {
public:
    /**
     * Just ignore the provided timeline
     */
    void processTimeline(const InputEventTimeline& timeline) override {
        for (const auto& [token, connectionTimeline] : timeline.connectionTimelines) {
            connectionTimeline.isComplete();
        }
    };
};

static sp<IBinder> getConnectionToken(FuzzedDataProvider& fdp,
                                      std::array<sp<IBinder>, 10>& tokens) {
    const bool useExistingToken = fdp.ConsumeBool();
    if (useExistingToken) {
        return tokens[fdp.ConsumeIntegralInRange(0ul, tokens.size() - 1)];
    }
    return new BBinder();
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    EmptyProcessor emptyProcessor;
    LatencyTracker tracker(&emptyProcessor);

    // Make some pre-defined tokens to ensure that some timelines are complete.
    std::array<sp<IBinder> /*token*/, 10> predefinedTokens;
    for (size_t i = 0; i < predefinedTokens.size(); i++) {
        predefinedTokens[i] = new BBinder();
    }

    // Randomly invoke LatencyTracker api's until randomness is exhausted.
    while (fdp.remaining_bytes() > 0) {
        fdp.PickValueInArray<std::function<void()>>({
                [&]() -> void {
                    int32_t inputEventId = fdp.ConsumeIntegral<int32_t>();
                    int32_t isDown = fdp.ConsumeBool();
                    nsecs_t eventTime = fdp.ConsumeIntegral<nsecs_t>();
                    nsecs_t readTime = fdp.ConsumeIntegral<nsecs_t>();
                    tracker.trackListener(inputEventId, isDown, eventTime, readTime);
                },
                [&]() -> void {
                    int32_t inputEventId = fdp.ConsumeIntegral<int32_t>();
                    sp<IBinder> connectionToken = getConnectionToken(fdp, predefinedTokens);
                    nsecs_t deliveryTime = fdp.ConsumeIntegral<nsecs_t>();
                    nsecs_t consumeTime = fdp.ConsumeIntegral<nsecs_t>();
                    nsecs_t finishTime = fdp.ConsumeIntegral<nsecs_t>();
                    tracker.trackFinishedEvent(inputEventId, connectionToken, deliveryTime,
                                               consumeTime, finishTime);
                },
                [&]() -> void {
                    int32_t inputEventId = fdp.ConsumeIntegral<int32_t>();
                    sp<IBinder> connectionToken = getConnectionToken(fdp, predefinedTokens);
                    std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline;
                    for (size_t i = 0; i < graphicsTimeline.size(); i++) {
                        graphicsTimeline[i] = fdp.ConsumeIntegral<nsecs_t>();
                    }
                    tracker.trackGraphicsLatency(inputEventId, connectionToken, graphicsTimeline);
                },
        })();
    }

    return 0;
}

} // namespace inputdispatcher

} // namespace android