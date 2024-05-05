/*
 * Copyright 2023 The Android Open Source Project
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

#include <android-base/stringprintf.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "../FakeApplicationHandle.h"
#include "../FakeInputDispatcherPolicy.h"
#include "../FakeWindows.h"
#include "FuzzedInputStream.h"
#include "dispatcher/InputDispatcher.h"
#include "input/InputVerifier.h"

namespace android {

using android::base::Result;
using android::gui::WindowInfo;

namespace inputdispatcher {

namespace {

static constexpr int32_t MAX_RANDOM_DISPLAYS = 4;
static constexpr int32_t MAX_RANDOM_WINDOWS = 4;

/**
 * Provide a valid motion stream, to make the fuzzer more effective.
 */
class NotifyStreamProvider {
public:
    NotifyStreamProvider(FuzzedDataProvider& fdp)
          : mFdp(fdp), mIdGenerator(IdGenerator::Source::OTHER) {}

    std::optional<NotifyMotionArgs> nextMotion() {
        NotifyMotionArgs args = generateFuzzedMotionArgs(mIdGenerator, mFdp, MAX_RANDOM_DISPLAYS);
        auto [it, _] = mVerifiers.emplace(args.displayId, "Fuzz Verifier");
        InputVerifier& verifier = it->second;
        const Result<void> result =
                verifier.processMovement(args.deviceId, args.source, args.action,
                                         args.getPointerCount(), args.pointerProperties.data(),
                                         args.pointerCoords.data(), args.flags);
        if (result.ok()) {
            return args;
        }
        return {};
    }

private:
    FuzzedDataProvider& mFdp;

    IdGenerator mIdGenerator;

    std::map<int32_t /*displayId*/, InputVerifier> mVerifiers;
};

void scrambleWindow(FuzzedDataProvider& fdp, FakeWindowHandle& window) {
    const int32_t left = fdp.ConsumeIntegralInRange<int32_t>(0, 100);
    const int32_t top = fdp.ConsumeIntegralInRange<int32_t>(0, 100);
    const int32_t width = fdp.ConsumeIntegralInRange<int32_t>(0, 100);
    const int32_t height = fdp.ConsumeIntegralInRange<int32_t>(0, 100);

    window.setFrame(Rect(left, top, left + width, top + height));
    window.setSlippery(fdp.ConsumeBool());
    window.setDupTouchToWallpaper(fdp.ConsumeBool());
    window.setIsWallpaper(fdp.ConsumeBool());
    window.setVisible(fdp.ConsumeBool());
    window.setPreventSplitting(fdp.ConsumeBool());
    const bool isTrustedOverlay = fdp.ConsumeBool();
    window.setTrustedOverlay(isTrustedOverlay);
    if (isTrustedOverlay) {
        window.setSpy(fdp.ConsumeBool());
    } else {
        window.setSpy(false);
    }
}

} // namespace

sp<FakeWindowHandle> generateFuzzedWindow(FuzzedDataProvider& fdp,
                                          std::unique_ptr<InputDispatcher>& dispatcher,
                                          ui::LogicalDisplayId displayId) {
    static size_t windowNumber = 0;
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    std::string windowName = android::base::StringPrintf("Win") + std::to_string(windowNumber++);
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, dispatcher, windowName, displayId);

    scrambleWindow(fdp, *window);
    return window;
}

void randomizeWindows(std::unordered_map<ui::LogicalDisplayId, std::vector<sp<FakeWindowHandle>>>&
                              windowsPerDisplay,
                      FuzzedDataProvider& fdp, std::unique_ptr<InputDispatcher>& dispatcher) {
    const ui::LogicalDisplayId displayId{
            fdp.ConsumeIntegralInRange<int32_t>(0, MAX_RANDOM_DISPLAYS - 1)};
    std::vector<sp<FakeWindowHandle>>& windows = windowsPerDisplay[displayId];

    fdp.PickValueInArray<std::function<void()>>({
            // Add a new window
            [&]() -> void {
                if (windows.size() < MAX_RANDOM_WINDOWS) {
                    windows.push_back(generateFuzzedWindow(fdp, dispatcher, displayId));
                }
            },
            // Remove a window
            [&]() -> void {
                if (windows.empty()) {
                    return;
                }
                const int32_t erasedPosition =
                        fdp.ConsumeIntegralInRange<int32_t>(0, windows.size() - 1);

                windows.erase(windows.begin() + erasedPosition);
                if (windows.empty()) {
                    windowsPerDisplay.erase(displayId);
                }
            },
            // Change flags or move some of the existing windows
            [&]() -> void {
                for (auto& window : windows) {
                    if (fdp.ConsumeBool()) {
                        scrambleWindow(fdp, *window);
                    }
                }
            },
    })();
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    NotifyStreamProvider streamProvider(fdp);

    FakeInputDispatcherPolicy fakePolicy;
    auto dispatcher = std::make_unique<InputDispatcher>(fakePolicy);
    dispatcher->setInputDispatchMode(/*enabled=*/true, /*frozen=*/false);
    // Start InputDispatcher thread
    dispatcher->start();

    std::unordered_map<ui::LogicalDisplayId, std::vector<sp<FakeWindowHandle>>> windowsPerDisplay;

    // Randomly invoke InputDispatcher api's until randomness is exhausted.
    while (fdp.remaining_bytes() > 0) {
        fdp.PickValueInArray<std::function<void()>>({
                [&]() -> void {
                    std::optional<NotifyMotionArgs> motion = streamProvider.nextMotion();
                    if (motion) {
                        dispatcher->notifyMotion(*motion);
                    }
                },
                [&]() -> void {
                    // Scramble the windows we currently have
                    randomizeWindows(/*byref*/ windowsPerDisplay, fdp, dispatcher);

                    std::vector<WindowInfo> windowInfos;
                    for (const auto& [displayId, windows] : windowsPerDisplay) {
                        for (const sp<FakeWindowHandle>& window : windows) {
                            windowInfos.emplace_back(*window->getInfo());
                        }
                    }

                    dispatcher->onWindowInfosChanged(
                            {windowInfos, {}, /*vsyncId=*/0, /*timestamp=*/0});
                },
                // Consume on all the windows
                [&]() -> void {
                    for (const auto& [_, windows] : windowsPerDisplay) {
                        for (const sp<FakeWindowHandle>& window : windows) {
                            // To speed up the fuzzing, don't wait for consumption. If there's an
                            // event pending, this can be consumed on the next call instead.
                            // We also don't care about whether consumption succeeds here, or what
                            // kind of event is returned.
                            window->consume(0ms);
                        }
                    }
                },
        })();
    }

    dispatcher->stop();

    return 0;
}

} // namespace inputdispatcher

} // namespace android