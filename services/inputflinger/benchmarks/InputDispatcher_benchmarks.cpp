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

#include <benchmark/benchmark.h>

#include <android/os/IInputConstants.h>
#include <binder/Binder.h>
#include "../dispatcher/InputDispatcher.h"
#include "../tests/FakeApplicationHandle.h"
#include "../tests/FakeInputDispatcherPolicy.h"
#include "../tests/FakeWindows.h"

using android::base::Result;
using android::gui::WindowInfo;
using android::os::IInputConstants;
using android::os::InputEventInjectionResult;
using android::os::InputEventInjectionSync;

namespace android::inputdispatcher {

namespace {

// An arbitrary device id.
constexpr DeviceId DEVICE_ID = 1;

// An arbitrary display id
constexpr ui::LogicalDisplayId DISPLAY_ID = ui::LogicalDisplayId::DEFAULT;

static constexpr std::chrono::duration INJECT_EVENT_TIMEOUT = 5s;

static nsecs_t now() {
    return systemTime(SYSTEM_TIME_MONOTONIC);
}

static MotionEvent generateMotionEvent() {
    PointerProperties pointerProperties[1];
    PointerCoords pointerCoords[1];

    pointerProperties[0].clear();
    pointerProperties[0].id = 0;
    pointerProperties[0].toolType = ToolType::FINGER;

    pointerCoords[0].clear();
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, 100);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, 100);

    const nsecs_t currentTime = now();

    ui::Transform identityTransform;
    MotionEvent event;
    event.initialize(IInputConstants::INVALID_INPUT_EVENT_ID, DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN,
                     ui::LogicalDisplayId::DEFAULT, INVALID_HMAC, AMOTION_EVENT_ACTION_DOWN,
                     /* actionButton */ 0, /* flags */ 0,
                     /* edgeFlags */ 0, AMETA_NONE, /* buttonState */ 0, MotionClassification::NONE,
                     identityTransform, /* xPrecision */ 0,
                     /* yPrecision */ 0, AMOTION_EVENT_INVALID_CURSOR_POSITION,
                     AMOTION_EVENT_INVALID_CURSOR_POSITION, identityTransform, currentTime,
                     currentTime,
                     /*pointerCount*/ 1, pointerProperties, pointerCoords);
    return event;
}

static NotifyMotionArgs generateMotionArgs() {
    PointerProperties pointerProperties[1];
    PointerCoords pointerCoords[1];

    pointerProperties[0].clear();
    pointerProperties[0].id = 0;
    pointerProperties[0].toolType = ToolType::FINGER;

    pointerCoords[0].clear();
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_X, 100);
    pointerCoords[0].setAxisValue(AMOTION_EVENT_AXIS_Y, 100);

    const nsecs_t currentTime = now();
    // Define a valid motion event.
    NotifyMotionArgs args(IInputConstants::INVALID_INPUT_EVENT_ID, currentTime, currentTime,
                          DEVICE_ID, AINPUT_SOURCE_TOUCHSCREEN, ui::LogicalDisplayId::DEFAULT,
                          POLICY_FLAG_PASS_TO_USER, AMOTION_EVENT_ACTION_DOWN,
                          /* actionButton */ 0, /* flags */ 0, AMETA_NONE, /* buttonState */ 0,
                          MotionClassification::NONE, AMOTION_EVENT_EDGE_FLAG_NONE, 1,
                          pointerProperties, pointerCoords,
                          /* xPrecision */ 0, /* yPrecision */ 0,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION,
                          AMOTION_EVENT_INVALID_CURSOR_POSITION, currentTime, /* videoFrames */ {});

    return args;
}

static void benchmarkNotifyMotion(benchmark::State& state) {
    // Create dispatcher
    FakeInputDispatcherPolicy fakePolicy;
    auto dispatcher = std::make_unique<InputDispatcher>(fakePolicy);
    dispatcher->setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
    dispatcher->start();

    // Create a window that will receive motion events
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, dispatcher, "Fake Window", DISPLAY_ID);

    dispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});

    NotifyMotionArgs motionArgs = generateMotionArgs();

    for (auto _ : state) {
        // Send ACTION_DOWN
        motionArgs.action = AMOTION_EVENT_ACTION_DOWN;
        motionArgs.downTime = now();
        motionArgs.eventTime = motionArgs.downTime;
        dispatcher->notifyMotion(motionArgs);

        // Send ACTION_UP
        motionArgs.action = AMOTION_EVENT_ACTION_UP;
        motionArgs.eventTime = now();
        dispatcher->notifyMotion(motionArgs);

        window->consumeMotionEvent();
        window->consumeMotionEvent();
    }

    dispatcher->stop();
}

static void benchmarkInjectMotion(benchmark::State& state) {
    // Create dispatcher
    FakeInputDispatcherPolicy fakePolicy;
    auto dispatcher = std::make_unique<InputDispatcher>(fakePolicy);
    dispatcher->setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
    dispatcher->start();

    // Create a window that will receive motion events
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, dispatcher, "Fake Window", DISPLAY_ID);

    dispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});

    for (auto _ : state) {
        MotionEvent event = generateMotionEvent();
        // Send ACTION_DOWN
        dispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                     INJECT_EVENT_TIMEOUT,
                                     POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);

        // Send ACTION_UP
        event.setAction(AMOTION_EVENT_ACTION_UP);
        dispatcher->injectInputEvent(&event, /*targetUid=*/{}, InputEventInjectionSync::NONE,
                                     INJECT_EVENT_TIMEOUT,
                                     POLICY_FLAG_FILTERED | POLICY_FLAG_PASS_TO_USER);

        window->consumeMotionEvent();
        window->consumeMotionEvent();
    }

    dispatcher->stop();
}

static void benchmarkOnWindowInfosChanged(benchmark::State& state) {
    // Create dispatcher
    FakeInputDispatcherPolicy fakePolicy;
    auto dispatcher = std::make_unique<InputDispatcher>(fakePolicy);
    dispatcher->setInputDispatchMode(/*enabled*/ true, /*frozen*/ false);
    dispatcher->start();

    // Create a window
    std::shared_ptr<FakeApplicationHandle> application = std::make_shared<FakeApplicationHandle>();
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make(application, dispatcher, "Fake Window", DISPLAY_ID);

    std::vector<gui::WindowInfo> windowInfos{*window->getInfo()};
    gui::DisplayInfo info;
    info.displayId = window->getInfo()->displayId;
    std::vector<gui::DisplayInfo> displayInfos{info};

    for (auto _ : state) {
        dispatcher->onWindowInfosChanged(
                {windowInfos, displayInfos, /*vsyncId=*/0, /*timestamp=*/0});
        dispatcher->onWindowInfosChanged(
                {/*windowInfos=*/{}, /*displayInfos=*/{}, /*vsyncId=*/{}, /*timestamp=*/0});
    }
    dispatcher->stop();
}

} // namespace

BENCHMARK(benchmarkNotifyMotion);
BENCHMARK(benchmarkInjectMotion);
BENCHMARK(benchmarkOnWindowInfosChanged);

} // namespace android::inputdispatcher

BENCHMARK_MAIN();
