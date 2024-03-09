/*
 * Copyright (C) 2024 The Android Open Source Project
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

#define LOG_TAG "Choreographer_test"

#include <android-base/stringprintf.h>
#include <android/choreographer.h>
#include <gtest/gtest.h>
#include <gui/Choreographer.h>
#include <utils/Looper.h>
#include <chrono>
#include <future>
#include <string>

namespace android {
class ChoreographerTest : public ::testing::Test {};

struct VsyncCallback {
    std::atomic<bool> completePromise{false};
    std::chrono::nanoseconds frameTime{0LL};
    std::chrono::nanoseconds receivedCallbackTime{0LL};

    void onVsyncCallback(const AChoreographerFrameCallbackData* callbackData) {
        frameTime = std::chrono::nanoseconds{
                AChoreographerFrameCallbackData_getFrameTimeNanos(callbackData)};
        receivedCallbackTime = std::chrono::nanoseconds{systemTime(SYSTEM_TIME_MONOTONIC)};
        completePromise.store(true);
    }

    bool callbackReceived() { return completePromise.load(); }
};

static void vsyncCallback(const AChoreographerFrameCallbackData* callbackData, void* data) {
    VsyncCallback* cb = static_cast<VsyncCallback*>(data);
    cb->onVsyncCallback(callbackData);
}

TEST_F(ChoreographerTest, InputCallbackBeforeAnimation) {
    sp<Looper> looper = Looper::prepare(0);
    Choreographer* choreographer = Choreographer::getForThread();
    VsyncCallback animationCb;
    VsyncCallback inputCb;

    choreographer->postFrameCallbackDelayed(nullptr, nullptr, vsyncCallback, &animationCb, 0,
                                            CALLBACK_ANIMATION);
    choreographer->postFrameCallbackDelayed(nullptr, nullptr, vsyncCallback, &inputCb, 0,
                                            CALLBACK_INPUT);

    nsecs_t startTime = systemTime(SYSTEM_TIME_MONOTONIC);
    nsecs_t currTime;
    int pollResult;
    do {
        pollResult = looper->pollOnce(16);
        currTime = systemTime(SYSTEM_TIME_MONOTONIC);
    } while (!(inputCb.callbackReceived() && animationCb.callbackReceived()) &&
             (pollResult != Looper::POLL_TIMEOUT && pollResult != Looper::POLL_ERROR) &&
             (currTime - startTime < 3000));

    ASSERT_TRUE(inputCb.callbackReceived()) << "did not receive input callback";
    ASSERT_TRUE(animationCb.callbackReceived()) << "did not receive animation callback";

    ASSERT_EQ(inputCb.frameTime, animationCb.frameTime)
            << android::base::StringPrintf("input and animation callback frame times don't match. "
                                           "inputFrameTime=%lld  animationFrameTime=%lld",
                                           inputCb.frameTime.count(),
                                           animationCb.frameTime.count());

    ASSERT_LT(inputCb.receivedCallbackTime, animationCb.receivedCallbackTime)
            << android::base::StringPrintf("input callback was not called first. "
                                           "inputCallbackTime=%lld  animationCallbackTime=%lld",
                                           inputCb.frameTime.count(),
                                           animationCb.frameTime.count());
}

} // namespace android