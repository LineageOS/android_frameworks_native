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

#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <gui/FenceMonitor.h>
#include <gui/TraceUtils.h>
#include <log/log.h>

#include <thread>

namespace android::gui {

FenceMonitor::FenceMonitor(const char* name) : mName(name), mFencesQueued(0), mFencesSignaled(0) {
    std::thread thread(&FenceMonitor::loop, this);
    pthread_setname_np(thread.native_handle(), mName);
    thread.detach();
}

void FenceMonitor::queueFence(const sp<Fence>& fence) {
    char message[64];

    std::lock_guard<std::mutex> lock(mMutex);
    if (fence->getSignalTime() != Fence::SIGNAL_TIME_PENDING) {
        snprintf(message, sizeof(message), "%s fence %u has signaled", mName, mFencesQueued);
        ATRACE_NAME(message);
        // Need an increment on both to make the trace number correct.
        mFencesQueued++;
        mFencesSignaled++;
        return;
    }
    snprintf(message, sizeof(message), "Trace %s fence %u", mName, mFencesQueued);
    ATRACE_NAME(message);

    mQueue.push_back(fence);
    mCondition.notify_one();
    mFencesQueued++;
    ATRACE_INT(mName, int32_t(mQueue.size()));
}

void FenceMonitor::loop() {
    while (true) {
        threadLoop();
    }
}

void FenceMonitor::threadLoop() {
    sp<Fence> fence;
    uint32_t fenceNum;
    {
        std::unique_lock<std::mutex> lock(mMutex);
        while (mQueue.empty()) {
            mCondition.wait(lock);
        }
        fence = mQueue[0];
        fenceNum = mFencesSignaled;
    }
    {
        char message[64];
        snprintf(message, sizeof(message), "waiting for %s %u", mName, fenceNum);
        ATRACE_NAME(message);

        status_t result = fence->waitForever(message);
        if (result != OK) {
            ALOGE("Error waiting for fence: %d", result);
        }
    }
    {
        std::lock_guard<std::mutex> lock(mMutex);
        mQueue.pop_front();
        mFencesSignaled++;
        ATRACE_INT(mName, int32_t(mQueue.size()));
    }
}

} // namespace android::gui