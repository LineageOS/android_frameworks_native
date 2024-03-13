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

//#define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "BackgroundExecutor"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <processgroup/sched_policy.h>
#include <pthread.h>
#include <sched.h>
#include <utils/Log.h>
#include <mutex>

#include "BackgroundExecutor.h"

namespace android {

namespace {

void set_thread_priority(bool highPriority) {
    set_sched_policy(0, highPriority ? SP_FOREGROUND : SP_BACKGROUND);
    struct sched_param param = {0};
    param.sched_priority = highPriority ? 2 : 0 /* must be 0 for non-RT */;
    sched_setscheduler(gettid(), highPriority ? SCHED_FIFO : SCHED_NORMAL, &param);
}

} // anonymous namespace

BackgroundExecutor::BackgroundExecutor(bool highPriority) {
    // mSemaphore must be initialized before any calls to
    // BackgroundExecutor::sendCallbacks. For this reason, we initialize it
    // within the constructor instead of within mThread.
    LOG_ALWAYS_FATAL_IF(sem_init(&mSemaphore, 0, 0), "sem_init failed");
    mThread = std::thread([&, highPriority]() {
        set_thread_priority(highPriority);
        while (!mDone) {
            LOG_ALWAYS_FATAL_IF(sem_wait(&mSemaphore), "sem_wait failed (%d)", errno);
            auto callbacks = mCallbacksQueue.pop();
            if (!callbacks) {
                continue;
            }
            for (auto& callback : *callbacks) {
                callback();
            }
        }
    });
    if (highPriority) {
        pthread_setname_np(mThread.native_handle(), "BckgrndExec HP");
    } else {
        pthread_setname_np(mThread.native_handle(), "BckgrndExec LP");
    }
}

BackgroundExecutor::~BackgroundExecutor() {
    mDone = true;
    LOG_ALWAYS_FATAL_IF(sem_post(&mSemaphore), "sem_post failed");
    if (mThread.joinable()) {
        mThread.join();
        LOG_ALWAYS_FATAL_IF(sem_destroy(&mSemaphore), "sem_destroy failed");
    }
}

void BackgroundExecutor::sendCallbacks(Callbacks&& tasks) {
    mCallbacksQueue.push(std::move(tasks));
    LOG_ALWAYS_FATAL_IF(sem_post(&mSemaphore), "sem_post failed");
}

void BackgroundExecutor::flushQueue() {
    std::mutex mutex;
    std::condition_variable cv;
    bool flushComplete = false;
    sendCallbacks({[&]() {
        std::scoped_lock lock{mutex};
        flushComplete = true;
        cv.notify_one();
    }});
    std::unique_lock<std::mutex> lock{mutex};
    cv.wait(lock, [&]() { return flushComplete; });
}

} // namespace android
