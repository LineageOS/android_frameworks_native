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

#include "BackgroundExecutor.h"

namespace android {

ANDROID_SINGLETON_STATIC_INSTANCE(BackgroundExecutor);

BackgroundExecutor::BackgroundExecutor() : Singleton<BackgroundExecutor>() {
    mThread = std::thread([&]() {
        bool done = false;
        while (!done) {
            std::vector<std::function<void()>> tasks;
            {
                std::unique_lock lock(mMutex);
                android::base::ScopedLockAssertion assumeLock(mMutex);
                mWorkAvailableCv.wait(lock,
                                      [&]() REQUIRES(mMutex) { return mDone || !mTasks.empty(); });
                tasks = std::move(mTasks);
                mTasks.clear();
                done = mDone;
            } // unlock mMutex

            for (auto& task : tasks) {
                task();
            }
        }
    });
}

BackgroundExecutor::~BackgroundExecutor() {
    {
        std::scoped_lock lock(mMutex);
        mDone = true;
        mWorkAvailableCv.notify_all();
    }
    if (mThread.joinable()) {
        mThread.join();
    }
}

void BackgroundExecutor::execute(std::function<void()> task) {
    std::scoped_lock lock(mMutex);
    mTasks.emplace_back(std::move(task));
    mWorkAvailableCv.notify_all();
}

} // namespace android