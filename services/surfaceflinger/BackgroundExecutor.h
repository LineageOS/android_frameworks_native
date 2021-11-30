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

#pragma once

#include <utils/Singleton.h>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

namespace android {

// Executes tasks off the main thread.
class BackgroundExecutor : public Singleton<BackgroundExecutor> {
public:
    BackgroundExecutor();
    ~BackgroundExecutor();
    void execute(std::function<void()>);

private:
    std::mutex mMutex;
    std::condition_variable mWorkAvailableCv;
    std::thread mThread;
    bool mDone = false;
    std::vector<std::function<void()>> mTasks;
};

} // namespace android
