/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <condition_variable>
#include <chrono>
#include <functional>
#include <mutex>
#include <thread>

#include <hidl/Status.h>

namespace android {
namespace lshal {

static constexpr std::chrono::milliseconds IPC_CALL_WAIT{500};

class BackgroundTaskState {
public:
    BackgroundTaskState(){}
    void notify() {
        std::unique_lock<std::mutex> lock(mMutex);
        mFinished = true;
        lock.unlock();
        mCondVar.notify_all();
    }
    template<class C, class D>
    bool wait(std::chrono::time_point<C, D> end) {
        std::unique_lock<std::mutex> lock(mMutex);
        mCondVar.wait_until(lock, end, [this](){ return this->mFinished; });
        return mFinished;
    }
private:
    std::mutex mMutex;
    std::condition_variable mCondVar;
    bool mFinished = false;
};

template<class R, class P>
bool timeout(std::chrono::duration<R, P> delay, const std::function<void(void)> &func) {
    auto now = std::chrono::system_clock::now();
    BackgroundTaskState state{};
    std::thread t([&state, &func] {
        func();
        state.notify();
    });
    t.detach();
    bool success = state.wait(now + delay);
    return success;
}

template<class Function, class I, class... Args>
typename std::result_of<Function(I *, Args...)>::type
timeoutIPC(const sp<I> &interfaceObject, Function &&func, Args &&... args) {
    using ::android::hardware::Status;
    typename std::result_of<Function(I *, Args...)>::type ret{Status::ok()};
    auto boundFunc = std::bind(std::forward<Function>(func),
            interfaceObject.get(), std::forward<Args>(args)...);
    bool success = timeout(IPC_CALL_WAIT, [&ret, &boundFunc] {
        ret = boundFunc();
    });
    if (!success) {
        return Status::fromStatusT(TIMED_OUT);
    }
    return ret;
}

}  // namespace lshal
}  // namespace android
