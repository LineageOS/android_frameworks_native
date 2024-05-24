/*
 * Copyright 2020 The Android Open Source Project
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

#include "RenderEngineThreaded.h"

#include <sched.h>
#include <chrono>
#include <future>

#include <android-base/stringprintf.h>
#include <private/gui/SyncFeatures.h>
#include <processgroup/processgroup.h>
#include <utils/Trace.h>

using namespace std::chrono_literals;

namespace android {
namespace renderengine {
namespace threaded {

std::unique_ptr<RenderEngineThreaded> RenderEngineThreaded::create(CreateInstanceFactory factory) {
    return std::make_unique<RenderEngineThreaded>(std::move(factory));
}

RenderEngineThreaded::RenderEngineThreaded(CreateInstanceFactory factory)
      : RenderEngine(Threaded::YES) {
    ATRACE_CALL();

    std::lock_guard lockThread(mThreadMutex);
    mThread = std::thread(&RenderEngineThreaded::threadMain, this, factory);
}

RenderEngineThreaded::~RenderEngineThreaded() {
    mRunning = false;
    mCondition.notify_one();

    if (mThread.joinable()) {
        mThread.join();
    }
}

status_t RenderEngineThreaded::setSchedFifo(bool enabled) {
    static constexpr int kFifoPriority = 2;
    static constexpr int kOtherPriority = 0;

    struct sched_param param = {0};
    int sched_policy;
    if (enabled) {
        sched_policy = SCHED_FIFO;
        param.sched_priority = kFifoPriority;
    } else {
        sched_policy = SCHED_OTHER;
        param.sched_priority = kOtherPriority;
    }

    if (sched_setscheduler(0, sched_policy, &param) != 0) {
        return -errno;
    }
    return NO_ERROR;
}

// NO_THREAD_SAFETY_ANALYSIS is because std::unique_lock presently lacks thread safety annotations.
void RenderEngineThreaded::threadMain(CreateInstanceFactory factory) NO_THREAD_SAFETY_ANALYSIS {
    ATRACE_CALL();

    if (!SetTaskProfiles(0, {"SFRenderEnginePolicy"})) {
        ALOGW("Failed to set render-engine task profile!");
    }

    if (setSchedFifo(true) != NO_ERROR) {
        ALOGW("Couldn't set SCHED_FIFO");
    }

    mRenderEngine = factory();

    pthread_setname_np(pthread_self(), mThreadName);

    {
        std::scoped_lock lock(mInitializedMutex);
        mIsInitialized = true;
    }
    mInitializedCondition.notify_all();

    while (mRunning) {
        const auto getNextTask = [this]() -> std::optional<Work> {
            std::scoped_lock lock(mThreadMutex);
            if (!mFunctionCalls.empty()) {
                Work task = mFunctionCalls.front();
                mFunctionCalls.pop();
                return std::make_optional<Work>(task);
            }
            return std::nullopt;
        };

        const auto task = getNextTask();

        if (task) {
            (*task)(*mRenderEngine);
        }

        std::unique_lock<std::mutex> lock(mThreadMutex);
        mCondition.wait(lock, [this]() REQUIRES(mThreadMutex) {
            return !mRunning || !mFunctionCalls.empty();
        });
    }

    // we must release the RenderEngine on the thread that created it
    mRenderEngine.reset();
}

void RenderEngineThreaded::waitUntilInitialized() const {
    if (!mIsInitialized) {
        std::unique_lock<std::mutex> lock(mInitializedMutex);
        mInitializedCondition.wait(lock, [this] { return mIsInitialized.load(); });
    }
}

std::future<void> RenderEngineThreaded::primeCache(bool shouldPrimeUltraHDR) {
    const auto resultPromise = std::make_shared<std::promise<void>>();
    std::future<void> resultFuture = resultPromise->get_future();
    ATRACE_CALL();
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push(
                [resultPromise, shouldPrimeUltraHDR](renderengine::RenderEngine& instance) {
                    ATRACE_NAME("REThreaded::primeCache");
                    if (setSchedFifo(false) != NO_ERROR) {
                        ALOGW("Couldn't set SCHED_OTHER for primeCache");
                    }

                    instance.primeCache(shouldPrimeUltraHDR);
                    resultPromise->set_value();

                    if (setSchedFifo(true) != NO_ERROR) {
                        ALOGW("Couldn't set SCHED_FIFO for primeCache");
                    }
                });
    }
    mCondition.notify_one();

    return resultFuture;
}

void RenderEngineThreaded::dump(std::string& result) {
    std::promise<std::string> resultPromise;
    std::future<std::string> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, &result](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::dump");
            std::string localResult = result;
            instance.dump(localResult);
            resultPromise.set_value(std::move(localResult));
        });
    }
    mCondition.notify_one();
    // Note: This is an rvalue.
    result.assign(resultFuture.get());
}

void RenderEngineThreaded::mapExternalTextureBuffer(const sp<GraphicBuffer>& buffer,
                                                    bool isRenderable) {
    ATRACE_CALL();
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([=](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::mapExternalTextureBuffer");
            instance.mapExternalTextureBuffer(buffer, isRenderable);
        });
    }
    mCondition.notify_one();
}

void RenderEngineThreaded::unmapExternalTextureBuffer(sp<GraphicBuffer>&& buffer) {
    ATRACE_CALL();
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push(
                [=, buffer = std::move(buffer)](renderengine::RenderEngine& instance) mutable {
                    ATRACE_NAME("REThreaded::unmapExternalTextureBuffer");
                    instance.unmapExternalTextureBuffer(std::move(buffer));
                });
    }
    mCondition.notify_one();
}

size_t RenderEngineThreaded::getMaxTextureSize() const {
    waitUntilInitialized();
    return mRenderEngine->getMaxTextureSize();
}

size_t RenderEngineThreaded::getMaxViewportDims() const {
    waitUntilInitialized();
    return mRenderEngine->getMaxViewportDims();
}

bool RenderEngineThreaded::supportsProtectedContent() const {
    waitUntilInitialized();
    return mRenderEngine->supportsProtectedContent();
}

void RenderEngineThreaded::cleanupPostRender() {
    if (canSkipPostRenderCleanup()) {
        return;
    }

    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([=](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::cleanupPostRender");
            instance.cleanupPostRender();
        });
        mNeedsPostRenderCleanup = false;
    }
    mCondition.notify_one();
}

bool RenderEngineThreaded::canSkipPostRenderCleanup() const {
    return !mNeedsPostRenderCleanup;
}

void RenderEngineThreaded::drawLayersInternal(
        const std::shared_ptr<std::promise<FenceResult>>&& resultPromise,
        const DisplaySettings& display, const std::vector<LayerSettings>& layers,
        const std::shared_ptr<ExternalTexture>& buffer, base::unique_fd&& bufferFence) {
    resultPromise->set_value(Fence::NO_FENCE);
    return;
}

ftl::Future<FenceResult> RenderEngineThreaded::drawLayers(
        const DisplaySettings& display, const std::vector<LayerSettings>& layers,
        const std::shared_ptr<ExternalTexture>& buffer, base::unique_fd&& bufferFence) {
    ATRACE_CALL();
    const auto resultPromise = std::make_shared<std::promise<FenceResult>>();
    std::future<FenceResult> resultFuture = resultPromise->get_future();
    int fd = bufferFence.release();
    {
        std::lock_guard lock(mThreadMutex);
        mNeedsPostRenderCleanup = true;
        mFunctionCalls.push(
                [resultPromise, display, layers, buffer, fd](renderengine::RenderEngine& instance) {
                    ATRACE_NAME("REThreaded::drawLayers");
                    instance.updateProtectedContext(layers, buffer);
                    instance.drawLayersInternal(std::move(resultPromise), display, layers, buffer,
                                                base::unique_fd(fd));
                });
    }
    mCondition.notify_one();
    return resultFuture;
}

int RenderEngineThreaded::getContextPriority() {
    std::promise<int> resultPromise;
    std::future<int> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::getContextPriority");
            int priority = instance.getContextPriority();
            resultPromise.set_value(priority);
        });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

bool RenderEngineThreaded::supportsBackgroundBlur() {
    waitUntilInitialized();
    return mRenderEngine->supportsBackgroundBlur();
}

void RenderEngineThreaded::onActiveDisplaySizeChanged(ui::Size size) {
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([size](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::onActiveDisplaySizeChanged");
            instance.onActiveDisplaySizeChanged(size);
        });
    }
    mCondition.notify_one();
}

std::optional<pid_t> RenderEngineThreaded::getRenderEngineTid() const {
    std::promise<pid_t> tidPromise;
    std::future<pid_t> tidFuture = tidPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&tidPromise](renderengine::RenderEngine& instance) {
            tidPromise.set_value(gettid());
        });
    }

    mCondition.notify_one();
    return std::make_optional(tidFuture.get());
}

void RenderEngineThreaded::setEnableTracing(bool tracingEnabled) {
    // This function is designed so it can run asynchronously, so we do not need to wait
    // for the futures.
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([tracingEnabled](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::setEnableTracing");
            instance.setEnableTracing(tracingEnabled);
        });
    }
    mCondition.notify_one();
}
} // namespace threaded
} // namespace renderengine
} // namespace android
