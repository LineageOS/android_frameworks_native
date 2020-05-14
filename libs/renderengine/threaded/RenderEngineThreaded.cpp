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
#include <utils/Trace.h>

#include "gl/GLESRenderEngine.h"

using namespace std::chrono_literals;

namespace android {
namespace renderengine {
namespace threaded {

std::unique_ptr<RenderEngineThreaded> RenderEngineThreaded::create(
        const RenderEngineCreationArgs& args) {
    return std::make_unique<RenderEngineThreaded>(args);
}

void RenderEngineThreaded::setRenderEngine(
        std::unique_ptr<renderengine::RenderEngine> renderEngine) {
    ATRACE_CALL();
    // In order to ensure this is a thread safe call, it also needs to be put on a stack.
    std::promise<void> resultPromise;
    std::future<void> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push(
                [this, &resultPromise, &renderEngine](renderengine::RenderEngine& /*instance*/) {
                    ATRACE_NAME("REThreaded::setRenderEngine");
                    mRenderEngine = std::move(renderEngine);
                    resultPromise.set_value();
                });
    }
    mCondition.notify_one();
    resultFuture.wait();
}

RenderEngineThreaded::RenderEngineThreaded(const RenderEngineCreationArgs& args)
      : renderengine::impl::RenderEngine(args) {
    ATRACE_CALL();

    std::lock_guard lockThread(mThreadMutex);
    mThread = std::thread(&RenderEngineThreaded::threadMain, this, args);
}

RenderEngineThreaded::~RenderEngineThreaded() {
    {
        std::lock_guard lock(mThreadMutex);
        mRunning = false;
        mCondition.notify_one();
    }

    if (mThread.joinable()) {
        mThread.join();
    }
}

// NO_THREAD_SAFETY_ANALYSIS is because std::unique_lock presently lacks thread safety annotations.
void RenderEngineThreaded::threadMain(const RenderEngineCreationArgs& args)
        NO_THREAD_SAFETY_ANALYSIS {
    ATRACE_CALL();

    struct sched_param param = {0};
    param.sched_priority = 2;
    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
        ALOGE("Couldn't set SCHED_FIFO");
    }

    mRenderEngine = renderengine::gl::GLESRenderEngine::create(args);

    std::unique_lock<std::mutex> lock(mThreadMutex);
    pthread_setname_np(pthread_self(), mThreadName);

    while (mRunning) {
        if (!mFunctionCalls.empty()) {
            auto task = mFunctionCalls.front();
            mFunctionCalls.pop();
            task(*mRenderEngine);
        }
        mCondition.wait(lock, [this]() REQUIRES(mThreadMutex) {
            return !mRunning || !mFunctionCalls.empty();
        });
    }
}

void RenderEngineThreaded::primeCache() const {
    std::promise<void> resultPromise;
    std::future<void> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::primeCache");
            instance.primeCache();
            resultPromise.set_value();
        });
    }
    mCondition.notify_one();
    resultFuture.wait();
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

void RenderEngineThreaded::genTextures(size_t count, uint32_t* names) {
    std::promise<void> resultPromise;
    std::future<void> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, count, names](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::genTextures");
            instance.genTextures(count, names);
            resultPromise.set_value();
        });
    }
    mCondition.notify_one();
    resultFuture.wait();
}

void RenderEngineThreaded::deleteTextures(size_t count, uint32_t const* names) {
    std::promise<void> resultPromise;
    std::future<void> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, count, &names](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::deleteTextures");
            instance.deleteTextures(count, names);
            resultPromise.set_value();
        });
    }
    mCondition.notify_one();
    resultFuture.wait();
}

void RenderEngineThreaded::bindExternalTextureImage(uint32_t texName, const Image& image) {
    std::promise<void> resultPromise;
    std::future<void> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push(
                [&resultPromise, texName, &image](renderengine::RenderEngine& instance) {
                    ATRACE_NAME("REThreaded::bindExternalTextureImage");
                    instance.bindExternalTextureImage(texName, image);
                    resultPromise.set_value();
                });
    }
    mCondition.notify_one();
    resultFuture.wait();
}

status_t RenderEngineThreaded::bindExternalTextureBuffer(uint32_t texName,
                                                         const sp<GraphicBuffer>& buffer,
                                                         const sp<Fence>& fence) {
    std::promise<status_t> resultPromise;
    std::future<status_t> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push(
                [&resultPromise, texName, &buffer, &fence](renderengine::RenderEngine& instance) {
                    ATRACE_NAME("REThreaded::bindExternalTextureBuffer");
                    status_t status = instance.bindExternalTextureBuffer(texName, buffer, fence);
                    resultPromise.set_value(status);
                });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

void RenderEngineThreaded::cacheExternalTextureBuffer(const sp<GraphicBuffer>& buffer) {
    std::promise<void> resultPromise;
    std::future<void> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, &buffer](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::cacheExternalTextureBuffer");
            instance.cacheExternalTextureBuffer(buffer);
            resultPromise.set_value();
        });
    }
    mCondition.notify_one();
    resultFuture.wait();
}

void RenderEngineThreaded::unbindExternalTextureBuffer(uint64_t bufferId) {
    std::promise<void> resultPromise;
    std::future<void> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, &bufferId](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::unbindExternalTextureBuffer");
            instance.unbindExternalTextureBuffer(bufferId);
            resultPromise.set_value();
        });
    }
    mCondition.notify_one();
    resultFuture.wait();
}

status_t RenderEngineThreaded::bindFrameBuffer(Framebuffer* framebuffer) {
    std::promise<status_t> resultPromise;
    std::future<status_t> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, &framebuffer](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::bindFrameBuffer");
            status_t status = instance.bindFrameBuffer(framebuffer);
            resultPromise.set_value(status);
        });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

void RenderEngineThreaded::unbindFrameBuffer(Framebuffer* framebuffer) {
    std::promise<void> resultPromise;
    std::future<void> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, &framebuffer](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::unbindFrameBuffer");
            instance.unbindFrameBuffer(framebuffer);
            resultPromise.set_value();
        });
    }
    mCondition.notify_one();
    resultFuture.wait();
}

size_t RenderEngineThreaded::getMaxTextureSize() const {
    std::promise<size_t> resultPromise;
    std::future<size_t> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::getMaxTextureSize");
            size_t size = instance.getMaxTextureSize();
            resultPromise.set_value(size);
        });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

size_t RenderEngineThreaded::getMaxViewportDims() const {
    std::promise<size_t> resultPromise;
    std::future<size_t> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::getMaxViewportDims");
            size_t size = instance.getMaxViewportDims();
            resultPromise.set_value(size);
        });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

bool RenderEngineThreaded::isProtected() const {
    std::promise<bool> resultPromise;
    std::future<bool> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::isProtected");
            bool returnValue = instance.isProtected();
            resultPromise.set_value(returnValue);
        });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

bool RenderEngineThreaded::supportsProtectedContent() const {
    std::promise<bool> resultPromise;
    std::future<bool> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::supportsProtectedContent");
            bool returnValue = instance.supportsProtectedContent();
            resultPromise.set_value(returnValue);
        });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

bool RenderEngineThreaded::useProtectedContext(bool useProtectedContext) {
    std::promise<bool> resultPromise;
    std::future<bool> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push(
                [&resultPromise, useProtectedContext](renderengine::RenderEngine& instance) {
                    ATRACE_NAME("REThreaded::useProtectedContext");
                    bool returnValue = instance.useProtectedContext(useProtectedContext);
                    resultPromise.set_value(returnValue);
                });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

Framebuffer* RenderEngineThreaded::getFramebufferForDrawing() {
    std::promise<Framebuffer*> resultPromise;
    std::future<Framebuffer*> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::getFramebufferForDrawing");
            Framebuffer* framebuffer = instance.getFramebufferForDrawing();
            resultPromise.set_value(framebuffer);
        });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

bool RenderEngineThreaded::cleanupPostRender() {
    std::promise<bool> resultPromise;
    std::future<bool> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::cleanupPostRender");
            bool returnValue = instance.cleanupPostRender();
            resultPromise.set_value(returnValue);
        });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

status_t RenderEngineThreaded::drawLayers(const DisplaySettings& display,
                                          const std::vector<const LayerSettings*>& layers,
                                          const sp<GraphicBuffer>& buffer,
                                          const bool useFramebufferCache,
                                          base::unique_fd&& bufferFence,
                                          base::unique_fd* drawFence) {
    std::promise<status_t> resultPromise;
    std::future<status_t> resultFuture = resultPromise.get_future();
    {
        std::lock_guard lock(mThreadMutex);
        mFunctionCalls.push([&resultPromise, &display, &layers, &buffer, useFramebufferCache,
                             &bufferFence, &drawFence](renderengine::RenderEngine& instance) {
            ATRACE_NAME("REThreaded::drawLayers");
            status_t status = instance.drawLayers(display, layers, buffer, useFramebufferCache,
                                                  std::move(bufferFence), drawFence);
            resultPromise.set_value(status);
        });
    }
    mCondition.notify_one();
    return resultFuture.get();
}

} // namespace threaded
} // namespace renderengine
} // namespace android