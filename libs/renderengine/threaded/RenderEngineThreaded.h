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

#pragma once

#include <android-base/thread_annotations.h>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

#include "renderengine/RenderEngine.h"

namespace android {
namespace renderengine {
namespace threaded {

using CreateInstanceFactory = std::function<std::unique_ptr<renderengine::RenderEngine>()>;

/**
 * This class extends a basic RenderEngine class. It contains a thread. Each time a function of
 * this class is called, we create a lambda function that is put on a queue. The main thread then
 * executes the functions in order.
 */
class RenderEngineThreaded : public RenderEngine {
public:
    static std::unique_ptr<RenderEngineThreaded> create(CreateInstanceFactory factory);

    RenderEngineThreaded(CreateInstanceFactory factory);
    ~RenderEngineThreaded() override;
    void primeCache() const override;

    void dump(std::string& result) override;

    void genTextures(size_t count, uint32_t* names) override;
    void deleteTextures(size_t count, uint32_t const* names) override;
    void cacheExternalTextureBuffer(const sp<GraphicBuffer>& buffer) override;
    void unbindExternalTextureBuffer(uint64_t bufferId) override;
    size_t getMaxTextureSize() const override;
    size_t getMaxViewportDims() const override;

    bool isProtected() const override;
    bool supportsProtectedContent() const override;
    bool useProtectedContext(bool useProtectedContext) override;
    bool cleanupPostRender(CleanupMode mode) override;

    status_t drawLayers(const DisplaySettings& display,
                        const std::vector<const LayerSettings*>& layers,
                        const sp<GraphicBuffer>& buffer, const bool useFramebufferCache,
                        base::unique_fd&& bufferFence, base::unique_fd* drawFence) override;

    void cleanFramebufferCache() override;
    int getContextPriority() override;
    bool supportsBackgroundBlur() override;

private:
    void threadMain(CreateInstanceFactory factory);

    /* ------------------------------------------------------------------------
     * Threading
     */
    const char* const mThreadName = "RenderEngineThread";
    // Protects the creation and destruction of mThread.
    mutable std::mutex mThreadMutex;
    std::thread mThread GUARDED_BY(mThreadMutex);
    bool mRunning GUARDED_BY(mThreadMutex) = true;
    mutable std::queue<std::function<void(renderengine::RenderEngine& instance)>> mFunctionCalls
            GUARDED_BY(mThreadMutex);
    mutable std::condition_variable mCondition;

    /* ------------------------------------------------------------------------
     * Render Engine
     */
    std::unique_ptr<renderengine::RenderEngine> mRenderEngine;
};
} // namespace threaded
} // namespace renderengine
} // namespace android
