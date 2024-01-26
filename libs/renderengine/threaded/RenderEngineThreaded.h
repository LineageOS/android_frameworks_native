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
    std::future<void> primeCache(bool shouldPrimeUltraHDR) override;

    void dump(std::string& result) override;

    size_t getMaxTextureSize() const override;
    size_t getMaxViewportDims() const override;

    bool supportsProtectedContent() const override;
    void cleanupPostRender() override;

    ftl::Future<FenceResult> drawLayers(const DisplaySettings& display,
                                        const std::vector<LayerSettings>& layers,
                                        const std::shared_ptr<ExternalTexture>& buffer,
                                        base::unique_fd&& bufferFence) override;

    int getContextPriority() override;
    bool supportsBackgroundBlur() override;
    void onActiveDisplaySizeChanged(ui::Size size) override;
    std::optional<pid_t> getRenderEngineTid() const override;
    void setEnableTracing(bool tracingEnabled) override;

protected:
    void mapExternalTextureBuffer(const sp<GraphicBuffer>& buffer, bool isRenderable) override;
    void unmapExternalTextureBuffer(sp<GraphicBuffer>&& buffer) override;
    bool canSkipPostRenderCleanup() const override;
    void drawLayersInternal(const std::shared_ptr<std::promise<FenceResult>>&& resultPromise,
                            const DisplaySettings& display,
                            const std::vector<LayerSettings>& layers,
                            const std::shared_ptr<ExternalTexture>& buffer,
                            base::unique_fd&& bufferFence) override;

private:
    void threadMain(CreateInstanceFactory factory);
    void waitUntilInitialized() const;
    static status_t setSchedFifo(bool enabled);

    // No-op. This method is only called on leaf implementations of RenderEngine.
    void useProtectedContext(bool) override {}

    /* ------------------------------------------------------------------------
     * Threading
     */
    const char* const mThreadName = "RenderEngine";
    // Protects the creation and destruction of mThread.
    mutable std::mutex mThreadMutex;
    std::thread mThread GUARDED_BY(mThreadMutex);
    std::atomic<bool> mRunning = true;
    std::atomic<bool> mNeedsPostRenderCleanup = false;

    using Work = std::function<void(renderengine::RenderEngine&)>;
    mutable std::queue<Work> mFunctionCalls GUARDED_BY(mThreadMutex);
    mutable std::condition_variable mCondition;

    // Used to allow select thread safe methods to be accessed without requiring the
    // method to be invoked on the RenderEngine thread
    std::atomic_bool mIsInitialized = false;
    mutable std::mutex mInitializedMutex;
    mutable std::condition_variable mInitializedCondition;

    /* ------------------------------------------------------------------------
     * Render Engine
     */
    std::unique_ptr<renderengine::RenderEngine> mRenderEngine;
};
} // namespace threaded
} // namespace renderengine
} // namespace android
