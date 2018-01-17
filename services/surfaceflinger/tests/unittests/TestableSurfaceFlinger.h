/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "DisplayDevice.h"
#include "SurfaceFlinger.h"

namespace android {

class EventThread;

namespace RE {
class RenderEngine;
}

namespace Hwc2 {
class Composer;
}

class TestableSurfaceFlinger {
public:
    // Extend this as needed for accessing SurfaceFlinger private (and public)
    // functions.

    void setupRenderEngine(std::unique_ptr<RE::RenderEngine> renderEngine) {
        mFlinger->getBE().mRenderEngine = std::move(renderEngine);
    }

    void setupComposer(std::unique_ptr<Hwc2::Composer> composer) {
        mFlinger->getBE().mHwc.reset(new HWComposer(std::move(composer)));
    }

    using CreateBufferQueueFunction = SurfaceFlinger::CreateBufferQueueFunction;

    void setCreateBufferQueueFunction(CreateBufferQueueFunction f) {
        mFlinger->mCreateBufferQueue = f;
    }

    /* ------------------------------------------------------------------------
     * Forwarding for functions being tested
     */
    auto processDisplayChangesLocked() { return mFlinger->processDisplayChangesLocked(); }

    /* ------------------------------------------------------------------------
     * Read-write access to private data to set up preconditions and assert
     * post-conditions.
     */
    auto& mutableBuiltinDisplays() { return mFlinger->mBuiltinDisplays; }
    auto& mutableDisplays() { return mFlinger->mDisplays; }
    auto& mutableCurrentState() { return mFlinger->mCurrentState; }
    auto& mutableDrawingState() { return mFlinger->mDrawingState; }
    auto& mutableEventThread() { return mFlinger->mEventThread; }
    auto& mutableEventQueue() { return mFlinger->mEventQueue; }

    auto& mutableHwcDisplayData() { return mFlinger->getBE().mHwc->mDisplayData; }
    auto& mutableHwcDisplaySlots() { return mFlinger->getBE().mHwc->mHwcDisplaySlots; }

    ~TestableSurfaceFlinger() {
        // All these pointer and container clears help ensure that GMock does
        // not report a leaked object, since the SurfaceFlinger instance may
        // still be referenced by something despite our best efforts to destroy
        // it after each test is done.
        mutableDisplays().clear();
        mutableEventThread().reset();
        mFlinger->getBE().mHwc.reset();
        mFlinger->getBE().mRenderEngine.reset();
    }

    /* ------------------------------------------------------------------------
     * Wrapper classes for Read-write access to private data to set up
     * preconditions and assert post-conditions.
     */
    struct HWC2Display : public HWC2::Display {
        HWC2Display(Hwc2::Composer& composer,
                    const std::unordered_set<HWC2::Capability>& capabilities, hwc2_display_t id,
                    HWC2::DisplayType type)
              : HWC2::Display(composer, capabilities, id, type) {}
        ~HWC2Display() {
            // Prevents a call to disable vsyncs.
            mType = HWC2::DisplayType::Invalid;
        }

        auto& mutableIsConnected() { return this->mIsConnected; }
        auto& mutableConfigs() { return this->mConfigs; }
    };

    sp<SurfaceFlinger> mFlinger = new SurfaceFlinger(SurfaceFlinger::SkipInitialization);
};

} // namespace android
