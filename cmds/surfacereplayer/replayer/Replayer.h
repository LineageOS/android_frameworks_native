/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef ANDROID_SURFACEREPLAYER_H
#define ANDROID_SURFACEREPLAYER_H

#include "BufferQueueScheduler.h"
#include "Color.h"
#include "Event.h"

#include <frameworks/native/cmds/surfacereplayer/proto/src/trace.pb.h>

#include <gui/SurfaceComposerClient.h>
#include <gui/SurfaceControl.h>

#include <utils/Errors.h>
#include <utils/StrongPointer.h>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>
#include <utility>

namespace android {

const auto DEFAULT_PATH = "/data/local/tmp/SurfaceTrace.dat";
const auto RAND_COLOR_SEED = 1000;
const auto DEFAULT_THREADS = 3;

typedef uint32_t layer_id;

class Replayer {
  public:
    Replayer(const std::string& filename, bool replayManually = false,
            int numThreads = DEFAULT_THREADS);
    Replayer(const Trace& trace, bool replayManually = false, int numThreads = DEFAULT_THREADS);

    status_t replay();

  private:
    status_t initReplay();

    void waitForConsoleCommmand();
    static void stopAutoReplayHandler(int signal);

    status_t dispatchEvent(int index);

    status_t doTransaction(const Transaction& transaction, const std::shared_ptr<Event>& event);
    status_t createSurfaceControl(const Create& create, const std::shared_ptr<Event>& event);
    status_t deleteSurfaceControl(const Delete& delete_, const std::shared_ptr<Event>& event);
    status_t injectVSyncEvent(const VSyncEvent& vsyncEvent, const std::shared_ptr<Event>& event);

    status_t setPosition(uint32_t id, const PositionChange& pc);
    status_t setSize(uint32_t id, const SizeChange& sc);
    status_t setAlpha(uint32_t id, const AlphaChange& ac);
    status_t setLayer(uint32_t id, const LayerChange& lc);
    status_t setCrop(uint32_t id, const CropChange& cc);
    status_t setFinalCrop(uint32_t id, const FinalCropChange& fcc);
    status_t setMatrix(uint32_t id, const MatrixChange& mc);
    status_t setOverrideScalingMode(uint32_t id, const OverrideScalingModeChange& osmc);
    status_t setTransparentRegionHint(uint32_t id, const TransparentRegionHintChange& trgc);
    status_t setLayerStack(uint32_t id, const LayerStackChange& lsc);
    status_t setHiddenFlag(uint32_t id, const HiddenFlagChange& hfc);
    status_t setOpaqueFlag(uint32_t id, const OpaqueFlagChange& ofc);
    status_t setSecureFlag(uint32_t id, const SecureFlagChange& sfc);
    status_t setDeferredTransaction(uint32_t id, const DeferredTransactionChange& dtc);

    void doDeleteSurfaceControls();
    void waitUntilTimestamp(int64_t timestamp);
    void waitUntilDeferredTransactionLayerExists(
            const DeferredTransactionChange& dtc, std::unique_lock<std::mutex>& lock);
    status_t loadSurfaceComposerClient();

    Trace mTrace;
    bool mLoaded = false;
    int32_t mIncrementIndex = 0;
    int64_t mCurrentTime = 0;
    int32_t mNumThreads = DEFAULT_THREADS;

    std::string mLastInput;

    static atomic_bool sReplayingManually;
    bool mWaitingForNextVSync;

    std::mutex mLayerLock;
    std::condition_variable mLayerCond;
    std::unordered_map<layer_id, sp<SurfaceControl>> mLayers;
    std::unordered_map<layer_id, RGB> mColors;

    std::mutex mPendingLayersLock;
    std::vector<layer_id> mLayersPendingRemoval;

    std::mutex mBufferQueueSchedulerLock;
    std::unordered_map<layer_id, std::shared_ptr<BufferQueueScheduler>> mBufferQueueSchedulers;

    sp<SurfaceComposerClient> mComposerClient;
    std::queue<std::shared_ptr<Event>> mPendingIncrements;
};

}  // namespace android
#endif
