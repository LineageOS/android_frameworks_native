/* Copyright 2016 The Android Open Source Project
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
#define LOG_TAG "SurfaceReplayer"

#include "Replayer.h"

#include <android/native_window.h>

#include <binder/IMemory.h>

#include <gui/ISurfaceComposer.h>
#include <gui/Surface.h>
#include <private/gui/ComposerService.h>
#include <private/gui/LayerState.h>

#include <ui/DisplayInfo.h>
#include <utils/Log.h>
#include <utils/String8.h>
#include <utils/Trace.h>

#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

using namespace android;

std::atomic_bool Replayer::sReplayingManually(false);

Replayer::Replayer(const std::string& filename, bool replayManually, int numThreads)
      : mTrace(), mLoaded(false), mIncrementIndex(0), mCurrentTime(0), mNumThreads(numThreads) {
    srand(RAND_COLOR_SEED);

    std::fstream input(filename, std::ios::in | std::ios::binary);

    mLoaded = mTrace.ParseFromIstream(&input);
    if (!mLoaded) {
        std::cerr << "Trace did not load. Does " << filename << " exist?" << std::endl;
        abort();
    }

    mCurrentTime = mTrace.increment(0).time_stamp();

    sReplayingManually.store(replayManually);
}

Replayer::Replayer(const Trace& t, bool replayManually, int numThreads)
      : mTrace(t), mLoaded(true), mIncrementIndex(0), mCurrentTime(0), mNumThreads(numThreads) {
    srand(RAND_COLOR_SEED);
    mCurrentTime = mTrace.increment(0).time_stamp();

    sReplayingManually.store(replayManually);
}

status_t Replayer::replay() {
    // for manual control
    signal(SIGINT, Replayer::stopAutoReplayHandler);

    ALOGV("There are %d increments.", mTrace.increment_size());

    status_t status = loadSurfaceComposerClient();

    if (status != NO_ERROR) {
        ALOGE("Couldn't create SurfaceComposerClient (%d)", status);
        return status;
    }

    SurfaceComposerClient::enableVSyncInjections(true);

    initReplay();

    ALOGV("Starting actual Replay!");
    while (!mPendingIncrements.empty()) {
        waitForConsoleCommmand();

        auto pastIncrement = mTrace.increment(mIncrementIndex);

        waitUntilTimestamp(pastIncrement.time_stamp());

        auto event = mPendingIncrements.front();
        mPendingIncrements.pop();

        event->complete();

        if (event->getIncrementType() == Increment::kVsyncEvent) {
            mWaitingForNextVSync = false;
        }

        if (mIncrementIndex + mNumThreads < mTrace.increment_size()) {
            status = dispatchEvent(mIncrementIndex + mNumThreads);

            if (status != NO_ERROR) {
                SurfaceComposerClient::enableVSyncInjections(false);
                return status;
            }
        }

        mIncrementIndex++;
        mCurrentTime = pastIncrement.time_stamp();
    }

    SurfaceComposerClient::enableVSyncInjections(false);

    return status;
}

status_t Replayer::initReplay() {
    for (int i = 0; i < mNumThreads && i < mTrace.increment_size(); i++) {
        status_t status = dispatchEvent(i);

        if (status != NO_ERROR) {
            ALOGE("Unable to dispatch event (%d)", status);
            return status;
        }
    }

    return NO_ERROR;
}

void Replayer::stopAutoReplayHandler(int /*signal*/) {
    if (sReplayingManually) {
        SurfaceComposerClient::enableVSyncInjections(false);
        exit(0);
    }

    sReplayingManually.store(true);
}

void Replayer::waitForConsoleCommmand() {
    if (!sReplayingManually || mWaitingForNextVSync) {
        return;
    }

    while (true) {
        std::string input = "";
        std::cout << "> ";
        getline(std::cin, input);

        if (input.empty()) {
            input = mLastInput;
        }

        input = mLastInput;
        if (input == "n") {  // next vsync
            mWaitingForNextVSync = true;
            break;
        } else if (input == "c") {  // continue
            sReplayingManually.store(false);
            mWaitingForNextVSync = false;
            break;
        } else if (input == "h") {  // help
                                    // add help menu
        }

        std::cout << "Invalid Command" << std::endl;
    }
}

status_t Replayer::dispatchEvent(int index) {
    auto increment = mTrace.increment(index);
    std::shared_ptr<Event> event = std::make_shared<Event>(increment.increment_case());
    mPendingIncrements.push(event);

    status_t status = NO_ERROR;
    switch (increment.increment_case()) {
        case increment.kTransaction: {
            std::thread(&Replayer::doTransaction, this, increment.transaction(), event).detach();
        } break;
        case increment.kCreate: {
            std::thread(&Replayer::createSurfaceControl, this, increment.create(), event).detach();
        } break;
        case increment.kDelete: {
            std::thread(&Replayer::deleteSurfaceControl, this, increment.delete_(), event).detach();
        } break;
        case increment.kBufferUpdate: {
            std::lock_guard<std::mutex> lock1(mLayerLock);
            std::lock_guard<std::mutex> lock2(mBufferQueueSchedulerLock);

            Dimensions dimensions(increment.buffer_update().w(), increment.buffer_update().h());
            BufferEvent bufferEvent(event, dimensions);

            auto layerId = increment.buffer_update().id();
            if (mBufferQueueSchedulers.count(layerId) == 0) {
                mBufferQueueSchedulers[layerId] = std::make_shared<BufferQueueScheduler>(
                        mLayers[layerId], mColors[layerId], layerId);
                mBufferQueueSchedulers[layerId]->addEvent(bufferEvent);

                std::thread(&BufferQueueScheduler::startScheduling,
                        mBufferQueueSchedulers[increment.buffer_update().id()].get())
                        .detach();
            } else {
                auto bqs = mBufferQueueSchedulers[increment.buffer_update().id()];
                bqs->addEvent(bufferEvent);
            }
        } break;
        case increment.kVsyncEvent: {
            std::thread(&Replayer::injectVSyncEvent, this, increment.vsync_event(), event).detach();
        } break;
        default:
            ALOGE("Unknown Increment Type: %d", increment.increment_case());
            status = BAD_VALUE;
            break;
    }

    return status;
}

status_t Replayer::doTransaction(const Transaction& t, const std::shared_ptr<Event>& event) {
    ALOGV("Started Transaction");

    if (t.change_size() == 0) {
        event->readyToExecute();
        return NO_ERROR;
    }

    Change change = t.change(0);

    std::unique_lock<std::mutex> lock(mLayerLock);
    if (mLayers[change.id()] == nullptr) {
        mLayerCond.wait(lock, [&] { return (mLayers[change.id()] != nullptr); });
    }
    lock.unlock();

    SurfaceComposerClient::openGlobalTransaction();

    status_t status = NO_ERROR;

    for (const Change& change : t.change()) {
        std::unique_lock<std::mutex> lock(mLayerLock);
        if (mLayers[change.id()] == nullptr) {
            mLayerCond.wait(lock, [&] { return (mLayers[change.id()] != nullptr); });
        }

        switch (change.Change_case()) {
            case Change::ChangeCase::kPosition:
                status = setPosition(change.id(), change.position());
                break;
            case Change::ChangeCase::kSize:
                status = setSize(change.id(), change.size());
                break;
            case Change::ChangeCase::kAlpha:
                status = setAlpha(change.id(), change.alpha());
                break;
            case Change::ChangeCase::kLayer:
                status = setLayer(change.id(), change.layer());
                break;
            case Change::ChangeCase::kCrop:
                status = setCrop(change.id(), change.crop());
                break;
            case Change::ChangeCase::kMatrix:
                status = setMatrix(change.id(), change.matrix());
                break;
            case Change::ChangeCase::kFinalCrop:
                status = setFinalCrop(change.id(), change.final_crop());
                break;
            case Change::ChangeCase::kOverrideScalingMode:
                status = setOverrideScalingMode(change.id(), change.override_scaling_mode());
                break;
            case Change::ChangeCase::kTransparentRegionHint:
                status = setTransparentRegionHint(change.id(), change.transparent_region_hint());
                break;
            case Change::ChangeCase::kLayerStack:
                status = setLayerStack(change.id(), change.layer_stack());
                break;
            case Change::ChangeCase::kHiddenFlag:
                status = setHiddenFlag(change.id(), change.hidden_flag());
                break;
            case Change::ChangeCase::kOpaqueFlag:
                status = setOpaqueFlag(change.id(), change.opaque_flag());
                break;
            case Change::ChangeCase::kSecureFlag:
                status = setSecureFlag(change.id(), change.secure_flag());
                break;
            case Change::ChangeCase::kDeferredTransaction:
                waitUntilDeferredTransactionLayerExists(change.deferred_transaction(), lock);
                status = setDeferredTransaction(change.id(), change.deferred_transaction());
                break;
            default:
                status = NO_ERROR;
                break;
        }

        if (status != NO_ERROR) {
            ALOGE("SET TRANSACTION FAILED");
            return status;
        }
    }

    if (t.animation()) {
        SurfaceComposerClient::setAnimationTransaction();
    }

    event->readyToExecute();

    SurfaceComposerClient::closeGlobalTransaction(t.synchronous());

    ALOGV("Ended Transaction");

    return status;
}

status_t Replayer::setPosition(uint32_t id, const PositionChange& pc) {
    ALOGV("Layer %d: Setting Position -- x=%f, y=%f", id, pc.x(), pc.y());
    return mLayers[id]->setPosition(pc.x(), pc.y());
}

status_t Replayer::setSize(uint32_t id, const SizeChange& sc) {
    ALOGV("Layer %d: Setting Size -- w=%u, h=%u", id, sc.w(), sc.h());
    return mLayers[id]->setSize(sc.w(), sc.h());
}

status_t Replayer::setLayer(uint32_t id, const LayerChange& lc) {
    ALOGV("Layer %d: Setting Layer -- layer=%d", id, lc.layer());
    return mLayers[id]->setLayer(lc.layer());
}

status_t Replayer::setAlpha(uint32_t id, const AlphaChange& ac) {
    ALOGV("Layer %d: Setting Alpha -- alpha=%f", id, ac.alpha());
    return mLayers[id]->setAlpha(ac.alpha());
}

status_t Replayer::setCrop(uint32_t id, const CropChange& cc) {
    ALOGV("Layer %d: Setting Crop -- left=%d, top=%d, right=%d, bottom=%d", id,
            cc.rectangle().left(), cc.rectangle().top(), cc.rectangle().right(),
            cc.rectangle().bottom());

    Rect r = Rect(cc.rectangle().left(), cc.rectangle().top(), cc.rectangle().right(),
            cc.rectangle().bottom());
    return mLayers[id]->setCrop(r);
}

status_t Replayer::setFinalCrop(uint32_t id, const FinalCropChange& fcc) {
    ALOGV("Layer %d: Setting Final Crop -- left=%d, top=%d, right=%d, bottom=%d", id,
            fcc.rectangle().left(), fcc.rectangle().top(), fcc.rectangle().right(),
            fcc.rectangle().bottom());
    Rect r = Rect(fcc.rectangle().left(), fcc.rectangle().top(), fcc.rectangle().right(),
            fcc.rectangle().bottom());
    return mLayers[id]->setFinalCrop(r);
}

status_t Replayer::setMatrix(uint32_t id, const MatrixChange& mc) {
    ALOGV("Layer %d: Setting Matrix -- dsdx=%f, dtdx=%f, dsdy=%f, dtdy=%f", id, mc.dsdx(),
            mc.dtdx(), mc.dsdy(), mc.dtdy());
    return mLayers[id]->setMatrix(mc.dsdx(), mc.dtdx(), mc.dsdy(), mc.dtdy());
}

status_t Replayer::setOverrideScalingMode(uint32_t id, const OverrideScalingModeChange& osmc) {
    ALOGV("Layer %d: Setting Override Scaling Mode -- mode=%d", id, osmc.override_scaling_mode());
    return mLayers[id]->setOverrideScalingMode(osmc.override_scaling_mode());
}

status_t Replayer::setTransparentRegionHint(uint32_t id, const TransparentRegionHintChange& trhc) {
    ALOGV("Setting Transparent Region Hint");
    Region re = Region();

    for (auto r : trhc.region()) {
        Rect rect = Rect(r.left(), r.top(), r.right(), r.bottom());
        re.merge(rect);
    }

    return mLayers[id]->setTransparentRegionHint(re);
}

status_t Replayer::setLayerStack(uint32_t id, const LayerStackChange& lsc) {
    ALOGV("Layer %d: Setting LayerStack -- layer_stack=%d", id, lsc.layer_stack());
    return mLayers[id]->setLayerStack(lsc.layer_stack());
}

status_t Replayer::setHiddenFlag(uint32_t id, const HiddenFlagChange& hfc) {
    ALOGV("Layer %d: Setting Hidden Flag -- hidden_flag=%d", id, hfc.hidden_flag());
    uint32_t flag = hfc.hidden_flag() ? layer_state_t::eLayerHidden : 0;

    return mLayers[id]->setFlags(flag, layer_state_t::eLayerHidden);
}

status_t Replayer::setOpaqueFlag(uint32_t id, const OpaqueFlagChange& ofc) {
    ALOGV("Layer %d: Setting Opaque Flag -- opaque_flag=%d", id, ofc.opaque_flag());
    uint32_t flag = ofc.opaque_flag() ? layer_state_t::eLayerOpaque : 0;

    return mLayers[id]->setFlags(flag, layer_state_t::eLayerOpaque);
}

status_t Replayer::setSecureFlag(uint32_t id, const SecureFlagChange& sfc) {
    ALOGV("Layer %d: Setting Secure Flag -- secure_flag=%d", id, sfc.secure_flag());
    uint32_t flag = sfc.secure_flag() ? layer_state_t::eLayerSecure : 0;

    return mLayers[id]->setFlags(flag, layer_state_t::eLayerSecure);
}

status_t Replayer::setDeferredTransaction(uint32_t id, const DeferredTransactionChange& dtc) {
    ALOGV("Layer %d: Setting Deferred Transaction -- layer_id=%d, "
          "frame_number=%llu",
            id, dtc.layer_id(), dtc.frame_number());
    if (mLayers.count(dtc.layer_id()) == 0 || mLayers[dtc.layer_id()] == nullptr) {
        ALOGE("Layer %d not found in Deferred Transaction", dtc.layer_id());
        return BAD_VALUE;
    }

    auto handle = mLayers[dtc.layer_id()]->getHandle();

    return mLayers[id]->deferTransactionUntil(handle, dtc.frame_number());
}

status_t Replayer::createSurfaceControl(const Create& create, const std::shared_ptr<Event>& event) {
    event->readyToExecute();

    ALOGV("Creating Surface Control: ID: %d", create.id());
    sp<SurfaceControl> surfaceControl = mComposerClient->createSurface(
            String8(create.name().c_str()), create.w(), create.h(), PIXEL_FORMAT_RGBA_8888, 0);

    if (surfaceControl == nullptr) {
        ALOGE("CreateSurfaceControl: unable to create surface control");
        return BAD_VALUE;
    }

    std::lock_guard<std::mutex> lock1(mLayerLock);
    auto& layer = mLayers[create.id()];
    layer = surfaceControl;

    mColors[create.id()] = HSVToRGB(HSV(rand() % 360, 1, 1));

    mLayerCond.notify_all();

    std::lock_guard<std::mutex> lock2(mBufferQueueSchedulerLock);
    if (mBufferQueueSchedulers.count(create.id()) != 0) {
        mBufferQueueSchedulers[create.id()]->setSurfaceControl(
                mLayers[create.id()], mColors[create.id()]);
    }

    return NO_ERROR;
}

status_t Replayer::deleteSurfaceControl(
        const Delete& delete_, const std::shared_ptr<Event>& event) {
    ALOGV("Deleting %d Surface Control", delete_.id());
    event->readyToExecute();

    std::lock_guard<std::mutex> lock1(mPendingLayersLock);

    mLayersPendingRemoval.push_back(delete_.id());

    auto iterator = mBufferQueueSchedulers.find(delete_.id());
    if (iterator != mBufferQueueSchedulers.end()) {
        (*iterator).second->stopScheduling();
    }

    std::lock_guard<std::mutex> lock2(mLayerLock);
    mComposerClient->destroySurface(mLayers[delete_.id()]->getHandle());

    return NO_ERROR;
}

void Replayer::doDeleteSurfaceControls() {
    std::lock_guard<std::mutex> lock1(mPendingLayersLock);
    std::lock_guard<std::mutex> lock2(mLayerLock);
    if (!mLayersPendingRemoval.empty()) {
        for (int id : mLayersPendingRemoval) {
            mLayers.erase(id);
            mColors.erase(id);
            mBufferQueueSchedulers.erase(id);
        }
        mLayersPendingRemoval.clear();
    }
}

status_t Replayer::injectVSyncEvent(
        const VSyncEvent& vSyncEvent, const std::shared_ptr<Event>& event) {
    ALOGV("Injecting VSync Event");

    doDeleteSurfaceControls();

    event->readyToExecute();

    SurfaceComposerClient::injectVSync(vSyncEvent.when());

    return NO_ERROR;
}

void Replayer::waitUntilTimestamp(int64_t timestamp) {
    ALOGV("Waiting for %lld nanoseconds...", static_cast<int64_t>(timestamp - mCurrentTime));
    std::this_thread::sleep_for(std::chrono::nanoseconds(timestamp - mCurrentTime));
}

void Replayer::waitUntilDeferredTransactionLayerExists(
        const DeferredTransactionChange& dtc, std::unique_lock<std::mutex>& lock) {
    if (mLayers.count(dtc.layer_id()) == 0 || mLayers[dtc.layer_id()] == nullptr) {
        mLayerCond.wait(lock, [&] { return (mLayers[dtc.layer_id()] != nullptr); });
    }
}

status_t Replayer::loadSurfaceComposerClient() {
    mComposerClient = new SurfaceComposerClient;
    return mComposerClient->initCheck();
}
