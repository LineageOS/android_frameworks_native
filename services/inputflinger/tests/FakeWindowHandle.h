/*
 * Copyright 2023 The Android Open Source Project
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

#include <android-base/logging.h>
#include "../dispatcher/InputDispatcher.h"

using android::base::Result;
using android::gui::Pid;
using android::gui::TouchOcclusionMode;
using android::gui::Uid;
using android::gui::WindowInfo;
using android::gui::WindowInfoHandle;

namespace android {
namespace inputdispatcher {

namespace {

// The default pid and uid for windows created by the test.
constexpr gui::Pid WINDOW_PID{999};
constexpr gui::Uid WINDOW_UID{1001};

static constexpr std::chrono::nanoseconds DISPATCHING_TIMEOUT = 100ms;

} // namespace

class FakeInputReceiver {
public:
    std::unique_ptr<InputEvent> consumeEvent(std::chrono::milliseconds timeout) {
        uint32_t consumeSeq = 0;
        std::unique_ptr<InputEvent> event;

        std::chrono::time_point start = std::chrono::steady_clock::now();
        status_t result = WOULD_BLOCK;
        while (result == WOULD_BLOCK) {
            InputEvent* rawEventPtr = nullptr;
            result = mConsumer.consume(&mEventFactory, /*consumeBatches=*/true, -1, &consumeSeq,
                                       &rawEventPtr);
            event = std::unique_ptr<InputEvent>(rawEventPtr);
            std::chrono::duration elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed > timeout) {
                if (timeout != 0ms) {
                    LOG(ERROR) << "Waited too long for consumer to produce an event, giving up";
                }
                break;
            }
        }
        // Events produced by this factory are owned pointers.
        if (result != OK) {
            if (timeout == 0ms) {
                // This is likely expected. No need to log.
            } else {
                LOG(ERROR) << "Received result =  " << result << " from consume";
            }
            return nullptr;
        }
        result = mConsumer.sendFinishedSignal(consumeSeq, true);
        if (result != OK) {
            LOG(ERROR) << "Received result = " << result << " from sendFinishedSignal";
        }
        return event;
    }

    explicit FakeInputReceiver(std::unique_ptr<InputChannel> channel, const std::string name)
          : mConsumer(std::move(channel)) {}

    virtual ~FakeInputReceiver() {}

private:
    std::unique_ptr<InputChannel> mClientChannel;
    InputConsumer mConsumer;
    DynamicInputEventFactory mEventFactory;
};

class FakeWindowHandle : public WindowInfoHandle {
public:
    static const int32_t WIDTH = 600;
    static const int32_t HEIGHT = 800;

    FakeWindowHandle(const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle,
                     InputDispatcher& dispatcher, const std::string name, int32_t displayId)
          : mName(name) {
        Result<std::unique_ptr<InputChannel>> channel = dispatcher.createInputChannel(name);
        mInfo.token = (*channel)->getConnectionToken();
        mInputReceiver = std::make_unique<FakeInputReceiver>(std::move(*channel), name);

        inputApplicationHandle->updateInfo();
        mInfo.applicationInfo = *inputApplicationHandle->getInfo();

        mInfo.id = sId++;
        mInfo.name = name;
        mInfo.dispatchingTimeout = DISPATCHING_TIMEOUT;
        mInfo.alpha = 1.0;
        mInfo.frame.left = 0;
        mInfo.frame.top = 0;
        mInfo.frame.right = WIDTH;
        mInfo.frame.bottom = HEIGHT;
        mInfo.transform.set(0, 0);
        mInfo.globalScaleFactor = 1.0;
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(Rect(0, 0, WIDTH, HEIGHT));
        mInfo.ownerPid = WINDOW_PID;
        mInfo.ownerUid = WINDOW_UID;
        mInfo.displayId = displayId;
        mInfo.inputConfig = WindowInfo::InputConfig::DEFAULT;
    }

    sp<FakeWindowHandle> clone(int32_t displayId) {
        sp<FakeWindowHandle> handle = sp<FakeWindowHandle>::make(mInfo.name + "(Mirror)");
        handle->mInfo = mInfo;
        handle->mInfo.displayId = displayId;
        handle->mInfo.id = sId++;
        handle->mInputReceiver = mInputReceiver;
        return handle;
    }

    void setTouchable(bool touchable) {
        mInfo.setInputConfig(WindowInfo::InputConfig::NOT_TOUCHABLE, !touchable);
    }

    void setFocusable(bool focusable) {
        mInfo.setInputConfig(WindowInfo::InputConfig::NOT_FOCUSABLE, !focusable);
    }

    void setVisible(bool visible) {
        mInfo.setInputConfig(WindowInfo::InputConfig::NOT_VISIBLE, !visible);
    }

    void setDispatchingTimeout(std::chrono::nanoseconds timeout) {
        mInfo.dispatchingTimeout = timeout;
    }

    void setPaused(bool paused) {
        mInfo.setInputConfig(WindowInfo::InputConfig::PAUSE_DISPATCHING, paused);
    }

    void setPreventSplitting(bool preventSplitting) {
        mInfo.setInputConfig(WindowInfo::InputConfig::PREVENT_SPLITTING, preventSplitting);
    }

    void setSlippery(bool slippery) {
        mInfo.setInputConfig(WindowInfo::InputConfig::SLIPPERY, slippery);
    }

    void setWatchOutsideTouch(bool watchOutside) {
        mInfo.setInputConfig(WindowInfo::InputConfig::WATCH_OUTSIDE_TOUCH, watchOutside);
    }

    void setSpy(bool spy) { mInfo.setInputConfig(WindowInfo::InputConfig::SPY, spy); }

    void setInterceptsStylus(bool interceptsStylus) {
        mInfo.setInputConfig(WindowInfo::InputConfig::INTERCEPTS_STYLUS, interceptsStylus);
    }

    void setDropInput(bool dropInput) {
        mInfo.setInputConfig(WindowInfo::InputConfig::DROP_INPUT, dropInput);
    }

    void setDropInputIfObscured(bool dropInputIfObscured) {
        mInfo.setInputConfig(WindowInfo::InputConfig::DROP_INPUT_IF_OBSCURED, dropInputIfObscured);
    }

    void setNoInputChannel(bool noInputChannel) {
        mInfo.setInputConfig(WindowInfo::InputConfig::NO_INPUT_CHANNEL, noInputChannel);
    }

    void setDisableUserActivity(bool disableUserActivity) {
        mInfo.setInputConfig(WindowInfo::InputConfig::DISABLE_USER_ACTIVITY, disableUserActivity);
    }

    void setAlpha(float alpha) { mInfo.alpha = alpha; }

    void setTouchOcclusionMode(TouchOcclusionMode mode) { mInfo.touchOcclusionMode = mode; }

    void setApplicationToken(sp<IBinder> token) { mInfo.applicationInfo.token = token; }

    void setFrame(const Rect& frame, const ui::Transform& displayTransform = ui::Transform()) {
        mInfo.frame.left = frame.left;
        mInfo.frame.top = frame.top;
        mInfo.frame.right = frame.right;
        mInfo.frame.bottom = frame.bottom;
        mInfo.touchableRegion.clear();
        mInfo.addTouchableRegion(frame);

        const Rect logicalDisplayFrame = displayTransform.transform(frame);
        ui::Transform translate;
        translate.set(-logicalDisplayFrame.left, -logicalDisplayFrame.top);
        mInfo.transform = translate * displayTransform;
    }

    void setTouchableRegion(const Region& region) { mInfo.touchableRegion = region; }

    void setIsWallpaper(bool isWallpaper) {
        mInfo.setInputConfig(WindowInfo::InputConfig::IS_WALLPAPER, isWallpaper);
    }

    void setDupTouchToWallpaper(bool hasWallpaper) {
        mInfo.setInputConfig(WindowInfo::InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER, hasWallpaper);
    }

    void setTrustedOverlay(bool trustedOverlay) {
        mInfo.setInputConfig(WindowInfo::InputConfig::TRUSTED_OVERLAY, trustedOverlay);
    }

    void setWindowTransform(float dsdx, float dtdx, float dtdy, float dsdy) {
        mInfo.transform.set(dsdx, dtdx, dtdy, dsdy);
    }

    void setWindowScale(float xScale, float yScale) { setWindowTransform(xScale, 0, 0, yScale); }

    void setWindowOffset(float offsetX, float offsetY) { mInfo.transform.set(offsetX, offsetY); }

    std::unique_ptr<InputEvent> consume(std::chrono::milliseconds timeout) {
        if (mInputReceiver == nullptr) {
            return nullptr;
        }
        return mInputReceiver->consumeEvent(timeout);
    }

    void consumeMotion() {
        std::unique_ptr<InputEvent> event = consume(100ms);

        if (event == nullptr) {
            LOG(FATAL) << mName << ": expected a MotionEvent, but didn't get one.";
            return;
        }

        if (event->getType() != InputEventType::MOTION) {
            LOG(FATAL) << mName << " expected a MotionEvent, got " << *event;
            return;
        }
    }

    sp<IBinder> getToken() { return mInfo.token; }

    const std::string& getName() { return mName; }

    void setOwnerInfo(Pid ownerPid, Uid ownerUid) {
        mInfo.ownerPid = ownerPid;
        mInfo.ownerUid = ownerUid;
    }

    Pid getPid() const { return mInfo.ownerPid; }

    void destroyReceiver() { mInputReceiver = nullptr; }

private:
    FakeWindowHandle(std::string name) : mName(name){};
    const std::string mName;
    std::shared_ptr<FakeInputReceiver> mInputReceiver;
    static std::atomic<int32_t> sId; // each window gets a unique id, like in surfaceflinger
    friend class sp<FakeWindowHandle>;
};

std::atomic<int32_t> FakeWindowHandle::sId{1};

} // namespace inputdispatcher

} // namespace android
