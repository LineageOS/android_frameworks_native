/*
 * Copyright (C) 2011 The Android Open Source Project
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

#define LOG_TAG "DisplayEventReceiver"

#include <string.h>

#include <utils/Errors.h>

#include <gui/DisplayEventReceiver.h>
#include <gui/VsyncEventData.h>

#include <private/gui/ComposerServiceAIDL.h>

#include <private/gui/BitTube.h>

// ---------------------------------------------------------------------------

namespace android {

// ---------------------------------------------------------------------------

DisplayEventReceiver::DisplayEventReceiver(gui::ISurfaceComposer::VsyncSource vsyncSource,
                                           EventRegistrationFlags eventRegistration,
                                           const sp<IBinder>& layerHandle) {
    sp<gui::ISurfaceComposer> sf(ComposerServiceAIDL::getComposerService());
    if (sf != nullptr) {
        mEventConnection = nullptr;
        binder::Status status =
                sf->createDisplayEventConnection(vsyncSource,
                                                 static_cast<
                                                         gui::ISurfaceComposer::EventRegistration>(
                                                         eventRegistration.get()),
                                                 layerHandle, &mEventConnection);
        if (status.isOk() && mEventConnection != nullptr) {
            mDataChannel = std::make_unique<gui::BitTube>();
            status = mEventConnection->stealReceiveChannel(mDataChannel.get());
            if (!status.isOk()) {
                ALOGE("stealReceiveChannel failed: %s", status.toString8().c_str());
                mInitError = std::make_optional<status_t>(status.transactionError());
                mDataChannel.reset();
                mEventConnection.clear();
            }
        } else {
            ALOGE("DisplayEventConnection creation failed: status=%s", status.toString8().c_str());
        }
    }
}

DisplayEventReceiver::~DisplayEventReceiver() {
}

status_t DisplayEventReceiver::initCheck() const {
    if (mDataChannel != nullptr)
        return NO_ERROR;
    return mInitError.has_value() ? mInitError.value() : NO_INIT;
}

int DisplayEventReceiver::getFd() const {
    if (mDataChannel == nullptr) return mInitError.has_value() ? mInitError.value() : NO_INIT;

    return mDataChannel->getFd();
}

status_t DisplayEventReceiver::setVsyncRate(uint32_t count) {
    if (int32_t(count) < 0)
        return BAD_VALUE;

    if (mEventConnection != nullptr) {
        mEventConnection->setVsyncRate(count);
        return NO_ERROR;
    }
    return mInitError.has_value() ? mInitError.value() : NO_INIT;
}

status_t DisplayEventReceiver::requestNextVsync() {
    if (mEventConnection != nullptr) {
        mEventConnection->requestNextVsync();
        return NO_ERROR;
    }
    return mInitError.has_value() ? mInitError.value() : NO_INIT;
}

status_t DisplayEventReceiver::getLatestVsyncEventData(
        ParcelableVsyncEventData* outVsyncEventData) const {
    if (mEventConnection != nullptr) {
        auto status = mEventConnection->getLatestVsyncEventData(outVsyncEventData);
        if (!status.isOk()) {
            ALOGE("Failed to get latest vsync event data: %s", status.toString8().c_str());
            return status.transactionError();
        }
        return NO_ERROR;
    }
    return NO_INIT;
}

ssize_t DisplayEventReceiver::getEvents(DisplayEventReceiver::Event* events,
        size_t count) {
    return DisplayEventReceiver::getEvents(mDataChannel.get(), events, count);
}

ssize_t DisplayEventReceiver::getEvents(gui::BitTube* dataChannel,
        Event* events, size_t count)
{
    return gui::BitTube::recvObjects(dataChannel, events, count);
}

ssize_t DisplayEventReceiver::sendEvents(Event const* events, size_t count) {
    return DisplayEventReceiver::sendEvents(mDataChannel.get(), events, count);
}

ssize_t DisplayEventReceiver::sendEvents(gui::BitTube* dataChannel,
        Event const* events, size_t count)
{
    return gui::BitTube::sendObjects(dataChannel, events, count);
}

// ---------------------------------------------------------------------------

}; // namespace android
