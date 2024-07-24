/*
 * Copyright (C) 2007 The Android Open Source Project
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

// tag as surfaceflinger
#define LOG_TAG "SurfaceFlinger"

#include <android/gui/IDisplayEventConnection.h>
#include <android/gui/IRegionSamplingListener.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/ISurfaceComposer.h>
#include <gui/LayerState.h>
#include <gui/SchedulingPolicy.h>
#include <private/gui/ParcelUtils.h>
#include <stdint.h>
#include <sys/types.h>
#include <system/graphics.h>
#include <ui/DisplayMode.h>
#include <ui/DisplayStatInfo.h>
#include <ui/DisplayState.h>
#include <ui/DynamicDisplayInfo.h>
#include <ui/HdrCapabilities.h>
#include <utils/Log.h>

// ---------------------------------------------------------------------------

using namespace aidl::android::hardware::graphics;

namespace android {

using gui::DisplayCaptureArgs;
using gui::IDisplayEventConnection;
using gui::IRegionSamplingListener;
using gui::IWindowInfosListener;
using gui::LayerCaptureArgs;
using ui::ColorMode;

class BpSurfaceComposer : public BpInterface<ISurfaceComposer>
{
public:
    explicit BpSurfaceComposer(const sp<IBinder>& impl)
        : BpInterface<ISurfaceComposer>(impl)
    {
    }

    virtual ~BpSurfaceComposer();

    status_t setTransactionState(
            const FrameTimelineInfo& frameTimelineInfo, Vector<ComposerState>& state,
            Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
            InputWindowCommands commands, int64_t desiredPresentTime, bool isAutoTimestamp,
            const std::vector<client_cache_t>& uncacheBuffers, bool hasListenerCallbacks,
            const std::vector<ListenerCallbacks>& listenerCallbacks, uint64_t transactionId,
            const std::vector<uint64_t>& mergedTransactionIds) override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());

        frameTimelineInfo.writeToParcel(&data);

        SAFE_PARCEL(data.writeUint32, static_cast<uint32_t>(state.size()));
        for (const auto& s : state) {
            SAFE_PARCEL(s.write, data);
        }

        SAFE_PARCEL(data.writeUint32, static_cast<uint32_t>(displays.size()));
        for (const auto& d : displays) {
            SAFE_PARCEL(d.write, data);
        }

        SAFE_PARCEL(data.writeUint32, flags);
        SAFE_PARCEL(data.writeStrongBinder, applyToken);
        SAFE_PARCEL(commands.write, data);
        SAFE_PARCEL(data.writeInt64, desiredPresentTime);
        SAFE_PARCEL(data.writeBool, isAutoTimestamp);
        SAFE_PARCEL(data.writeUint32, static_cast<uint32_t>(uncacheBuffers.size()));
        for (const client_cache_t& uncacheBuffer : uncacheBuffers) {
            SAFE_PARCEL(data.writeStrongBinder, uncacheBuffer.token.promote());
            SAFE_PARCEL(data.writeUint64, uncacheBuffer.id);
        }
        SAFE_PARCEL(data.writeBool, hasListenerCallbacks);

        SAFE_PARCEL(data.writeVectorSize, listenerCallbacks);
        for (const auto& [listener, callbackIds] : listenerCallbacks) {
            SAFE_PARCEL(data.writeStrongBinder, listener);
            SAFE_PARCEL(data.writeParcelableVector, callbackIds);
        }

        SAFE_PARCEL(data.writeUint64, transactionId);

        SAFE_PARCEL(data.writeUint32, static_cast<uint32_t>(mergedTransactionIds.size()));
        for (auto mergedTransactionId : mergedTransactionIds) {
            SAFE_PARCEL(data.writeUint64, mergedTransactionId);
        }

        if (flags & ISurfaceComposer::eOneWay) {
            return remote()->transact(BnSurfaceComposer::SET_TRANSACTION_STATE,
                    data, &reply, IBinder::FLAG_ONEWAY);
        } else {
            return remote()->transact(BnSurfaceComposer::SET_TRANSACTION_STATE,
                    data, &reply);
        }
    }
};

// Out-of-line virtual method definition to trigger vtable emission in this
// translation unit (see clang warning -Wweak-vtables)
BpSurfaceComposer::~BpSurfaceComposer() {}

IMPLEMENT_META_INTERFACE(SurfaceComposer, "android.ui.ISurfaceComposer");

// ----------------------------------------------------------------------

status_t BnSurfaceComposer::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    switch (code) {
        case SET_TRANSACTION_STATE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            FrameTimelineInfo frameTimelineInfo;
            frameTimelineInfo.readFromParcel(&data);

            uint32_t count = 0;
            SAFE_PARCEL_READ_SIZE(data.readUint32, &count, data.dataSize());
            Vector<ComposerState> state;
            state.setCapacity(count);
            for (size_t i = 0; i < count; i++) {
                ComposerState s;
                SAFE_PARCEL(s.read, data);
                state.add(s);
            }

            SAFE_PARCEL_READ_SIZE(data.readUint32, &count, data.dataSize());
            DisplayState d;
            Vector<DisplayState> displays;
            displays.setCapacity(count);
            for (size_t i = 0; i < count; i++) {
                SAFE_PARCEL(d.read, data);
                displays.add(d);
            }

            uint32_t stateFlags = 0;
            SAFE_PARCEL(data.readUint32, &stateFlags);
            sp<IBinder> applyToken;
            SAFE_PARCEL(data.readStrongBinder, &applyToken);
            InputWindowCommands inputWindowCommands;
            SAFE_PARCEL(inputWindowCommands.read, data);

            int64_t desiredPresentTime = 0;
            bool isAutoTimestamp = true;
            SAFE_PARCEL(data.readInt64, &desiredPresentTime);
            SAFE_PARCEL(data.readBool, &isAutoTimestamp);

            SAFE_PARCEL_READ_SIZE(data.readUint32, &count, data.dataSize());
            std::vector<client_cache_t> uncacheBuffers(count);
            sp<IBinder> tmpBinder;
            for (size_t i = 0; i < count; i++) {
                SAFE_PARCEL(data.readNullableStrongBinder, &tmpBinder);
                uncacheBuffers[i].token = tmpBinder;
                SAFE_PARCEL(data.readUint64, &uncacheBuffers[i].id);
            }

            bool hasListenerCallbacks = false;
            SAFE_PARCEL(data.readBool, &hasListenerCallbacks);

            std::vector<ListenerCallbacks> listenerCallbacks;
            int32_t listenersSize = 0;
            SAFE_PARCEL_READ_SIZE(data.readInt32, &listenersSize, data.dataSize());
            for (int32_t i = 0; i < listenersSize; i++) {
                SAFE_PARCEL(data.readStrongBinder, &tmpBinder);
                std::vector<CallbackId> callbackIds;
                SAFE_PARCEL(data.readParcelableVector, &callbackIds);
                listenerCallbacks.emplace_back(tmpBinder, callbackIds);
            }

            uint64_t transactionId = -1;
            SAFE_PARCEL(data.readUint64, &transactionId);

            SAFE_PARCEL_READ_SIZE(data.readUint32, &count, data.dataSize());
            std::vector<uint64_t> mergedTransactions(count);
            for (size_t i = 0; i < count; i++) {
                SAFE_PARCEL(data.readUint64, &mergedTransactions[i]);
            }

            return setTransactionState(frameTimelineInfo, state, displays, stateFlags, applyToken,
                                       std::move(inputWindowCommands), desiredPresentTime,
                                       isAutoTimestamp, uncacheBuffers, hasListenerCallbacks,
                                       listenerCallbacks, transactionId, mergedTransactions);
        }
        case GET_SCHEDULING_POLICY: {
            gui::SchedulingPolicy policy;
            const auto status = gui::getSchedulingPolicy(&policy);
            if (!status.isOk()) {
                return status.exceptionCode();
            }

            SAFE_PARCEL(reply->writeInt32, policy.policy);
            SAFE_PARCEL(reply->writeInt32, policy.priority);
            return NO_ERROR;
        }

        default: {
            return BBinder::onTransact(code, data, reply, flags);
        }
    }
}

} // namespace android
