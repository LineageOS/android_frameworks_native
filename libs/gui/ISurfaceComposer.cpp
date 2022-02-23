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
#include <android/gui/ITransactionTraceListener.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/ISurfaceComposer.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerState.h>
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

    virtual sp<ISurfaceComposerClient> createConnection()
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        remote()->transact(BnSurfaceComposer::CREATE_CONNECTION, data, &reply);
        return interface_cast<ISurfaceComposerClient>(reply.readStrongBinder());
    }

    status_t setTransactionState(const FrameTimelineInfo& frameTimelineInfo,
                                 const Vector<ComposerState>& state,
                                 const Vector<DisplayState>& displays, uint32_t flags,
                                 const sp<IBinder>& applyToken, const InputWindowCommands& commands,
                                 int64_t desiredPresentTime, bool isAutoTimestamp,
                                 const client_cache_t& uncacheBuffer, bool hasListenerCallbacks,
                                 const std::vector<ListenerCallbacks>& listenerCallbacks,
                                 uint64_t transactionId) override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());

        SAFE_PARCEL(frameTimelineInfo.write, data);

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
        SAFE_PARCEL(data.writeStrongBinder, uncacheBuffer.token.promote());
        SAFE_PARCEL(data.writeUint64, uncacheBuffer.id);
        SAFE_PARCEL(data.writeBool, hasListenerCallbacks);

        SAFE_PARCEL(data.writeVectorSize, listenerCallbacks);
        for (const auto& [listener, callbackIds] : listenerCallbacks) {
            SAFE_PARCEL(data.writeStrongBinder, listener);
            SAFE_PARCEL(data.writeParcelableVector, callbackIds);
        }

        SAFE_PARCEL(data.writeUint64, transactionId);

        if (flags & ISurfaceComposer::eOneWay) {
            return remote()->transact(BnSurfaceComposer::SET_TRANSACTION_STATE,
                    data, &reply, IBinder::FLAG_ONEWAY);
        } else {
            return remote()->transact(BnSurfaceComposer::SET_TRANSACTION_STATE,
                    data, &reply);
        }
    }

    void bootFinished() override {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        remote()->transact(BnSurfaceComposer::BOOT_FINISHED, data, &reply);
    }

    bool authenticateSurfaceTexture(
            const sp<IGraphicBufferProducer>& bufferProducer) const override {
        Parcel data, reply;
        int err = NO_ERROR;
        err = data.writeInterfaceToken(
                ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            ALOGE("ISurfaceComposer::authenticateSurfaceTexture: error writing "
                    "interface descriptor: %s (%d)", strerror(-err), -err);
            return false;
        }
        err = data.writeStrongBinder(IInterface::asBinder(bufferProducer));
        if (err != NO_ERROR) {
            ALOGE("ISurfaceComposer::authenticateSurfaceTexture: error writing "
                    "strong binder to parcel: %s (%d)", strerror(-err), -err);
            return false;
        }
        err = remote()->transact(BnSurfaceComposer::AUTHENTICATE_SURFACE, data,
                &reply);
        if (err != NO_ERROR) {
            ALOGE("ISurfaceComposer::authenticateSurfaceTexture: error "
                    "performing transaction: %s (%d)", strerror(-err), -err);
            return false;
        }
        int32_t result = 0;
        err = reply.readInt32(&result);
        if (err != NO_ERROR) {
            ALOGE("ISurfaceComposer::authenticateSurfaceTexture: error "
                    "retrieving result: %s (%d)", strerror(-err), -err);
            return false;
        }
        return result != 0;
    }

    sp<IDisplayEventConnection> createDisplayEventConnection(
            VsyncSource vsyncSource, EventRegistrationFlags eventRegistration) override {
        Parcel data, reply;
        sp<IDisplayEventConnection> result;
        int err = data.writeInterfaceToken(
                ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            return result;
        }
        data.writeInt32(static_cast<int32_t>(vsyncSource));
        data.writeUint32(eventRegistration.get());
        err = remote()->transact(
                BnSurfaceComposer::CREATE_DISPLAY_EVENT_CONNECTION,
                data, &reply);
        if (err != NO_ERROR) {
            ALOGE("ISurfaceComposer::createDisplayEventConnection: error performing "
                    "transaction: %s (%d)", strerror(-err), -err);
            return result;
        }
        result = interface_cast<IDisplayEventConnection>(reply.readStrongBinder());
        return result;
    }

    status_t getDisplayedContentSample(const sp<IBinder>& display, uint64_t maxFrames,
                                       uint64_t timestamp,
                                       DisplayedFrameStats* outStats) const override {
        if (!outStats) return BAD_VALUE;

        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        data.writeUint64(maxFrames);
        data.writeUint64(timestamp);

        status_t result =
                remote()->transact(BnSurfaceComposer::GET_DISPLAYED_CONTENT_SAMPLE, data, &reply);

        if (result != NO_ERROR) {
            return result;
        }

        result = reply.readUint64(&outStats->numFrames);
        if (result != NO_ERROR) {
            return result;
        }

        result = reply.readUint64Vector(&outStats->component_0_sample);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readUint64Vector(&outStats->component_1_sample);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readUint64Vector(&outStats->component_2_sample);
        if (result != NO_ERROR) {
            return result;
        }
        result = reply.readUint64Vector(&outStats->component_3_sample);
        return result;
    }

    status_t setGlobalShadowSettings(const half4& ambientColor, const half4& spotColor,
                                     float lightPosY, float lightPosZ, float lightRadius) override {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("setGlobalShadowSettings: failed to write interface token: %d", error);
            return error;
        }

        std::vector<float> shadowConfig = {ambientColor.r, ambientColor.g, ambientColor.b,
                                           ambientColor.a, spotColor.r,    spotColor.g,
                                           spotColor.b,    spotColor.a,    lightPosY,
                                           lightPosZ,      lightRadius};

        error = data.writeFloatVector(shadowConfig);
        if (error != NO_ERROR) {
            ALOGE("setGlobalShadowSettings: failed to write shadowConfig: %d", error);
            return error;
        }

        error = remote()->transact(BnSurfaceComposer::SET_GLOBAL_SHADOW_SETTINGS, data, &reply,
                                   IBinder::FLAG_ONEWAY);
        if (error != NO_ERROR) {
            ALOGE("setGlobalShadowSettings: failed to transact: %d", error);
            return error;
        }
        return NO_ERROR;
    }

    status_t getDisplayDecorationSupport(
            const sp<IBinder>& displayToken,
            std::optional<common::DisplayDecorationSupport>* outSupport) const override {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("getDisplayDecorationSupport: failed to write interface token: %d", error);
            return error;
        }
        error = data.writeStrongBinder(displayToken);
        if (error != NO_ERROR) {
            ALOGE("getDisplayDecorationSupport: failed to write display token: %d", error);
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::GET_DISPLAY_DECORATION_SUPPORT, data, &reply);
        if (error != NO_ERROR) {
            ALOGE("getDisplayDecorationSupport: failed to transact: %d", error);
            return error;
        }
        bool support;
        error = reply.readBool(&support);
        if (error != NO_ERROR) {
            ALOGE("getDisplayDecorationSupport: failed to read support: %d", error);
            return error;
        }

        if (support) {
            int32_t format, alphaInterpretation;
            error = reply.readInt32(&format);
            if (error != NO_ERROR) {
                ALOGE("getDisplayDecorationSupport: failed to read format: %d", error);
                return error;
            }
            error = reply.readInt32(&alphaInterpretation);
            if (error != NO_ERROR) {
                ALOGE("getDisplayDecorationSupport: failed to read alphaInterpretation: %d", error);
                return error;
            }
            outSupport->emplace();
            outSupport->value().format = static_cast<common::PixelFormat>(format);
            outSupport->value().alphaInterpretation =
                    static_cast<common::AlphaInterpretation>(alphaInterpretation);
        } else {
            outSupport->reset();
        }
        return NO_ERROR;
    }

    status_t setFrameRate(const sp<IGraphicBufferProducer>& surface, float frameRate,
                          int8_t compatibility, int8_t changeFrameRateStrategy) override {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(surface));
        SAFE_PARCEL(data.writeFloat, frameRate);
        SAFE_PARCEL(data.writeByte, compatibility);
        SAFE_PARCEL(data.writeByte, changeFrameRateStrategy);

        status_t err = remote()->transact(BnSurfaceComposer::SET_FRAME_RATE, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("setFrameRate: failed to transact: %s (%d)", strerror(-err), err);
            return err;
        }

        return reply.readInt32();
    }

    status_t setFrameTimelineInfo(const sp<IGraphicBufferProducer>& surface,
                                  const FrameTimelineInfo& frameTimelineInfo) override {
        Parcel data, reply;
        status_t err = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            ALOGE("%s: failed writing interface token: %s (%d)", __func__, strerror(-err), -err);
            return err;
        }

        err = data.writeStrongBinder(IInterface::asBinder(surface));
        if (err != NO_ERROR) {
            ALOGE("%s: failed writing strong binder: %s (%d)", __func__, strerror(-err), -err);
            return err;
        }

        SAFE_PARCEL(frameTimelineInfo.write, data);

        err = remote()->transact(BnSurfaceComposer::SET_FRAME_TIMELINE_INFO, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("%s: failed to transact: %s (%d)", __func__, strerror(-err), err);
            return err;
        }

        return reply.readInt32();
    }

    status_t setOverrideFrameRate(uid_t uid, float frameRate) override {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeUint32, uid);
        SAFE_PARCEL(data.writeFloat, frameRate);

        status_t err = remote()->transact(BnSurfaceComposer::SET_OVERRIDE_FRAME_RATE, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("setOverrideFrameRate: failed to transact %s (%d)", strerror(-err), err);
            return err;
        }

        return NO_ERROR;
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
    switch(code) {
        case CREATE_CONNECTION: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> b = IInterface::asBinder(createConnection());
            reply->writeStrongBinder(b);
            return NO_ERROR;
        }
        case SET_TRANSACTION_STATE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            FrameTimelineInfo frameTimelineInfo;
            SAFE_PARCEL(frameTimelineInfo.read, data);

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

            client_cache_t uncachedBuffer;
            sp<IBinder> tmpBinder;
            SAFE_PARCEL(data.readNullableStrongBinder, &tmpBinder);
            uncachedBuffer.token = tmpBinder;
            SAFE_PARCEL(data.readUint64, &uncachedBuffer.id);

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

            return setTransactionState(frameTimelineInfo, state, displays, stateFlags, applyToken,
                                       inputWindowCommands, desiredPresentTime, isAutoTimestamp,
                                       uncachedBuffer, hasListenerCallbacks, listenerCallbacks,
                                       transactionId);
        }
        case BOOT_FINISHED: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            bootFinished();
            return NO_ERROR;
        }
        case AUTHENTICATE_SURFACE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IGraphicBufferProducer> bufferProducer =
                    interface_cast<IGraphicBufferProducer>(data.readStrongBinder());
            int32_t result = authenticateSurfaceTexture(bufferProducer) ? 1 : 0;
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case CREATE_DISPLAY_EVENT_CONNECTION: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            auto vsyncSource = static_cast<ISurfaceComposer::VsyncSource>(data.readInt32());
            EventRegistrationFlags eventRegistration =
                    static_cast<EventRegistration>(data.readUint32());

            sp<IDisplayEventConnection> connection(
                    createDisplayEventConnection(vsyncSource, eventRegistration));
            reply->writeStrongBinder(IInterface::asBinder(connection));
            return NO_ERROR;
        }
        case GET_DISPLAYED_CONTENT_SAMPLE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            sp<IBinder> display = data.readStrongBinder();
            uint64_t maxFrames = 0;
            uint64_t timestamp = 0;

            status_t result = data.readUint64(&maxFrames);
            if (result != NO_ERROR) {
                ALOGE("getDisplayedContentSample failure in reading max frames: %d", result);
                return result;
            }

            result = data.readUint64(&timestamp);
            if (result != NO_ERROR) {
                ALOGE("getDisplayedContentSample failure in reading timestamp: %d", result);
                return result;
            }

            DisplayedFrameStats stats;
            result = getDisplayedContentSample(display, maxFrames, timestamp, &stats);
            if (result == NO_ERROR) {
                reply->writeUint64(stats.numFrames);
                reply->writeUint64Vector(stats.component_0_sample);
                reply->writeUint64Vector(stats.component_1_sample);
                reply->writeUint64Vector(stats.component_2_sample);
                reply->writeUint64Vector(stats.component_3_sample);
            }
            return result;
        }
        case SET_GLOBAL_SHADOW_SETTINGS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            std::vector<float> shadowConfig;
            status_t error = data.readFloatVector(&shadowConfig);
            if (error != NO_ERROR || shadowConfig.size() != 11) {
                ALOGE("setGlobalShadowSettings: failed to read shadowConfig: %d", error);
                return error;
            }

            half4 ambientColor = {shadowConfig[0], shadowConfig[1], shadowConfig[2],
                                  shadowConfig[3]};
            half4 spotColor = {shadowConfig[4], shadowConfig[5], shadowConfig[6], shadowConfig[7]};
            float lightPosY = shadowConfig[8];
            float lightPosZ = shadowConfig[9];
            float lightRadius = shadowConfig[10];
            return setGlobalShadowSettings(ambientColor, spotColor, lightPosY, lightPosZ,
                                           lightRadius);
        }
        case GET_DISPLAY_DECORATION_SUPPORT: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> displayToken;
            SAFE_PARCEL(data.readNullableStrongBinder, &displayToken);
            std::optional<common::DisplayDecorationSupport> support;
            auto error = getDisplayDecorationSupport(displayToken, &support);
            if (error != NO_ERROR) {
                ALOGE("getDisplayDecorationSupport failed with error %d", error);
                return error;
            }
            reply->writeBool(support.has_value());
            if (support) {
                reply->writeInt32(static_cast<int32_t>(support.value().format));
                reply->writeInt32(static_cast<int32_t>(support.value().alphaInterpretation));
            }
            return error;
        }
        case SET_FRAME_RATE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> binder;
            SAFE_PARCEL(data.readStrongBinder, &binder);

            sp<IGraphicBufferProducer> surface = interface_cast<IGraphicBufferProducer>(binder);
            if (!surface) {
                ALOGE("setFrameRate: failed to cast to IGraphicBufferProducer");
                return BAD_VALUE;
            }
            float frameRate;
            SAFE_PARCEL(data.readFloat, &frameRate);

            int8_t compatibility;
            SAFE_PARCEL(data.readByte, &compatibility);

            int8_t changeFrameRateStrategy;
            SAFE_PARCEL(data.readByte, &changeFrameRateStrategy);

            status_t result =
                    setFrameRate(surface, frameRate, compatibility, changeFrameRateStrategy);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case SET_FRAME_TIMELINE_INFO: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> binder;
            status_t err = data.readStrongBinder(&binder);
            if (err != NO_ERROR) {
                ALOGE("setFrameTimelineInfo: failed to read strong binder: %s (%d)", strerror(-err),
                      -err);
                return err;
            }
            sp<IGraphicBufferProducer> surface = interface_cast<IGraphicBufferProducer>(binder);
            if (!surface) {
                ALOGE("setFrameTimelineInfo: failed to cast to IGraphicBufferProducer: %s (%d)",
                      strerror(-err), -err);
                return err;
            }

            FrameTimelineInfo frameTimelineInfo;
            SAFE_PARCEL(frameTimelineInfo.read, data);

            status_t result = setFrameTimelineInfo(surface, frameTimelineInfo);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case SET_OVERRIDE_FRAME_RATE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            uid_t uid;
            SAFE_PARCEL(data.readUint32, &uid);

            float frameRate;
            SAFE_PARCEL(data.readFloat, &frameRate);

            return setOverrideFrameRate(uid, frameRate);
        }
        default: {
            return BBinder::onTransact(code, data, reply, flags);
        }
    }
}

} // namespace android
