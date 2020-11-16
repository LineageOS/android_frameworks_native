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

#include <stdint.h>
#include <sys/types.h>

#include <android/gui/ITransactionTraceListener.h>

#include <binder/Parcel.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

#include <gui/IDisplayEventConnection.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/IRegionSamplingListener.h>
#include <gui/ISurfaceComposer.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/LayerDebugInfo.h>
#include <gui/LayerState.h>

#include <system/graphics.h>

#include <ui/DisplayConfig.h>
#include <ui/DisplayInfo.h>
#include <ui/DisplayStatInfo.h>
#include <ui/DisplayState.h>
#include <ui/HdrCapabilities.h>

#include <utils/Log.h>

// ---------------------------------------------------------------------------

namespace android {

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

    virtual status_t setTransactionState(
            int64_t frameTimelineVsyncId, const Vector<ComposerState>& state,
            const Vector<DisplayState>& displays, uint32_t flags, const sp<IBinder>& applyToken,
            const InputWindowCommands& commands, int64_t desiredPresentTime,
            const client_cache_t& uncacheBuffer, bool hasListenerCallbacks,
            const std::vector<ListenerCallbacks>& listenerCallbacks, uint64_t transactionId) {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());

        SAFE_PARCEL(data.writeInt64, frameTimelineVsyncId);
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
        SAFE_PARCEL(data.writeStrongBinder, uncacheBuffer.token.promote());
        SAFE_PARCEL(data.writeUint64, uncacheBuffer.id);
        SAFE_PARCEL(data.writeBool, hasListenerCallbacks);

        SAFE_PARCEL(data.writeVectorSize, listenerCallbacks);
        for (const auto& [listener, callbackIds] : listenerCallbacks) {
            SAFE_PARCEL(data.writeStrongBinder, listener);
            SAFE_PARCEL(data.writeInt64Vector, callbackIds);
        }

        SAFE_PARCEL(data.writeUint64, transactionId);

        return remote()->transact(BnSurfaceComposer::SET_TRANSACTION_STATE, data, &reply);
    }

    virtual void bootFinished()
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        remote()->transact(BnSurfaceComposer::BOOT_FINISHED, data, &reply);
    }

    virtual status_t captureDisplay(const DisplayCaptureArgs& args,
                                    const sp<IScreenCaptureListener>& captureListener) {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(args.write, data);
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(captureListener));

        return remote()->transact(BnSurfaceComposer::CAPTURE_DISPLAY, data, &reply);
    }

    virtual status_t captureDisplay(uint64_t displayOrLayerStack,
                                    const sp<IScreenCaptureListener>& captureListener) {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeUint64, displayOrLayerStack);
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(captureListener));

        return remote()->transact(BnSurfaceComposer::CAPTURE_DISPLAY_BY_ID, data, &reply);
    }

    virtual status_t captureLayers(const LayerCaptureArgs& args,
                                   const sp<IScreenCaptureListener>& captureListener) {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(args.write, data);
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(captureListener));

        return remote()->transact(BnSurfaceComposer::CAPTURE_LAYERS, data, &reply);
    }

    virtual bool authenticateSurfaceTexture(
            const sp<IGraphicBufferProducer>& bufferProducer) const
    {
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

    virtual status_t getSupportedFrameTimestamps(
            std::vector<FrameEvent>* outSupported) const {
        if (!outSupported) {
            return UNEXPECTED_NULL;
        }
        outSupported->clear();

        Parcel data, reply;

        status_t err = data.writeInterfaceToken(
                ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            return err;
        }

        err = remote()->transact(
                BnSurfaceComposer::GET_SUPPORTED_FRAME_TIMESTAMPS,
                data, &reply);
        if (err != NO_ERROR) {
            return err;
        }

        int32_t result = 0;
        err = reply.readInt32(&result);
        if (err != NO_ERROR) {
            return err;
        }
        if (result != NO_ERROR) {
            return result;
        }

        std::vector<int32_t> supported;
        err = reply.readInt32Vector(&supported);
        if (err != NO_ERROR) {
            return err;
        }

        outSupported->reserve(supported.size());
        for (int32_t s : supported) {
            outSupported->push_back(static_cast<FrameEvent>(s));
        }
        return NO_ERROR;
    }

    virtual sp<IDisplayEventConnection> createDisplayEventConnection(VsyncSource vsyncSource,
                                                                     ConfigChanged configChanged) {
        Parcel data, reply;
        sp<IDisplayEventConnection> result;
        int err = data.writeInterfaceToken(
                ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            return result;
        }
        data.writeInt32(static_cast<int32_t>(vsyncSource));
        data.writeInt32(static_cast<int32_t>(configChanged));
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

    virtual sp<IBinder> createDisplay(const String8& displayName, bool secure)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        status_t status = data.writeString8(displayName);
        if (status) {
            return nullptr;
        }
        status = data.writeBool(secure);
        if (status) {
            return nullptr;
        }

        status = remote()->transact(BnSurfaceComposer::CREATE_DISPLAY, data, &reply);
        if (status) {
            return nullptr;
        }
        sp<IBinder> display;
        status = reply.readNullableStrongBinder(&display);
        if (status) {
            return nullptr;
        }
        return display;
    }

    virtual void destroyDisplay(const sp<IBinder>& display)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        remote()->transact(BnSurfaceComposer::DESTROY_DISPLAY, data, &reply);
    }

    virtual std::vector<PhysicalDisplayId> getPhysicalDisplayIds() const {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (remote()->transact(BnSurfaceComposer::GET_PHYSICAL_DISPLAY_IDS, data, &reply) ==
            NO_ERROR) {
            std::vector<uint64_t> rawIds;
            if (reply.readUint64Vector(&rawIds) == NO_ERROR) {
                std::vector<PhysicalDisplayId> displayIds(rawIds.size());
                std::transform(rawIds.begin(), rawIds.end(), displayIds.begin(),
                               [](uint64_t rawId) { return PhysicalDisplayId(rawId); });
                return displayIds;
            }
        }

        return {};
    }

    virtual sp<IBinder> getPhysicalDisplayToken(PhysicalDisplayId displayId) const {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeUint64(displayId.value);
        remote()->transact(BnSurfaceComposer::GET_PHYSICAL_DISPLAY_TOKEN, data, &reply);
        return reply.readStrongBinder();
    }

    virtual void setPowerMode(const sp<IBinder>& display, int mode)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        data.writeInt32(mode);
        remote()->transact(BnSurfaceComposer::SET_POWER_MODE, data, &reply);
    }

    virtual status_t getDisplayState(const sp<IBinder>& display, ui::DisplayState* state) {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        remote()->transact(BnSurfaceComposer::GET_DISPLAY_STATE, data, &reply);
        const status_t result = reply.readInt32();
        if (result == NO_ERROR) {
            memcpy(state, reply.readInplace(sizeof(ui::DisplayState)), sizeof(ui::DisplayState));
        }
        return result;
    }

    virtual status_t getDisplayInfo(const sp<IBinder>& display, DisplayInfo* info) {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        remote()->transact(BnSurfaceComposer::GET_DISPLAY_INFO, data, &reply);
        const status_t result = reply.readInt32();
        if (result != NO_ERROR) return result;
        return reply.read(*info);
    }

    virtual status_t getDisplayConfigs(const sp<IBinder>& display, Vector<DisplayConfig>* configs) {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        remote()->transact(BnSurfaceComposer::GET_DISPLAY_CONFIGS, data, &reply);
        const status_t result = reply.readInt32();
        if (result == NO_ERROR) {
            const size_t numConfigs = reply.readUint32();
            configs->clear();
            configs->resize(numConfigs);
            for (size_t c = 0; c < numConfigs; ++c) {
                memcpy(&(configs->editItemAt(c)), reply.readInplace(sizeof(DisplayConfig)),
                       sizeof(DisplayConfig));
            }
        }
        return result;
    }

    virtual status_t getDisplayStats(const sp<IBinder>& display,
            DisplayStatInfo* stats)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        remote()->transact(BnSurfaceComposer::GET_DISPLAY_STATS, data, &reply);
        status_t result = reply.readInt32();
        if (result == NO_ERROR) {
            memcpy(stats,
                    reply.readInplace(sizeof(DisplayStatInfo)),
                    sizeof(DisplayStatInfo));
        }
        return result;
    }

    virtual int getActiveConfig(const sp<IBinder>& display)
    {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        remote()->transact(BnSurfaceComposer::GET_ACTIVE_CONFIG, data, &reply);
        return reply.readInt32();
    }

    virtual status_t getDisplayColorModes(const sp<IBinder>& display,
            Vector<ColorMode>* outColorModes) {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("getDisplayColorModes failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("getDisplayColorModes failed to writeStrongBinder: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::GET_DISPLAY_COLOR_MODES, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getDisplayColorModes failed to transact: %d", result);
            return result;
        }
        result = static_cast<status_t>(reply.readInt32());
        if (result == NO_ERROR) {
            size_t numModes = reply.readUint32();
            outColorModes->clear();
            outColorModes->resize(numModes);
            for (size_t i = 0; i < numModes; ++i) {
                outColorModes->replaceAt(static_cast<ColorMode>(reply.readInt32()), i);
            }
        }
        return result;
    }

    virtual status_t getDisplayNativePrimaries(const sp<IBinder>& display,
            ui::DisplayPrimaries& primaries) {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("getDisplayNativePrimaries failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("getDisplayNativePrimaries failed to writeStrongBinder: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::GET_DISPLAY_NATIVE_PRIMARIES, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getDisplayNativePrimaries failed to transact: %d", result);
            return result;
        }
        result = reply.readInt32();
        if (result == NO_ERROR) {
            memcpy(&primaries, reply.readInplace(sizeof(ui::DisplayPrimaries)),
                    sizeof(ui::DisplayPrimaries));
        }
        return result;
    }

    virtual ColorMode getActiveColorMode(const sp<IBinder>& display) {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("getActiveColorMode failed to writeInterfaceToken: %d", result);
            return static_cast<ColorMode>(result);
        }
        result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("getActiveColorMode failed to writeStrongBinder: %d", result);
            return static_cast<ColorMode>(result);
        }
        result = remote()->transact(BnSurfaceComposer::GET_ACTIVE_COLOR_MODE, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getActiveColorMode failed to transact: %d", result);
            return static_cast<ColorMode>(result);
        }
        return static_cast<ColorMode>(reply.readInt32());
    }

    virtual status_t setActiveColorMode(const sp<IBinder>& display,
            ColorMode colorMode) {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("setActiveColorMode failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("setActiveColorMode failed to writeStrongBinder: %d", result);
            return result;
        }
        result = data.writeInt32(static_cast<int32_t>(colorMode));
        if (result != NO_ERROR) {
            ALOGE("setActiveColorMode failed to writeInt32: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::SET_ACTIVE_COLOR_MODE, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("setActiveColorMode failed to transact: %d", result);
            return result;
        }
        return static_cast<status_t>(reply.readInt32());
    }

    virtual status_t getAutoLowLatencyModeSupport(const sp<IBinder>& display,
                                                  bool* outSupport) const {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        status_t result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("getAutoLowLatencyModeSupport failed to writeStrongBinder: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::GET_AUTO_LOW_LATENCY_MODE_SUPPORT, data,
                                    &reply);
        if (result != NO_ERROR) {
            ALOGE("getAutoLowLatencyModeSupport failed to transact: %d", result);
            return result;
        }
        return reply.readBool(outSupport);
    }

    virtual void setAutoLowLatencyMode(const sp<IBinder>& display, bool on) {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("setAutoLowLatencyMode failed to writeInterfaceToken: %d", result);
            return;
        }

        result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("setAutoLowLatencyMode failed to writeStrongBinder: %d", result);
            return;
        }
        result = data.writeBool(on);
        if (result != NO_ERROR) {
            ALOGE("setAutoLowLatencyMode failed to writeBool: %d", result);
            return;
        }
        result = remote()->transact(BnSurfaceComposer::SET_AUTO_LOW_LATENCY_MODE, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("setAutoLowLatencyMode failed to transact: %d", result);
            return;
        }
    }

    virtual status_t getGameContentTypeSupport(const sp<IBinder>& display, bool* outSupport) const {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        status_t result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("getGameContentTypeSupport failed to writeStrongBinder: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::GET_GAME_CONTENT_TYPE_SUPPORT, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getGameContentTypeSupport failed to transact: %d", result);
            return result;
        }
        return reply.readBool(outSupport);
    }

    virtual void setGameContentType(const sp<IBinder>& display, bool on) {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("setGameContentType failed to writeInterfaceToken: %d", result);
            return;
        }
        result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("setGameContentType failed to writeStrongBinder: %d", result);
            return;
        }
        result = data.writeBool(on);
        if (result != NO_ERROR) {
            ALOGE("setGameContentType failed to writeBool: %d", result);
            return;
        }
        result = remote()->transact(BnSurfaceComposer::SET_GAME_CONTENT_TYPE, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("setGameContentType failed to transact: %d", result);
        }
    }

    virtual status_t clearAnimationFrameStats() {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("clearAnimationFrameStats failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::CLEAR_ANIMATION_FRAME_STATS, data, &reply);
        if (result != NO_ERROR) {
            ALOGE("clearAnimationFrameStats failed to transact: %d", result);
            return result;
        }
        return reply.readInt32();
    }

    virtual status_t getAnimationFrameStats(FrameStats* outStats) const {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        remote()->transact(BnSurfaceComposer::GET_ANIMATION_FRAME_STATS, data, &reply);
        reply.read(*outStats);
        return reply.readInt32();
    }

    virtual status_t getHdrCapabilities(const sp<IBinder>& display,
            HdrCapabilities* outCapabilities) const {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        status_t result = data.writeStrongBinder(display);
        if (result != NO_ERROR) {
            ALOGE("getHdrCapabilities failed to writeStrongBinder: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::GET_HDR_CAPABILITIES,
                data, &reply);
        if (result != NO_ERROR) {
            ALOGE("getHdrCapabilities failed to transact: %d", result);
            return result;
        }
        result = reply.readInt32();
        if (result == NO_ERROR) {
            result = reply.read(*outCapabilities);
        }
        return result;
    }

    virtual status_t enableVSyncInjections(bool enable) {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("enableVSyncInjections failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeBool(enable);
        if (result != NO_ERROR) {
            ALOGE("enableVSyncInjections failed to writeBool: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::ENABLE_VSYNC_INJECTIONS, data, &reply,
                                    IBinder::FLAG_ONEWAY);
        if (result != NO_ERROR) {
            ALOGE("enableVSyncInjections failed to transact: %d", result);
            return result;
        }
        return result;
    }

    virtual status_t injectVSync(nsecs_t when) {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("injectVSync failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeInt64(when);
        if (result != NO_ERROR) {
            ALOGE("injectVSync failed to writeInt64: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::INJECT_VSYNC, data, &reply,
                                    IBinder::FLAG_ONEWAY);
        if (result != NO_ERROR) {
            ALOGE("injectVSync failed to transact: %d", result);
            return result;
        }
        return result;
    }

    virtual status_t getLayerDebugInfo(std::vector<LayerDebugInfo>* outLayers) {
        if (!outLayers) {
            return UNEXPECTED_NULL;
        }

        Parcel data, reply;

        status_t err = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            return err;
        }

        err = remote()->transact(BnSurfaceComposer::GET_LAYER_DEBUG_INFO, data, &reply);
        if (err != NO_ERROR) {
            return err;
        }

        int32_t result = 0;
        err = reply.readInt32(&result);
        if (err != NO_ERROR) {
            return err;
        }
        if (result != NO_ERROR) {
            return result;
        }

        outLayers->clear();
        return reply.readParcelableVector(outLayers);
    }

    virtual status_t getCompositionPreference(ui::Dataspace* defaultDataspace,
                                              ui::PixelFormat* defaultPixelFormat,
                                              ui::Dataspace* wideColorGamutDataspace,
                                              ui::PixelFormat* wideColorGamutPixelFormat) const {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::GET_COMPOSITION_PREFERENCE, data, &reply);
        if (error != NO_ERROR) {
            return error;
        }
        error = static_cast<status_t>(reply.readInt32());
        if (error == NO_ERROR) {
            *defaultDataspace = static_cast<ui::Dataspace>(reply.readInt32());
            *defaultPixelFormat = static_cast<ui::PixelFormat>(reply.readInt32());
            *wideColorGamutDataspace = static_cast<ui::Dataspace>(reply.readInt32());
            *wideColorGamutPixelFormat = static_cast<ui::PixelFormat>(reply.readInt32());
        }
        return error;
    }

    virtual status_t getColorManagement(bool* outGetColorManagement) const {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        remote()->transact(BnSurfaceComposer::GET_COLOR_MANAGEMENT, data, &reply);
        bool result;
        status_t err = reply.readBool(&result);
        if (err == NO_ERROR) {
            *outGetColorManagement = result;
        }
        return err;
    }

    virtual status_t getDisplayedContentSamplingAttributes(const sp<IBinder>& display,
                                                           ui::PixelFormat* outFormat,
                                                           ui::Dataspace* outDataspace,
                                                           uint8_t* outComponentMask) const {
        if (!outFormat || !outDataspace || !outComponentMask) return BAD_VALUE;
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);

        status_t error =
                remote()->transact(BnSurfaceComposer::GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES,
                                   data, &reply);
        if (error != NO_ERROR) {
            return error;
        }

        uint32_t value = 0;
        error = reply.readUint32(&value);
        if (error != NO_ERROR) {
            return error;
        }
        *outFormat = static_cast<ui::PixelFormat>(value);

        error = reply.readUint32(&value);
        if (error != NO_ERROR) {
            return error;
        }
        *outDataspace = static_cast<ui::Dataspace>(value);

        error = reply.readUint32(&value);
        if (error != NO_ERROR) {
            return error;
        }
        *outComponentMask = static_cast<uint8_t>(value);
        return error;
    }

    virtual status_t setDisplayContentSamplingEnabled(const sp<IBinder>& display, bool enable,
                                                      uint8_t componentMask, uint64_t maxFrames) {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        data.writeStrongBinder(display);
        data.writeBool(enable);
        data.writeByte(static_cast<int8_t>(componentMask));
        data.writeUint64(maxFrames);
        status_t result =
                remote()->transact(BnSurfaceComposer::SET_DISPLAY_CONTENT_SAMPLING_ENABLED, data,
                                   &reply);
        return result;
    }

    virtual status_t getDisplayedContentSample(const sp<IBinder>& display, uint64_t maxFrames,
                                               uint64_t timestamp,
                                               DisplayedFrameStats* outStats) const {
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

    virtual status_t getProtectedContentSupport(bool* outSupported) const {
        Parcel data, reply;
        data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        status_t error =
                remote()->transact(BnSurfaceComposer::GET_PROTECTED_CONTENT_SUPPORT, data, &reply);
        if (error != NO_ERROR) {
            return error;
        }
        error = reply.readBool(outSupported);
        return error;
    }

    virtual status_t isWideColorDisplay(const sp<IBinder>& token,
                                        bool* outIsWideColorDisplay) const {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            return error;
        }
        error = data.writeStrongBinder(token);
        if (error != NO_ERROR) {
            return error;
        }

        error = remote()->transact(BnSurfaceComposer::IS_WIDE_COLOR_DISPLAY, data, &reply);
        if (error != NO_ERROR) {
            return error;
        }
        error = reply.readBool(outIsWideColorDisplay);
        return error;
    }

    virtual status_t addRegionSamplingListener(const Rect& samplingArea,
                                               const sp<IBinder>& stopLayerHandle,
                                               const sp<IRegionSamplingListener>& listener) {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("addRegionSamplingListener: Failed to write interface token");
            return error;
        }
        error = data.write(samplingArea);
        if (error != NO_ERROR) {
            ALOGE("addRegionSamplingListener: Failed to write sampling area");
            return error;
        }
        error = data.writeStrongBinder(stopLayerHandle);
        if (error != NO_ERROR) {
            ALOGE("addRegionSamplingListener: Failed to write stop layer handle");
            return error;
        }
        error = data.writeStrongBinder(IInterface::asBinder(listener));
        if (error != NO_ERROR) {
            ALOGE("addRegionSamplingListener: Failed to write listener");
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::ADD_REGION_SAMPLING_LISTENER, data, &reply);
        if (error != NO_ERROR) {
            ALOGE("addRegionSamplingListener: Failed to transact");
        }
        return error;
    }

    virtual status_t removeRegionSamplingListener(const sp<IRegionSamplingListener>& listener) {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("removeRegionSamplingListener: Failed to write interface token");
            return error;
        }
        error = data.writeStrongBinder(IInterface::asBinder(listener));
        if (error != NO_ERROR) {
            ALOGE("removeRegionSamplingListener: Failed to write listener");
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::REMOVE_REGION_SAMPLING_LISTENER, data,
                                   &reply);
        if (error != NO_ERROR) {
            ALOGE("removeRegionSamplingListener: Failed to transact");
        }
        return error;
    }

    virtual status_t setDesiredDisplayConfigSpecs(const sp<IBinder>& displayToken,
                                                  int32_t defaultConfig, bool allowGroupSwitching,
                                                  float primaryRefreshRateMin,
                                                  float primaryRefreshRateMax,
                                                  float appRequestRefreshRateMin,
                                                  float appRequestRefreshRateMax) {
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayConfigSpecs: failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeStrongBinder(displayToken);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayConfigSpecs: failed to write display token: %d", result);
            return result;
        }
        result = data.writeInt32(defaultConfig);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayConfigSpecs failed to write defaultConfig: %d", result);
            return result;
        }
        result = data.writeBool(allowGroupSwitching);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayConfigSpecs failed to write allowGroupSwitching: %d", result);
            return result;
        }
        result = data.writeFloat(primaryRefreshRateMin);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayConfigSpecs failed to write primaryRefreshRateMin: %d", result);
            return result;
        }
        result = data.writeFloat(primaryRefreshRateMax);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayConfigSpecs failed to write primaryRefreshRateMax: %d", result);
            return result;
        }
        result = data.writeFloat(appRequestRefreshRateMin);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayConfigSpecs failed to write appRequestRefreshRateMin: %d",
                  result);
            return result;
        }
        result = data.writeFloat(appRequestRefreshRateMax);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayConfigSpecs failed to write appRequestRefreshRateMax: %d",
                  result);
            return result;
        }

        result = remote()->transact(BnSurfaceComposer::SET_DESIRED_DISPLAY_CONFIG_SPECS, data,
                                    &reply);
        if (result != NO_ERROR) {
            ALOGE("setDesiredDisplayConfigSpecs failed to transact: %d", result);
            return result;
        }
        return reply.readInt32();
    }

    virtual status_t getDesiredDisplayConfigSpecs(const sp<IBinder>& displayToken,
                                                  int32_t* outDefaultConfig,
                                                  bool* outAllowGroupSwitching,
                                                  float* outPrimaryRefreshRateMin,
                                                  float* outPrimaryRefreshRateMax,
                                                  float* outAppRequestRefreshRateMin,
                                                  float* outAppRequestRefreshRateMax) {
        if (!outDefaultConfig || !outAllowGroupSwitching || !outPrimaryRefreshRateMin ||
            !outPrimaryRefreshRateMax || !outAppRequestRefreshRateMin ||
            !outAppRequestRefreshRateMax) {
            return BAD_VALUE;
        }
        Parcel data, reply;
        status_t result = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayConfigSpecs failed to writeInterfaceToken: %d", result);
            return result;
        }
        result = data.writeStrongBinder(displayToken);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayConfigSpecs failed to writeStrongBinder: %d", result);
            return result;
        }
        result = remote()->transact(BnSurfaceComposer::GET_DESIRED_DISPLAY_CONFIG_SPECS, data,
                                    &reply);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayConfigSpecs failed to transact: %d", result);
            return result;
        }
        result = reply.readInt32(outDefaultConfig);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayConfigSpecs failed to read defaultConfig: %d", result);
            return result;
        }
        result = reply.readBool(outAllowGroupSwitching);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayConfigSpecs failed to read allowGroupSwitching: %d", result);
            return result;
        }
        result = reply.readFloat(outPrimaryRefreshRateMin);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayConfigSpecs failed to read primaryRefreshRateMin: %d", result);
            return result;
        }
        result = reply.readFloat(outPrimaryRefreshRateMax);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayConfigSpecs failed to read primaryRefreshRateMax: %d", result);
            return result;
        }
        result = reply.readFloat(outAppRequestRefreshRateMin);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayConfigSpecs failed to read appRequestRefreshRateMin: %d",
                  result);
            return result;
        }
        result = reply.readFloat(outAppRequestRefreshRateMax);
        if (result != NO_ERROR) {
            ALOGE("getDesiredDisplayConfigSpecs failed to read appRequestRefreshRateMax: %d",
                  result);
            return result;
        }
        return reply.readInt32();
    }

    virtual status_t getDisplayBrightnessSupport(const sp<IBinder>& displayToken,
                                                 bool* outSupport) const {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("getDisplayBrightnessSupport: failed to write interface token: %d", error);
            return error;
        }
        error = data.writeStrongBinder(displayToken);
        if (error != NO_ERROR) {
            ALOGE("getDisplayBrightnessSupport: failed to write display token: %d", error);
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::GET_DISPLAY_BRIGHTNESS_SUPPORT, data, &reply);
        if (error != NO_ERROR) {
            ALOGE("getDisplayBrightnessSupport: failed to transact: %d", error);
            return error;
        }
        bool support;
        error = reply.readBool(&support);
        if (error != NO_ERROR) {
            ALOGE("getDisplayBrightnessSupport: failed to read support: %d", error);
            return error;
        }
        *outSupport = support;
        return NO_ERROR;
    }

    virtual status_t setDisplayBrightness(const sp<IBinder>& displayToken, float brightness) {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("setDisplayBrightness: failed to write interface token: %d", error);
            return error;
        }
        error = data.writeStrongBinder(displayToken);
        if (error != NO_ERROR) {
            ALOGE("setDisplayBrightness: failed to write display token: %d", error);
            return error;
        }
        error = data.writeFloat(brightness);
        if (error != NO_ERROR) {
            ALOGE("setDisplayBrightness: failed to write brightness: %d", error);
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::SET_DISPLAY_BRIGHTNESS, data, &reply);
        if (error != NO_ERROR) {
            ALOGE("setDisplayBrightness: failed to transact: %d", error);
            return error;
        }
        return NO_ERROR;
    }

    virtual status_t notifyPowerBoost(int32_t boostId) {
        Parcel data, reply;
        status_t error = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (error != NO_ERROR) {
            ALOGE("notifyPowerBoost: failed to write interface token: %d", error);
            return error;
        }
        error = data.writeInt32(boostId);
        if (error != NO_ERROR) {
            ALOGE("notifyPowerBoost: failed to write boostId: %d", error);
            return error;
        }
        error = remote()->transact(BnSurfaceComposer::NOTIFY_POWER_BOOST, data, &reply,
                                   IBinder::FLAG_ONEWAY);
        if (error != NO_ERROR) {
            ALOGE("notifyPowerBoost: failed to transact: %d", error);
            return error;
        }
        return NO_ERROR;
    }

    virtual status_t setGlobalShadowSettings(const half4& ambientColor, const half4& spotColor,
                                             float lightPosY, float lightPosZ, float lightRadius) {
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

    virtual status_t setFrameRate(const sp<IGraphicBufferProducer>& surface, float frameRate,
                                  int8_t compatibility) {
        Parcel data, reply;
        status_t err = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            ALOGE("setFrameRate: failed writing interface token: %s (%d)", strerror(-err), -err);
            return err;
        }

        err = data.writeStrongBinder(IInterface::asBinder(surface));
        if (err != NO_ERROR) {
            ALOGE("setFrameRate: failed writing strong binder: %s (%d)", strerror(-err), -err);
            return err;
        }

        err = data.writeFloat(frameRate);
        if (err != NO_ERROR) {
            ALOGE("setFrameRate: failed writing float: %s (%d)", strerror(-err), -err);
            return err;
        }

        err = data.writeByte(compatibility);
        if (err != NO_ERROR) {
            ALOGE("setFrameRate: failed writing byte: %s (%d)", strerror(-err), -err);
            return err;
        }

        err = remote()->transact(BnSurfaceComposer::SET_FRAME_RATE, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("setFrameRate: failed to transact: %s (%d)", strerror(-err), err);
            return err;
        }

        return reply.readInt32();
    }

    virtual status_t acquireFrameRateFlexibilityToken(sp<IBinder>* outToken) {
        if (!outToken) return BAD_VALUE;

        Parcel data, reply;
        status_t err = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            ALOGE("acquireFrameRateFlexibilityToken: failed writing interface token: %s (%d)",
                  strerror(-err), -err);
            return err;
        }

        err = remote()->transact(BnSurfaceComposer::ACQUIRE_FRAME_RATE_FLEXIBILITY_TOKEN, data,
                                 &reply);
        if (err != NO_ERROR) {
            ALOGE("acquireFrameRateFlexibilityToken: failed to transact: %s (%d)", strerror(-err),
                  err);
            return err;
        }

        err = reply.readInt32();
        if (err != NO_ERROR) {
            ALOGE("acquireFrameRateFlexibilityToken: call failed: %s (%d)", strerror(-err), err);
            return err;
        }

        err = reply.readStrongBinder(outToken);
        if (err != NO_ERROR) {
            ALOGE("acquireFrameRateFlexibilityToken: failed reading binder token: %s (%d)",
                  strerror(-err), err);
            return err;
        }

        return NO_ERROR;
    }

    virtual status_t setFrameTimelineVsync(const sp<IGraphicBufferProducer>& surface,
                                           int64_t frameTimelineVsyncId) {
        Parcel data, reply;
        status_t err = data.writeInterfaceToken(ISurfaceComposer::getInterfaceDescriptor());
        if (err != NO_ERROR) {
            ALOGE("setFrameTimelineVsync: failed writing interface token: %s (%d)", strerror(-err),
                  -err);
            return err;
        }

        err = data.writeStrongBinder(IInterface::asBinder(surface));
        if (err != NO_ERROR) {
            ALOGE("setFrameTimelineVsync: failed writing strong binder: %s (%d)", strerror(-err),
                  -err);
            return err;
        }

        err = data.writeInt64(frameTimelineVsyncId);
        if (err != NO_ERROR) {
            ALOGE("setFrameTimelineVsync: failed writing int64_t: %s (%d)", strerror(-err), -err);
            return err;
        }

        err = remote()->transact(BnSurfaceComposer::SET_FRAME_TIMELINE_VSYNC, data, &reply);
        if (err != NO_ERROR) {
            ALOGE("setFrameTimelineVsync: failed to transact: %s (%d)", strerror(-err), err);
            return err;
        }

        return reply.readInt32();
    }

    virtual status_t addTransactionTraceListener(
            const sp<gui::ITransactionTraceListener>& listener) {
        Parcel data, reply;
        SAFE_PARCEL(data.writeInterfaceToken, ISurfaceComposer::getInterfaceDescriptor());
        SAFE_PARCEL(data.writeStrongBinder, IInterface::asBinder(listener));

        return remote()->transact(BnSurfaceComposer::ADD_TRANSACTION_TRACE_LISTENER, data, &reply);
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

            int64_t frameTimelineVsyncId;
            SAFE_PARCEL(data.readInt64, &frameTimelineVsyncId);
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
            SAFE_PARCEL(data.readInt64, &desiredPresentTime);

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
                SAFE_PARCEL(data.readInt64Vector, &callbackIds);
                listenerCallbacks.emplace_back(tmpBinder, callbackIds);
            }

            uint64_t transactionId = -1;
            SAFE_PARCEL(data.readUint64, &transactionId);

            return setTransactionState(frameTimelineVsyncId, state, displays, stateFlags,
                                       applyToken, inputWindowCommands, desiredPresentTime,
                                       uncachedBuffer, hasListenerCallbacks, listenerCallbacks,
                                       transactionId);
        }
        case BOOT_FINISHED: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            bootFinished();
            return NO_ERROR;
        }
        case CAPTURE_DISPLAY: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            DisplayCaptureArgs args;
            sp<IScreenCaptureListener> captureListener;
            SAFE_PARCEL(args.read, data);
            SAFE_PARCEL(data.readStrongBinder, &captureListener);

            return captureDisplay(args, captureListener);
        }
        case CAPTURE_DISPLAY_BY_ID: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            uint64_t displayOrLayerStack = 0;
            sp<IScreenCaptureListener> captureListener;
            SAFE_PARCEL(data.readUint64, &displayOrLayerStack);
            SAFE_PARCEL(data.readStrongBinder, &captureListener);

            return captureDisplay(displayOrLayerStack, captureListener);
        }
        case CAPTURE_LAYERS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            LayerCaptureArgs args;
            sp<IScreenCaptureListener> captureListener;
            SAFE_PARCEL(args.read, data);
            SAFE_PARCEL(data.readStrongBinder, &captureListener);

            return captureLayers(args, captureListener);
        }
        case AUTHENTICATE_SURFACE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IGraphicBufferProducer> bufferProducer =
                    interface_cast<IGraphicBufferProducer>(data.readStrongBinder());
            int32_t result = authenticateSurfaceTexture(bufferProducer) ? 1 : 0;
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case GET_SUPPORTED_FRAME_TIMESTAMPS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            std::vector<FrameEvent> supportedTimestamps;
            status_t result = getSupportedFrameTimestamps(&supportedTimestamps);
            status_t err = reply->writeInt32(result);
            if (err != NO_ERROR) {
                return err;
            }
            if (result != NO_ERROR) {
                return result;
            }

            std::vector<int32_t> supported;
            supported.reserve(supportedTimestamps.size());
            for (FrameEvent s : supportedTimestamps) {
                supported.push_back(static_cast<int32_t>(s));
            }
            return reply->writeInt32Vector(supported);
        }
        case CREATE_DISPLAY_EVENT_CONNECTION: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            auto vsyncSource = static_cast<ISurfaceComposer::VsyncSource>(data.readInt32());
            auto configChanged = static_cast<ISurfaceComposer::ConfigChanged>(data.readInt32());

            sp<IDisplayEventConnection> connection(
                    createDisplayEventConnection(vsyncSource, configChanged));
            reply->writeStrongBinder(IInterface::asBinder(connection));
            return NO_ERROR;
        }
        case CREATE_DISPLAY: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            String8 displayName;
            SAFE_PARCEL(data.readString8, &displayName);
            bool secure = false;
            SAFE_PARCEL(data.readBool, &secure);
            sp<IBinder> display = createDisplay(displayName, secure);
            SAFE_PARCEL(reply->writeStrongBinder, display);
            return NO_ERROR;
        }
        case DESTROY_DISPLAY: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = data.readStrongBinder();
            destroyDisplay(display);
            return NO_ERROR;
        }
        case GET_PHYSICAL_DISPLAY_TOKEN: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            PhysicalDisplayId displayId(data.readUint64());
            sp<IBinder> display = getPhysicalDisplayToken(displayId);
            reply->writeStrongBinder(display);
            return NO_ERROR;
        }
        case GET_DISPLAY_STATE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            ui::DisplayState state;
            const sp<IBinder> display = data.readStrongBinder();
            const status_t result = getDisplayState(display, &state);
            reply->writeInt32(result);
            if (result == NO_ERROR) {
                memcpy(reply->writeInplace(sizeof(ui::DisplayState)), &state,
                       sizeof(ui::DisplayState));
            }
            return NO_ERROR;
        }
        case GET_DISPLAY_INFO: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            DisplayInfo info;
            const sp<IBinder> display = data.readStrongBinder();
            const status_t result = getDisplayInfo(display, &info);
            reply->writeInt32(result);
            if (result != NO_ERROR) return result;
            return reply->write(info);
        }
        case GET_DISPLAY_CONFIGS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            Vector<DisplayConfig> configs;
            const sp<IBinder> display = data.readStrongBinder();
            const status_t result = getDisplayConfigs(display, &configs);
            reply->writeInt32(result);
            if (result == NO_ERROR) {
                reply->writeUint32(static_cast<uint32_t>(configs.size()));
                for (size_t c = 0; c < configs.size(); ++c) {
                    memcpy(reply->writeInplace(sizeof(DisplayConfig)), &configs[c],
                           sizeof(DisplayConfig));
                }
            }
            return NO_ERROR;
        }
        case GET_DISPLAY_STATS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            DisplayStatInfo stats;
            sp<IBinder> display = data.readStrongBinder();
            status_t result = getDisplayStats(display, &stats);
            reply->writeInt32(result);
            if (result == NO_ERROR) {
                memcpy(reply->writeInplace(sizeof(DisplayStatInfo)),
                        &stats, sizeof(DisplayStatInfo));
            }
            return NO_ERROR;
        }
        case GET_ACTIVE_CONFIG: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = data.readStrongBinder();
            int id = getActiveConfig(display);
            reply->writeInt32(id);
            return NO_ERROR;
        }
        case GET_DISPLAY_COLOR_MODES: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            Vector<ColorMode> colorModes;
            sp<IBinder> display = nullptr;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("getDisplayColorModes failed to readStrongBinder: %d", result);
                return result;
            }
            result = getDisplayColorModes(display, &colorModes);
            reply->writeInt32(result);
            if (result == NO_ERROR) {
                reply->writeUint32(static_cast<uint32_t>(colorModes.size()));
                for (size_t i = 0; i < colorModes.size(); ++i) {
                    reply->writeInt32(static_cast<int32_t>(colorModes[i]));
                }
            }
            return NO_ERROR;
        }
        case GET_DISPLAY_NATIVE_PRIMARIES: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            ui::DisplayPrimaries primaries;
            sp<IBinder> display = nullptr;

            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("getDisplayNativePrimaries failed to readStrongBinder: %d", result);
                return result;
            }

            result = getDisplayNativePrimaries(display, primaries);
            reply->writeInt32(result);
            if (result == NO_ERROR) {
                memcpy(reply->writeInplace(sizeof(ui::DisplayPrimaries)), &primaries,
                        sizeof(ui::DisplayPrimaries));
            }

            return NO_ERROR;
        }
        case GET_ACTIVE_COLOR_MODE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("getActiveColorMode failed to readStrongBinder: %d", result);
                return result;
            }
            ColorMode colorMode = getActiveColorMode(display);
            result = reply->writeInt32(static_cast<int32_t>(colorMode));
            return result;
        }
        case SET_ACTIVE_COLOR_MODE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("getActiveColorMode failed to readStrongBinder: %d", result);
                return result;
            }
            int32_t colorModeInt = 0;
            result = data.readInt32(&colorModeInt);
            if (result != NO_ERROR) {
                ALOGE("setActiveColorMode failed to readInt32: %d", result);
                return result;
            }
            result = setActiveColorMode(display,
                    static_cast<ColorMode>(colorModeInt));
            result = reply->writeInt32(result);
            return result;
        }

        case GET_AUTO_LOW_LATENCY_MODE_SUPPORT: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("getAutoLowLatencyModeSupport failed to readStrongBinder: %d", result);
                return result;
            }
            bool supported = false;
            result = getAutoLowLatencyModeSupport(display, &supported);
            if (result == NO_ERROR) {
                result = reply->writeBool(supported);
            }
            return result;
        }

        case SET_AUTO_LOW_LATENCY_MODE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("setAutoLowLatencyMode failed to readStrongBinder: %d", result);
                return result;
            }
            bool setAllm = false;
            result = data.readBool(&setAllm);
            if (result != NO_ERROR) {
                ALOGE("setAutoLowLatencyMode failed to readBool: %d", result);
                return result;
            }
            setAutoLowLatencyMode(display, setAllm);
            return result;
        }

        case GET_GAME_CONTENT_TYPE_SUPPORT: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("getGameContentTypeSupport failed to readStrongBinder: %d", result);
                return result;
            }
            bool supported = false;
            result = getGameContentTypeSupport(display, &supported);
            if (result == NO_ERROR) {
                result = reply->writeBool(supported);
            }
            return result;
        }

        case SET_GAME_CONTENT_TYPE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("setGameContentType failed to readStrongBinder: %d", result);
                return result;
            }
            bool setGameContentTypeOn = false;
            result = data.readBool(&setGameContentTypeOn);
            if (result != NO_ERROR) {
                ALOGE("setGameContentType failed to readBool: %d", result);
                return result;
            }
            setGameContentType(display, setGameContentTypeOn);
            return result;
        }

        case CLEAR_ANIMATION_FRAME_STATS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            status_t result = clearAnimationFrameStats();
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case GET_ANIMATION_FRAME_STATS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            FrameStats stats;
            status_t result = getAnimationFrameStats(&stats);
            reply->write(stats);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case SET_POWER_MODE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = data.readStrongBinder();
            int32_t mode = data.readInt32();
            setPowerMode(display, mode);
            return NO_ERROR;
        }
        case GET_HDR_CAPABILITIES: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("getHdrCapabilities failed to readStrongBinder: %d",
                        result);
                return result;
            }
            HdrCapabilities capabilities;
            result = getHdrCapabilities(display, &capabilities);
            reply->writeInt32(result);
            if (result == NO_ERROR) {
                reply->write(capabilities);
            }
            return NO_ERROR;
        }
        case ENABLE_VSYNC_INJECTIONS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            bool enable = false;
            status_t result = data.readBool(&enable);
            if (result != NO_ERROR) {
                ALOGE("enableVSyncInjections failed to readBool: %d", result);
                return result;
            }
            return enableVSyncInjections(enable);
        }
        case INJECT_VSYNC: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            int64_t when = 0;
            status_t result = data.readInt64(&when);
            if (result != NO_ERROR) {
                ALOGE("enableVSyncInjections failed to readInt64: %d", result);
                return result;
            }
            return injectVSync(when);
        }
        case GET_LAYER_DEBUG_INFO: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            std::vector<LayerDebugInfo> outLayers;
            status_t result = getLayerDebugInfo(&outLayers);
            reply->writeInt32(result);
            if (result == NO_ERROR)
            {
                result = reply->writeParcelableVector(outLayers);
            }
            return result;
        }
        case GET_COMPOSITION_PREFERENCE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            ui::Dataspace defaultDataspace;
            ui::PixelFormat defaultPixelFormat;
            ui::Dataspace wideColorGamutDataspace;
            ui::PixelFormat wideColorGamutPixelFormat;
            status_t error =
                    getCompositionPreference(&defaultDataspace, &defaultPixelFormat,
                                             &wideColorGamutDataspace, &wideColorGamutPixelFormat);
            reply->writeInt32(error);
            if (error == NO_ERROR) {
                reply->writeInt32(static_cast<int32_t>(defaultDataspace));
                reply->writeInt32(static_cast<int32_t>(defaultPixelFormat));
                reply->writeInt32(static_cast<int32_t>(wideColorGamutDataspace));
                reply->writeInt32(static_cast<int32_t>(wideColorGamutPixelFormat));
            }
            return error;
        }
        case GET_COLOR_MANAGEMENT: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            bool result;
            status_t error = getColorManagement(&result);
            if (error == NO_ERROR) {
                reply->writeBool(result);
            }
            return error;
        }
        case GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            sp<IBinder> display = data.readStrongBinder();
            ui::PixelFormat format;
            ui::Dataspace dataspace;
            uint8_t component = 0;
            auto result =
                    getDisplayedContentSamplingAttributes(display, &format, &dataspace, &component);
            if (result == NO_ERROR) {
                reply->writeUint32(static_cast<uint32_t>(format));
                reply->writeUint32(static_cast<uint32_t>(dataspace));
                reply->writeUint32(static_cast<uint32_t>(component));
            }
            return result;
        }
        case SET_DISPLAY_CONTENT_SAMPLING_ENABLED: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);

            sp<IBinder> display = nullptr;
            bool enable = false;
            int8_t componentMask = 0;
            uint64_t maxFrames = 0;
            status_t result = data.readStrongBinder(&display);
            if (result != NO_ERROR) {
                ALOGE("setDisplayContentSamplingEnabled failure in reading Display token: %d",
                      result);
                return result;
            }

            result = data.readBool(&enable);
            if (result != NO_ERROR) {
                ALOGE("setDisplayContentSamplingEnabled failure in reading enable: %d", result);
                return result;
            }

            result = data.readByte(static_cast<int8_t*>(&componentMask));
            if (result != NO_ERROR) {
                ALOGE("setDisplayContentSamplingEnabled failure in reading component mask: %d",
                      result);
                return result;
            }

            result = data.readUint64(&maxFrames);
            if (result != NO_ERROR) {
                ALOGE("setDisplayContentSamplingEnabled failure in reading max frames: %d", result);
                return result;
            }

            return setDisplayContentSamplingEnabled(display, enable,
                                                    static_cast<uint8_t>(componentMask), maxFrames);
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
        case GET_PROTECTED_CONTENT_SUPPORT: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            bool result;
            status_t error = getProtectedContentSupport(&result);
            if (error == NO_ERROR) {
                reply->writeBool(result);
            }
            return error;
        }
        case IS_WIDE_COLOR_DISPLAY: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> display = nullptr;
            status_t error = data.readStrongBinder(&display);
            if (error != NO_ERROR) {
                return error;
            }
            bool result;
            error = isWideColorDisplay(display, &result);
            if (error == NO_ERROR) {
                reply->writeBool(result);
            }
            return error;
        }
        case GET_PHYSICAL_DISPLAY_IDS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            std::vector<PhysicalDisplayId> ids = getPhysicalDisplayIds();
            std::vector<uint64_t> rawIds(ids.size());
            std::transform(ids.begin(), ids.end(), rawIds.begin(),
                           [](PhysicalDisplayId id) { return id.value; });
            return reply->writeUint64Vector(rawIds);
        }
        case ADD_REGION_SAMPLING_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            Rect samplingArea;
            status_t result = data.read(samplingArea);
            if (result != NO_ERROR) {
                ALOGE("addRegionSamplingListener: Failed to read sampling area");
                return result;
            }
            sp<IBinder> stopLayerHandle;
            result = data.readNullableStrongBinder(&stopLayerHandle);
            if (result != NO_ERROR) {
                ALOGE("addRegionSamplingListener: Failed to read stop layer handle");
                return result;
            }
            sp<IRegionSamplingListener> listener;
            result = data.readNullableStrongBinder(&listener);
            if (result != NO_ERROR) {
                ALOGE("addRegionSamplingListener: Failed to read listener");
                return result;
            }
            return addRegionSamplingListener(samplingArea, stopLayerHandle, listener);
        }
        case REMOVE_REGION_SAMPLING_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IRegionSamplingListener> listener;
            status_t result = data.readNullableStrongBinder(&listener);
            if (result != NO_ERROR) {
                ALOGE("removeRegionSamplingListener: Failed to read listener");
                return result;
            }
            return removeRegionSamplingListener(listener);
        }
        case SET_DESIRED_DISPLAY_CONFIG_SPECS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> displayToken = data.readStrongBinder();
            int32_t defaultConfig;
            status_t result = data.readInt32(&defaultConfig);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayConfigSpecs: failed to read defaultConfig: %d", result);
                return result;
            }
            bool allowGroupSwitching;
            result = data.readBool(&allowGroupSwitching);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayConfigSpecs: failed to read allowGroupSwitching: %d",
                      result);
                return result;
            }
            float primaryRefreshRateMin;
            result = data.readFloat(&primaryRefreshRateMin);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayConfigSpecs: failed to read primaryRefreshRateMin: %d",
                      result);
                return result;
            }
            float primaryRefreshRateMax;
            result = data.readFloat(&primaryRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayConfigSpecs: failed to read primaryRefreshRateMax: %d",
                      result);
                return result;
            }
            float appRequestRefreshRateMin;
            result = data.readFloat(&appRequestRefreshRateMin);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayConfigSpecs: failed to read appRequestRefreshRateMin: %d",
                      result);
                return result;
            }
            float appRequestRefreshRateMax;
            result = data.readFloat(&appRequestRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayConfigSpecs: failed to read appRequestRefreshRateMax: %d",
                      result);
                return result;
            }
            result = setDesiredDisplayConfigSpecs(displayToken, defaultConfig, allowGroupSwitching,
                                                  primaryRefreshRateMin, primaryRefreshRateMax,
                                                  appRequestRefreshRateMin,
                                                  appRequestRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("setDesiredDisplayConfigSpecs: failed to call setDesiredDisplayConfigSpecs: "
                      "%d",
                      result);
                return result;
            }
            reply->writeInt32(result);
            return result;
        }
        case GET_DESIRED_DISPLAY_CONFIG_SPECS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> displayToken = data.readStrongBinder();
            int32_t defaultConfig;
            bool allowGroupSwitching;
            float primaryRefreshRateMin;
            float primaryRefreshRateMax;
            float appRequestRefreshRateMin;
            float appRequestRefreshRateMax;

            status_t result =
                    getDesiredDisplayConfigSpecs(displayToken, &defaultConfig, &allowGroupSwitching,
                                                 &primaryRefreshRateMin, &primaryRefreshRateMax,
                                                 &appRequestRefreshRateMin,
                                                 &appRequestRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayConfigSpecs: failed to get getDesiredDisplayConfigSpecs: "
                      "%d",
                      result);
                return result;
            }

            result = reply->writeInt32(defaultConfig);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayConfigSpecs: failed to write defaultConfig: %d", result);
                return result;
            }
            result = reply->writeBool(allowGroupSwitching);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayConfigSpecs: failed to write allowGroupSwitching: %d",
                      result);
                return result;
            }
            result = reply->writeFloat(primaryRefreshRateMin);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayConfigSpecs: failed to write primaryRefreshRateMin: %d",
                      result);
                return result;
            }
            result = reply->writeFloat(primaryRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayConfigSpecs: failed to write primaryRefreshRateMax: %d",
                      result);
                return result;
            }
            result = reply->writeFloat(appRequestRefreshRateMin);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayConfigSpecs: failed to write appRequestRefreshRateMin: %d",
                      result);
                return result;
            }
            result = reply->writeFloat(appRequestRefreshRateMax);
            if (result != NO_ERROR) {
                ALOGE("getDesiredDisplayConfigSpecs: failed to write appRequestRefreshRateMax: %d",
                      result);
                return result;
            }
            reply->writeInt32(result);
            return result;
        }
        case GET_DISPLAY_BRIGHTNESS_SUPPORT: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> displayToken;
            status_t error = data.readNullableStrongBinder(&displayToken);
            if (error != NO_ERROR) {
                ALOGE("getDisplayBrightnessSupport: failed to read display token: %d", error);
                return error;
            }
            bool support = false;
            error = getDisplayBrightnessSupport(displayToken, &support);
            reply->writeBool(support);
            return error;
        }
        case SET_DISPLAY_BRIGHTNESS: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> displayToken;
            status_t error = data.readNullableStrongBinder(&displayToken);
            if (error != NO_ERROR) {
                ALOGE("setDisplayBrightness: failed to read display token: %d", error);
                return error;
            }
            float brightness = -1.0f;
            error = data.readFloat(&brightness);
            if (error != NO_ERROR) {
                ALOGE("setDisplayBrightness: failed to read brightness: %d", error);
                return error;
            }
            return setDisplayBrightness(displayToken, brightness);
        }
        case NOTIFY_POWER_BOOST: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            int32_t boostId;
            status_t error = data.readInt32(&boostId);
            if (error != NO_ERROR) {
                ALOGE("notifyPowerBoost: failed to read boostId: %d", error);
                return error;
            }
            return notifyPowerBoost(boostId);
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
        case SET_FRAME_RATE: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> binder;
            status_t err = data.readStrongBinder(&binder);
            if (err != NO_ERROR) {
                ALOGE("setFrameRate: failed to read strong binder: %s (%d)", strerror(-err), -err);
                return err;
            }
            sp<IGraphicBufferProducer> surface = interface_cast<IGraphicBufferProducer>(binder);
            if (!surface) {
                ALOGE("setFrameRate: failed to cast to IGraphicBufferProducer: %s (%d)",
                      strerror(-err), -err);
                return err;
            }
            float frameRate;
            err = data.readFloat(&frameRate);
            if (err != NO_ERROR) {
                ALOGE("setFrameRate: failed to read float: %s (%d)", strerror(-err), -err);
                return err;
            }
            int8_t compatibility;
            err = data.readByte(&compatibility);
            if (err != NO_ERROR) {
                ALOGE("setFrameRate: failed to read byte: %s (%d)", strerror(-err), -err);
                return err;
            }
            status_t result = setFrameRate(surface, frameRate, compatibility);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case ACQUIRE_FRAME_RATE_FLEXIBILITY_TOKEN: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> token;
            status_t result = acquireFrameRateFlexibilityToken(&token);
            reply->writeInt32(result);
            if (result == NO_ERROR) {
                reply->writeStrongBinder(token);
            }
            return NO_ERROR;
        }
        case SET_FRAME_TIMELINE_VSYNC: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<IBinder> binder;
            status_t err = data.readStrongBinder(&binder);
            if (err != NO_ERROR) {
                ALOGE("setFrameTimelineVsync: failed to read strong binder: %s (%d)",
                      strerror(-err), -err);
                return err;
            }
            sp<IGraphicBufferProducer> surface = interface_cast<IGraphicBufferProducer>(binder);
            if (!surface) {
                ALOGE("setFrameTimelineVsync: failed to cast to IGraphicBufferProducer: %s (%d)",
                      strerror(-err), -err);
                return err;
            }
            int64_t frameTimelineVsyncId;
            err = data.readInt64(&frameTimelineVsyncId);
            if (err != NO_ERROR) {
                ALOGE("setFrameTimelineVsync: failed to read int64_t: %s (%d)", strerror(-err),
                      -err);
                return err;
            }

            status_t result = setFrameTimelineVsync(surface, frameTimelineVsyncId);
            reply->writeInt32(result);
            return NO_ERROR;
        }
        case ADD_TRANSACTION_TRACE_LISTENER: {
            CHECK_INTERFACE(ISurfaceComposer, data, reply);
            sp<gui::ITransactionTraceListener> listener;
            SAFE_PARCEL(data.readStrongBinder, &listener);

            return addTransactionTraceListener(listener);
        }
        default: {
            return BBinder::onTransact(code, data, reply, flags);
        }
    }
}

} // namespace android