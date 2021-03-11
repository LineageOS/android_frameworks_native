/*
 * Copyright (C) 2019 The Android Open Source Project
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

#include <cutils/properties.h>
#include <gtest/gtest.h>
#include <gui/ISurfaceComposer.h>
#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>
#include <ui/DisplayMode.h>

#include "BufferGenerator.h"
#include "utils/ScreenshotUtils.h"
#include "utils/TransactionUtils.h"

namespace android {

using android::hardware::graphics::common::V1_1::BufferUsage;

class LayerTransactionTest : public ::testing::Test {
protected:
    void SetUp() override {
        mClient = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mClient->initCheck()) << "failed to create SurfaceComposerClient";

        ASSERT_NO_FATAL_FAILURE(SetUpDisplay());

        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        ASSERT_NO_FATAL_FAILURE(sf->getColorManagement(&mColorManagementUsed));

        mCaptureArgs.displayToken = mDisplay;
    }

    virtual void TearDown() {
        mBlackBgSurface = 0;
        mClient->dispose();
        mClient = 0;
    }

    virtual sp<SurfaceControl> createLayer(const sp<SurfaceComposerClient>& client,
                                           const char* name, uint32_t width, uint32_t height,
                                           uint32_t flags = 0, SurfaceControl* parent = nullptr,
                                           uint32_t* outTransformHint = nullptr,
                                           PixelFormat format = PIXEL_FORMAT_RGBA_8888) {
        auto layer =
                createSurface(client, name, width, height, format, flags, parent, outTransformHint);

        Transaction t;
        t.setLayerStack(layer, mDisplayLayerStack).setLayer(layer, mLayerZBase);

        status_t error = t.apply();
        if (error != NO_ERROR) {
            ADD_FAILURE() << "failed to initialize SurfaceControl";
            layer.clear();
        }

        return layer;
    }

    virtual sp<SurfaceControl> createSurface(const sp<SurfaceComposerClient>& client,
                                             const char* name, uint32_t width, uint32_t height,
                                             PixelFormat format, uint32_t flags,
                                             SurfaceControl* parent = nullptr,
                                             uint32_t* outTransformHint = nullptr) {
        sp<IBinder> parentHandle = (parent) ? parent->getHandle() : nullptr;
        auto layer = client->createSurface(String8(name), width, height, format, flags,
                                           parentHandle, LayerMetadata(), outTransformHint);
        EXPECT_NE(nullptr, layer.get()) << "failed to create SurfaceControl";
        return layer;
    }

    virtual sp<SurfaceControl> createLayer(const char* name, uint32_t width, uint32_t height,
                                           uint32_t flags = 0, SurfaceControl* parent = nullptr,
                                           uint32_t* outTransformHint = nullptr,
                                           PixelFormat format = PIXEL_FORMAT_RGBA_8888) {
        return createLayer(mClient, name, width, height, flags, parent, outTransformHint, format);
    }

    sp<SurfaceControl> createColorLayer(const char* name, const Color& color,
                                        SurfaceControl* parent = nullptr) {
        auto colorLayer = createSurface(mClient, name, 0 /* buffer width */, 0 /* buffer height */,
                                        PIXEL_FORMAT_RGBA_8888,
                                        ISurfaceComposerClient::eFXSurfaceEffect, parent);
        asTransaction([&](Transaction& t) {
            t.setColor(colorLayer, half3{color.r / 255.0f, color.g / 255.0f, color.b / 255.0f});
            t.setAlpha(colorLayer, color.a / 255.0f);
        });
        return colorLayer;
    }

    ANativeWindow_Buffer getBufferQueueLayerBuffer(const sp<SurfaceControl>& layer) {
        // wait for previous transactions (such as setSize) to complete
        Transaction().apply(true);

        ANativeWindow_Buffer buffer = {};
        EXPECT_EQ(NO_ERROR, layer->getSurface()->lock(&buffer, nullptr));

        return buffer;
    }

    void postBufferQueueLayerBuffer(const sp<SurfaceControl>& layer) {
        ASSERT_EQ(NO_ERROR, layer->getSurface()->unlockAndPost());

        // wait for the newly posted buffer to be latched
        waitForLayerBuffers();
    }

    virtual void fillBufferQueueLayerColor(const sp<SurfaceControl>& layer, const Color& color,
                                           uint32_t bufferWidth, uint32_t bufferHeight) {
        ANativeWindow_Buffer buffer;
        ASSERT_NO_FATAL_FAILURE(buffer = getBufferQueueLayerBuffer(layer));
        TransactionUtils::fillANativeWindowBufferColor(buffer,
                                                       Rect(0, 0, bufferWidth, bufferHeight),
                                                       color);
        postBufferQueueLayerBuffer(layer);
    }

    virtual void fillBufferStateLayerColor(const sp<SurfaceControl>& layer, const Color& color,
                                           int32_t bufferWidth, int32_t bufferHeight) {
        sp<GraphicBuffer> buffer =
                new GraphicBuffer(bufferWidth, bufferHeight, PIXEL_FORMAT_RGBA_8888, 1,
                                  BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                          BufferUsage::COMPOSER_OVERLAY,
                                  "test");
        TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, bufferWidth, bufferHeight),
                                                 color);
        Transaction().setBuffer(layer, buffer).apply();
    }

    void fillLayerColor(uint32_t mLayerType, const sp<SurfaceControl>& layer, const Color& color,
                        uint32_t bufferWidth, uint32_t bufferHeight) {
        switch (mLayerType) {
            case ISurfaceComposerClient::eFXSurfaceBufferQueue:
                fillBufferQueueLayerColor(layer, color, bufferWidth, bufferHeight);
                break;
            case ISurfaceComposerClient::eFXSurfaceBufferState:
                fillBufferStateLayerColor(layer, color, bufferWidth, bufferHeight);
                break;
            default:
                ASSERT_TRUE(false) << "unsupported layer type: " << mLayerType;
        }
    }

    void fillLayerQuadrant(uint32_t mLayerType, const sp<SurfaceControl>& layer,
                           int32_t bufferWidth, int32_t bufferHeight, const Color& topLeft,
                           const Color& topRight, const Color& bottomLeft,
                           const Color& bottomRight) {
        switch (mLayerType) {
            case ISurfaceComposerClient::eFXSurfaceBufferQueue:
                fillBufferQueueLayerQuadrant(layer, bufferWidth, bufferHeight, topLeft, topRight,
                                             bottomLeft, bottomRight);
                break;
            case ISurfaceComposerClient::eFXSurfaceBufferState:
                fillBufferStateLayerQuadrant(layer, bufferWidth, bufferHeight, topLeft, topRight,
                                             bottomLeft, bottomRight);
                break;
            default:
                ASSERT_TRUE(false) << "unsupported layer type: " << mLayerType;
        }
    }

    virtual void fillBufferQueueLayerQuadrant(const sp<SurfaceControl>& layer, int32_t bufferWidth,
                                              int32_t bufferHeight, const Color& topLeft,
                                              const Color& topRight, const Color& bottomLeft,
                                              const Color& bottomRight) {
        ANativeWindow_Buffer buffer;
        ASSERT_NO_FATAL_FAILURE(buffer = getBufferQueueLayerBuffer(layer));
        ASSERT_TRUE(bufferWidth % 2 == 0 && bufferHeight % 2 == 0);

        const int32_t halfW = bufferWidth / 2;
        const int32_t halfH = bufferHeight / 2;
        TransactionUtils::fillANativeWindowBufferColor(buffer, Rect(0, 0, halfW, halfH), topLeft);
        TransactionUtils::fillANativeWindowBufferColor(buffer, Rect(halfW, 0, bufferWidth, halfH),
                                                       topRight);
        TransactionUtils::fillANativeWindowBufferColor(buffer, Rect(0, halfH, halfW, bufferHeight),
                                                       bottomLeft);
        TransactionUtils::fillANativeWindowBufferColor(buffer,
                                                       Rect(halfW, halfH, bufferWidth,
                                                            bufferHeight),
                                                       bottomRight);

        postBufferQueueLayerBuffer(layer);
    }

    virtual void fillBufferStateLayerQuadrant(const sp<SurfaceControl>& layer, int32_t bufferWidth,
                                              int32_t bufferHeight, const Color& topLeft,
                                              const Color& topRight, const Color& bottomLeft,
                                              const Color& bottomRight) {
        sp<GraphicBuffer> buffer =
                new GraphicBuffer(bufferWidth, bufferHeight, PIXEL_FORMAT_RGBA_8888, 1,
                                  BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                          BufferUsage::COMPOSER_OVERLAY,
                                  "test");

        ASSERT_TRUE(bufferWidth % 2 == 0 && bufferHeight % 2 == 0);

        const int32_t halfW = bufferWidth / 2;
        const int32_t halfH = bufferHeight / 2;
        TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, 0, halfW, halfH), topLeft);
        TransactionUtils::fillGraphicBufferColor(buffer, Rect(halfW, 0, bufferWidth, halfH),
                                                 topRight);
        TransactionUtils::fillGraphicBufferColor(buffer, Rect(0, halfH, halfW, bufferHeight),
                                                 bottomLeft);
        TransactionUtils::fillGraphicBufferColor(buffer,
                                                 Rect(halfW, halfH, bufferWidth, bufferHeight),
                                                 bottomRight);

        Transaction().setBuffer(layer, buffer).setSize(layer, bufferWidth, bufferHeight).apply();
    }

    std::unique_ptr<ScreenCapture> screenshot() {
        std::unique_ptr<ScreenCapture> screenshot;
        ScreenCapture::captureScreen(&screenshot);
        return screenshot;
    }

    void asTransaction(const std::function<void(Transaction&)>& exec) {
        Transaction t;
        exec(t);
        t.apply(true);
    }

    static status_t getBuffer(sp<GraphicBuffer>* outBuffer, sp<Fence>* outFence) {
        static BufferGenerator bufferGenerator;
        return bufferGenerator.get(outBuffer, outFence);
    }

    sp<SurfaceComposerClient> mClient;

    bool deviceSupportsBlurs() {
        char value[PROPERTY_VALUE_MAX];
        property_get("ro.surface_flinger.supports_background_blur", value, "0");
        return atoi(value);
    }

    bool deviceUsesSkiaRenderEngine() {
        char value[PROPERTY_VALUE_MAX];
        property_get("debug.renderengine.backend", value, "default");
        return strstr(value, "skia") != nullptr;
    }

    sp<IBinder> mDisplay;
    uint32_t mDisplayWidth;
    uint32_t mDisplayHeight;
    uint32_t mDisplayLayerStack;
    Rect mDisplayRect = Rect::INVALID_RECT;

    // leave room for ~256 layers
    const int32_t mLayerZBase = std::numeric_limits<int32_t>::max() - 256;

    sp<SurfaceControl> mBlackBgSurface;
    bool mColorManagementUsed;

    DisplayCaptureArgs mCaptureArgs;
    ScreenCaptureResults mCaptureResults;

private:
    void SetUpDisplay() {
        mDisplay = mClient->getInternalDisplayToken();
        ASSERT_FALSE(mDisplay == nullptr) << "failed to get display";

        ui::DisplayMode mode;
        ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayMode(mDisplay, &mode));
        mDisplayRect = Rect(mode.resolution);
        mDisplayWidth = mDisplayRect.getWidth();
        mDisplayHeight = mDisplayRect.getHeight();

        // After a new buffer is queued, SurfaceFlinger is notified and will
        // latch the new buffer on next vsync.  Let's heuristically wait for 3
        // vsyncs.
        mBufferPostDelay = static_cast<int32_t>(1e6 / mode.refreshRate) * 3;

        mDisplayLayerStack = 0;

        mBlackBgSurface =
                createSurface(mClient, "BaseSurface", 0 /* buffer width */, 0 /* buffer height */,
                              PIXEL_FORMAT_RGBA_8888, ISurfaceComposerClient::eFXSurfaceEffect);

        // set layer stack (b/68888219)
        Transaction t;
        t.setDisplayLayerStack(mDisplay, mDisplayLayerStack);
        t.setCrop_legacy(mBlackBgSurface, Rect(0, 0, mDisplayWidth, mDisplayHeight));
        t.setLayerStack(mBlackBgSurface, mDisplayLayerStack);
        t.setColor(mBlackBgSurface, half3{0, 0, 0});
        t.setLayer(mBlackBgSurface, mLayerZBase);
        t.apply();
    }

    void waitForLayerBuffers() {
        // Request an empty transaction to get applied synchronously to ensure the buffer is
        // latched.
        Transaction().apply(true);
        usleep(mBufferPostDelay);
    }

    int32_t mBufferPostDelay;

    friend class LayerRenderPathTestHarness;
};

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
