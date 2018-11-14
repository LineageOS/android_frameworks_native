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

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <functional>
#include <limits>
#include <ostream>
#include <thread>

#include <gtest/gtest.h>

#include <android/native_window.h>

#include <gui/ISurfaceComposer.h>
#include <gui/LayerState.h>

#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <private/gui/ComposerService.h>

#include <ui/ColorSpace.h>
#include <ui/DisplayInfo.h>
#include <ui/Rect.h>
#include <utils/String8.h>

#include <math.h>
#include <math/vec3.h>

namespace android {

namespace {

struct Color {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;

    static const Color RED;
    static const Color GREEN;
    static const Color BLUE;
    static const Color WHITE;
    static const Color BLACK;
    static const Color TRANSPARENT;
};

const Color Color::RED{255, 0, 0, 255};
const Color Color::GREEN{0, 255, 0, 255};
const Color Color::BLUE{0, 0, 255, 255};
const Color Color::WHITE{255, 255, 255, 255};
const Color Color::BLACK{0, 0, 0, 255};
const Color Color::TRANSPARENT{0, 0, 0, 0};

using android::hardware::graphics::common::V1_1::BufferUsage;
using namespace std::chrono_literals;

std::ostream& operator<<(std::ostream& os, const Color& color) {
    os << int(color.r) << ", " << int(color.g) << ", " << int(color.b) << ", " << int(color.a);
    return os;
}

// Fill a region with the specified color.
void fillANativeWindowBufferColor(const ANativeWindow_Buffer& buffer, const Rect& rect,
                                  const Color& color) {
    Rect r(0, 0, buffer.width, buffer.height);
    if (!r.intersect(rect, &r)) {
        return;
    }

    int32_t width = r.right - r.left;
    int32_t height = r.bottom - r.top;

    for (int32_t row = 0; row < height; row++) {
        uint8_t* dst =
                static_cast<uint8_t*>(buffer.bits) + (buffer.stride * (r.top + row) + r.left) * 4;
        for (int32_t column = 0; column < width; column++) {
            dst[0] = color.r;
            dst[1] = color.g;
            dst[2] = color.b;
            dst[3] = color.a;
            dst += 4;
        }
    }
}

// Fill a region with the specified color.
void fillGraphicBufferColor(const sp<GraphicBuffer>& buffer, const Rect& rect, const Color& color) {
    Rect r(0, 0, buffer->width, buffer->height);
    if (!r.intersect(rect, &r)) {
        return;
    }

    int32_t width = r.right - r.left;
    int32_t height = r.bottom - r.top;

    uint8_t* pixels;
    buffer->lock(GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN,
                 reinterpret_cast<void**>(&pixels));

    for (int32_t row = 0; row < height; row++) {
        uint8_t* dst = pixels + (buffer->getStride() * (r.top + row) + r.left) * 4;
        for (int32_t column = 0; column < width; column++) {
            dst[0] = color.r;
            dst[1] = color.g;
            dst[2] = color.b;
            dst[3] = color.a;
            dst += 4;
        }
    }
    buffer->unlock();
}

// Check if a region has the specified color.
void expectBufferColor(const sp<GraphicBuffer>& outBuffer, uint8_t* pixels, const Rect& rect,
                       const Color& color, uint8_t tolerance) {
    int32_t x = rect.left;
    int32_t y = rect.top;
    int32_t width = rect.right - rect.left;
    int32_t height = rect.bottom - rect.top;

    int32_t bufferWidth = int32_t(outBuffer->getWidth());
    int32_t bufferHeight = int32_t(outBuffer->getHeight());
    if (x + width > bufferWidth) {
        x = std::min(x, bufferWidth);
        width = bufferWidth - x;
    }
    if (y + height > bufferHeight) {
        y = std::min(y, bufferHeight);
        height = bufferHeight - y;
    }

    auto colorCompare = [tolerance](uint8_t a, uint8_t b) {
        uint8_t tmp = a >= b ? a - b : b - a;
        return tmp <= tolerance;
    };
    for (int32_t j = 0; j < height; j++) {
        const uint8_t* src = pixels + (outBuffer->getStride() * (y + j) + x) * 4;
        for (int32_t i = 0; i < width; i++) {
            const uint8_t expected[4] = {color.r, color.g, color.b, color.a};
            EXPECT_TRUE(std::equal(src, src + 4, expected, colorCompare))
                    << "pixel @ (" << x + i << ", " << y + j << "): "
                    << "expected (" << color << "), "
                    << "got (" << Color{src[0], src[1], src[2], src[3]} << ")";
            src += 4;
        }
    }
}

} // anonymous namespace

using Transaction = SurfaceComposerClient::Transaction;

// Fill an RGBA_8888 formatted surface with a single color.
static void fillSurfaceRGBA8(const sp<SurfaceControl>& sc, uint8_t r, uint8_t g, uint8_t b,
                             bool unlock = true) {
    ANativeWindow_Buffer outBuffer;
    sp<Surface> s = sc->getSurface();
    ASSERT_TRUE(s != nullptr);
    ASSERT_EQ(NO_ERROR, s->lock(&outBuffer, nullptr));
    uint8_t* img = reinterpret_cast<uint8_t*>(outBuffer.bits);
    for (int y = 0; y < outBuffer.height; y++) {
        for (int x = 0; x < outBuffer.width; x++) {
            uint8_t* pixel = img + (4 * (y * outBuffer.stride + x));
            pixel[0] = r;
            pixel[1] = g;
            pixel[2] = b;
            pixel[3] = 255;
        }
    }
    if (unlock) {
        ASSERT_EQ(NO_ERROR, s->unlockAndPost());
    }
}

// A ScreenCapture is a screenshot from SurfaceFlinger that can be used to check
// individual pixel values for testing purposes.
class ScreenCapture : public RefBase {
public:
    static void captureScreen(std::unique_ptr<ScreenCapture>* sc) {
        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        sp<IBinder> display(sf->getBuiltInDisplay(ISurfaceComposer::eDisplayIdMain));
        SurfaceComposerClient::Transaction().apply(true);

        sp<GraphicBuffer> outBuffer;
        ASSERT_EQ(NO_ERROR,
                  sf->captureScreen(display, &outBuffer, Rect(), 0, 0, false));
        *sc = std::make_unique<ScreenCapture>(outBuffer);
    }

    static void captureLayers(std::unique_ptr<ScreenCapture>* sc, sp<IBinder>& parentHandle,
                              Rect crop = Rect::EMPTY_RECT, float frameScale = 1.0) {
        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        SurfaceComposerClient::Transaction().apply(true);

        sp<GraphicBuffer> outBuffer;
        ASSERT_EQ(NO_ERROR, sf->captureLayers(parentHandle, &outBuffer, crop, frameScale));
        *sc = std::make_unique<ScreenCapture>(outBuffer);
    }

    static void captureChildLayers(std::unique_ptr<ScreenCapture>* sc, sp<IBinder>& parentHandle,
                                   Rect crop = Rect::EMPTY_RECT, float frameScale = 1.0) {
        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        SurfaceComposerClient::Transaction().apply(true);

        sp<GraphicBuffer> outBuffer;
        ASSERT_EQ(NO_ERROR, sf->captureLayers(parentHandle, &outBuffer, crop, frameScale, true));
        *sc = std::make_unique<ScreenCapture>(outBuffer);
    }

    void expectColor(const Rect& rect, const Color& color, uint8_t tolerance = 0) {
        ASSERT_EQ(HAL_PIXEL_FORMAT_RGBA_8888, mOutBuffer->getPixelFormat());
        expectBufferColor(mOutBuffer, mPixels, rect, color, tolerance);
    }

    void expectBorder(const Rect& rect, const Color& color, uint8_t tolerance = 0) {
        ASSERT_EQ(HAL_PIXEL_FORMAT_RGBA_8888, mOutBuffer->getPixelFormat());
        const bool leftBorder = rect.left > 0;
        const bool topBorder = rect.top > 0;
        const bool rightBorder = rect.right < int32_t(mOutBuffer->getWidth());
        const bool bottomBorder = rect.bottom < int32_t(mOutBuffer->getHeight());

        if (topBorder) {
            Rect top(rect.left, rect.top - 1, rect.right, rect.top);
            if (leftBorder) {
                top.left -= 1;
            }
            if (rightBorder) {
                top.right += 1;
            }
            expectColor(top, color, tolerance);
        }
        if (leftBorder) {
            Rect left(rect.left - 1, rect.top, rect.left, rect.bottom);
            expectColor(left, color, tolerance);
        }
        if (rightBorder) {
            Rect right(rect.right, rect.top, rect.right + 1, rect.bottom);
            expectColor(right, color, tolerance);
        }
        if (bottomBorder) {
            Rect bottom(rect.left, rect.bottom, rect.right, rect.bottom + 1);
            if (leftBorder) {
                bottom.left -= 1;
            }
            if (rightBorder) {
                bottom.right += 1;
            }
            expectColor(bottom, color, tolerance);
        }
    }

    void expectQuadrant(const Rect& rect, const Color& topLeft, const Color& topRight,
                        const Color& bottomLeft, const Color& bottomRight, bool filtered = false,
                        uint8_t tolerance = 0) {
        ASSERT_TRUE((rect.right - rect.left) % 2 == 0 && (rect.bottom - rect.top) % 2 == 0);

        const int32_t centerX = rect.left + (rect.right - rect.left) / 2;
        const int32_t centerY = rect.top + (rect.bottom - rect.top) / 2;
        // avoid checking borders due to unspecified filtering behavior
        const int32_t offsetX = filtered ? 2 : 0;
        const int32_t offsetY = filtered ? 2 : 0;
        expectColor(Rect(rect.left, rect.top, centerX - offsetX, centerY - offsetY), topLeft,
                    tolerance);
        expectColor(Rect(centerX + offsetX, rect.top, rect.right, centerY - offsetY), topRight,
                    tolerance);
        expectColor(Rect(rect.left, centerY + offsetY, centerX - offsetX, rect.bottom), bottomLeft,
                    tolerance);
        expectColor(Rect(centerX + offsetX, centerY + offsetY, rect.right, rect.bottom),
                    bottomRight, tolerance);
    }

    void checkPixel(uint32_t x, uint32_t y, uint8_t r, uint8_t g, uint8_t b) {
        ASSERT_EQ(HAL_PIXEL_FORMAT_RGBA_8888, mOutBuffer->getPixelFormat());
        const uint8_t* pixel = mPixels + (4 * (y * mOutBuffer->getStride() + x));
        if (r != pixel[0] || g != pixel[1] || b != pixel[2]) {
            String8 err(String8::format("pixel @ (%3d, %3d): "
                                        "expected [%3d, %3d, %3d], got [%3d, %3d, %3d]",
                                        x, y, r, g, b, pixel[0], pixel[1], pixel[2]));
            EXPECT_EQ(String8(), err) << err.string();
        }
    }

    void expectFGColor(uint32_t x, uint32_t y) { checkPixel(x, y, 195, 63, 63); }

    void expectBGColor(uint32_t x, uint32_t y) { checkPixel(x, y, 63, 63, 195); }

    void expectChildColor(uint32_t x, uint32_t y) { checkPixel(x, y, 200, 200, 200); }

    ScreenCapture(const sp<GraphicBuffer>& outBuffer) : mOutBuffer(outBuffer) {
        mOutBuffer->lock(GRALLOC_USAGE_SW_READ_OFTEN, reinterpret_cast<void**>(&mPixels));
    }

    ~ScreenCapture() { mOutBuffer->unlock(); }

private:
    sp<GraphicBuffer> mOutBuffer;
    uint8_t* mPixels = nullptr;
};

class LayerTransactionTest : public ::testing::Test {
protected:
    void SetUp() override {
        mClient = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mClient->initCheck()) << "failed to create SurfaceComposerClient";

        ASSERT_NO_FATAL_FAILURE(SetUpDisplay());

        sp<ISurfaceComposer> sf(ComposerService::getComposerService());
        sp<IBinder> binder = sf->getBuiltInDisplay(ISurfaceComposer::eDisplayIdMain);
        ASSERT_NO_FATAL_FAILURE(sf->getColorManagement(&mColorManagementUsed));
    }

    virtual void TearDown() {
        mBlackBgSurface = 0;
        mClient->dispose();
        mClient = 0;
    }

    virtual sp<SurfaceControl> createLayer(const sp<SurfaceComposerClient>& client,
                                           const char* name, uint32_t width, uint32_t height,
                                           uint32_t flags = 0) {
        auto layer =
                client->createSurface(String8(name), width, height, PIXEL_FORMAT_RGBA_8888, flags);
        EXPECT_NE(nullptr, layer.get()) << "failed to create SurfaceControl";

        Transaction t;
        t.setLayerStack(layer, mDisplayLayerStack).setLayer(layer, mLayerZBase);
        // If we are creating a color layer, set its crop since its size will be ignored.
        if (flags == ISurfaceComposerClient::eFXSurfaceColor) {
            t.setCrop_legacy(layer, Rect(0, 0, width, height));
        }

        status_t error = t.apply();
        if (error != NO_ERROR) {
            ADD_FAILURE() << "failed to initialize SurfaceControl";
            layer.clear();
        }

        return layer;
    }

    virtual sp<SurfaceControl> createLayer(const char* name, uint32_t width, uint32_t height,
                                           uint32_t flags = 0) {
        return createLayer(mClient, name, width, height, flags);
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
                                           int32_t bufferWidth, int32_t bufferHeight) {
        ANativeWindow_Buffer buffer;
        ASSERT_NO_FATAL_FAILURE(buffer = getBufferQueueLayerBuffer(layer));
        fillANativeWindowBufferColor(buffer, Rect(0, 0, bufferWidth, bufferHeight), color);
        postBufferQueueLayerBuffer(layer);
    }

    virtual void fillBufferStateLayerColor(const sp<SurfaceControl>& layer, const Color& color,
                                           int32_t bufferWidth, int32_t bufferHeight) {
        sp<GraphicBuffer> buffer =
                new GraphicBuffer(bufferWidth, bufferHeight, PIXEL_FORMAT_RGBA_8888, 1,
                                  BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                          BufferUsage::COMPOSER_OVERLAY,
                                  "test");
        fillGraphicBufferColor(buffer, Rect(0, 0, bufferWidth, bufferHeight), color);
        Transaction().setBuffer(layer, buffer).setSize(layer, bufferWidth, bufferHeight).apply();
    }

    void fillLayerColor(uint32_t mLayerType, const sp<SurfaceControl>& layer, const Color& color,
                        int32_t bufferWidth, int32_t bufferHeight) {
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
        fillANativeWindowBufferColor(buffer, Rect(0, 0, halfW, halfH), topLeft);
        fillANativeWindowBufferColor(buffer, Rect(halfW, 0, bufferWidth, halfH), topRight);
        fillANativeWindowBufferColor(buffer, Rect(0, halfH, halfW, bufferHeight), bottomLeft);
        fillANativeWindowBufferColor(buffer, Rect(halfW, halfH, bufferWidth, bufferHeight),
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
        fillGraphicBufferColor(buffer, Rect(0, 0, halfW, halfH), topLeft);
        fillGraphicBufferColor(buffer, Rect(halfW, 0, bufferWidth, halfH), topRight);
        fillGraphicBufferColor(buffer, Rect(0, halfH, halfW, bufferHeight), bottomLeft);
        fillGraphicBufferColor(buffer, Rect(halfW, halfH, bufferWidth, bufferHeight), bottomRight);

        Transaction().setBuffer(layer, buffer).setSize(layer, bufferWidth, bufferHeight).apply();
    }

    std::unique_ptr<ScreenCapture> screenshot() {
        std::unique_ptr<ScreenCapture> screenshot;
        ScreenCapture::captureScreen(&screenshot);
        return screenshot;
    }

    sp<SurfaceComposerClient> mClient;

    sp<IBinder> mDisplay;
    uint32_t mDisplayWidth;
    uint32_t mDisplayHeight;
    uint32_t mDisplayLayerStack;

    // leave room for ~256 layers
    const int32_t mLayerZBase = std::numeric_limits<int32_t>::max() - 256;

    void setPositionWithResizeHelper(uint32_t layerType);
    void setSizeBasicHelper(uint32_t layerType);
    void setMatrixWithResizeHelper(uint32_t layerType);

    sp<SurfaceControl> mBlackBgSurface;
    bool mColorManagementUsed;

private:
    void SetUpDisplay() {
        mDisplay = mClient->getBuiltInDisplay(ISurfaceComposer::eDisplayIdMain);
        ASSERT_NE(nullptr, mDisplay.get()) << "failed to get built-in display";

        // get display width/height
        DisplayInfo info;
        SurfaceComposerClient::getDisplayInfo(mDisplay, &info);
        mDisplayWidth = info.w;
        mDisplayHeight = info.h;

        // After a new buffer is queued, SurfaceFlinger is notified and will
        // latch the new buffer on next vsync.  Let's heuristically wait for 3
        // vsyncs.
        mBufferPostDelay = int32_t(1e6 / info.fps) * 3;

        mDisplayLayerStack = 0;

        mBlackBgSurface = mClient->createSurface(String8("BaseSurface"), mDisplayWidth,
                                                 mDisplayHeight, PIXEL_FORMAT_RGBA_8888,
                                                 ISurfaceComposerClient::eFXSurfaceColor);

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
};

class LayerTypeTransactionTest : public LayerTransactionTest,
                                 public ::testing::WithParamInterface<uint32_t> {
public:
    LayerTypeTransactionTest() { mLayerType = GetParam(); }

    sp<SurfaceControl> createLayer(const char* name, uint32_t width, uint32_t height,
                                   uint32_t flags = 0) override {
        // if the flags already have a layer type specified, return an error
        if (flags & ISurfaceComposerClient::eFXSurfaceMask) {
            return nullptr;
        }
        return LayerTransactionTest::createLayer(name, width, height, flags | mLayerType);
    }

    void fillLayerColor(const sp<SurfaceControl>& layer, const Color& color, int32_t bufferWidth,
                        int32_t bufferHeight) {
        ASSERT_NO_FATAL_FAILURE(LayerTransactionTest::fillLayerColor(mLayerType, layer, color,
                                                                     bufferWidth, bufferHeight));
    }

    void fillLayerQuadrant(const sp<SurfaceControl>& layer, int32_t bufferWidth,
                           int32_t bufferHeight, const Color& topLeft, const Color& topRight,
                           const Color& bottomLeft, const Color& bottomRight) {
        ASSERT_NO_FATAL_FAILURE(LayerTransactionTest::fillLayerQuadrant(mLayerType, layer,
                                                                        bufferWidth, bufferHeight,
                                                                        topLeft, topRight,
                                                                        bottomLeft, bottomRight));
    }

protected:
    uint32_t mLayerType;
};

INSTANTIATE_TEST_CASE_P(
        LayerTypeTransactionTests, LayerTypeTransactionTest,
        ::testing::Values(static_cast<uint32_t>(ISurfaceComposerClient::eFXSurfaceBufferQueue),
                          static_cast<uint32_t>(ISurfaceComposerClient::eFXSurfaceBufferState)));

TEST_P(LayerTypeTransactionTest, SetPositionBasic) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    {
        SCOPED_TRACE("default position");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
    }

    Transaction().setPosition(layer, 5, 10).apply();
    {
        SCOPED_TRACE("new position");
        auto shot = screenshot();
        shot->expectColor(Rect(5, 10, 37, 42), Color::RED);
        shot->expectBorder(Rect(5, 10, 37, 42), Color::BLACK);
    }
}

TEST_P(LayerTypeTransactionTest, SetPositionRounding) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    // GLES requires only 4 bits of subpixel precision during rasterization
    // XXX GLES composition does not match HWC composition due to precision
    // loss (b/69315223)
    const float epsilon = 1.0f / 16.0f;
    Transaction().setPosition(layer, 0.5f - epsilon, 0.5f - epsilon).apply();
    {
        SCOPED_TRACE("rounding down");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    Transaction().setPosition(layer, 0.5f + epsilon, 0.5f + epsilon).apply();
    {
        SCOPED_TRACE("rounding up");
        screenshot()->expectColor(Rect(1, 1, 33, 33), Color::RED);
    }
}

TEST_P(LayerTypeTransactionTest, SetPositionOutOfBounds) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    Transaction().setPosition(layer, -32, -32).apply();
    {
        SCOPED_TRACE("negative coordinates");
        screenshot()->expectColor(Rect(0, 0, mDisplayWidth, mDisplayHeight), Color::BLACK);
    }

    Transaction().setPosition(layer, mDisplayWidth, mDisplayHeight).apply();
    {
        SCOPED_TRACE("positive coordinates");
        screenshot()->expectColor(Rect(0, 0, mDisplayWidth, mDisplayHeight), Color::BLACK);
    }
}

TEST_P(LayerTypeTransactionTest, SetPositionPartiallyOutOfBounds) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    // partially out of bounds
    Transaction().setPosition(layer, -30, -30).apply();
    {
        SCOPED_TRACE("negative coordinates");
        screenshot()->expectColor(Rect(0, 0, 2, 2), Color::RED);
    }

    Transaction().setPosition(layer, mDisplayWidth - 2, mDisplayHeight - 2).apply();
    {
        SCOPED_TRACE("positive coordinates");
        screenshot()->expectColor(Rect(mDisplayWidth - 2, mDisplayHeight - 2, mDisplayWidth,
                                       mDisplayHeight),
                                  Color::RED);
    }
}

void LayerTransactionTest::setPositionWithResizeHelper(uint32_t layerType) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32, layerType));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layer, Color::RED, 32, 32));

    // setPosition is applied immediately by default, with or without resize
    // pending
    Transaction().setPosition(layer, 5, 10).setSize(layer, 64, 64).apply();
    {
        SCOPED_TRACE("resize pending");
        auto shot = screenshot();
        Rect rect;
        switch (layerType) {
            case ISurfaceComposerClient::eFXSurfaceBufferQueue:
                rect = {5, 10, 37, 42};
                break;
            case ISurfaceComposerClient::eFXSurfaceBufferState:
                rect = {5, 10, 69, 74};
                break;
            default:
                ASSERT_FALSE(true) << "Unsupported layer type";
        }

        shot->expectColor(rect, Color::RED);
        shot->expectBorder(rect, Color::BLACK);
    }

    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layer, Color::RED, 64, 64));
    {
        SCOPED_TRACE("resize applied");
        screenshot()->expectColor(Rect(5, 10, 69, 74), Color::RED);
    }
}

TEST_F(LayerTransactionTest, SetPositionWithResize_BufferQueue) {
    ASSERT_NO_FATAL_FAILURE(
            setPositionWithResizeHelper(ISurfaceComposerClient::eFXSurfaceBufferQueue));
}

TEST_F(LayerTransactionTest, SetPositionWithResize_BufferState) {
    ASSERT_NO_FATAL_FAILURE(
            setPositionWithResizeHelper(ISurfaceComposerClient::eFXSurfaceBufferState));
}

TEST_F(LayerTransactionTest, SetPositionWithNextResize_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    // request setPosition to be applied with the next resize
    Transaction().setPosition(layer, 5, 10).setGeometryAppliesWithResize(layer).apply();
    {
        SCOPED_TRACE("new position pending");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    Transaction().setPosition(layer, 15, 20).apply();
    {
        SCOPED_TRACE("pending new position modified");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    Transaction().setSize(layer, 64, 64).apply();
    {
        SCOPED_TRACE("resize pending");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    // finally resize and latch the buffer
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 64, 64));
    {
        SCOPED_TRACE("new position applied");
        screenshot()->expectColor(Rect(15, 20, 79, 84), Color::RED);
    }
}

TEST_F(LayerTransactionTest, SetPositionWithNextResizeScaleToWindow_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    // setPosition is not immediate even with SCALE_TO_WINDOW override
    Transaction()
            .setPosition(layer, 5, 10)
            .setSize(layer, 64, 64)
            .setOverrideScalingMode(layer, NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW)
            .setGeometryAppliesWithResize(layer)
            .apply();
    {
        SCOPED_TRACE("new position pending");
        screenshot()->expectColor(Rect(0, 0, 64, 64), Color::RED);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 64, 64));
    {
        SCOPED_TRACE("new position applied");
        screenshot()->expectColor(Rect(5, 10, 69, 74), Color::RED);
    }
}

void LayerTransactionTest::setSizeBasicHelper(uint32_t layerType) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32, layerType));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layer, Color::RED, 32, 32));

    Transaction().setSize(layer, 64, 64).apply();
    {
        SCOPED_TRACE("resize pending");
        auto shot = screenshot();
        Rect rect;
        switch (layerType) {
            case ISurfaceComposerClient::eFXSurfaceBufferQueue:
                rect = {0, 0, 32, 32};
                break;
            case ISurfaceComposerClient::eFXSurfaceBufferState:
                rect = {0, 0, 64, 64};
                break;
            default:
                ASSERT_FALSE(true) << "Unsupported layer type";
        }
        shot->expectColor(rect, Color::RED);
        shot->expectBorder(rect, Color::BLACK);
    }

    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layer, Color::RED, 64, 64));
    {
        SCOPED_TRACE("resize applied");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 64, 64), Color::RED);
        shot->expectBorder(Rect(0, 0, 64, 64), Color::BLACK);
    }
}

TEST_F(LayerTransactionTest, SetSizeBasic_BufferQueue) {
    setSizeBasicHelper(ISurfaceComposerClient::eFXSurfaceBufferQueue);
}

TEST_F(LayerTransactionTest, SetSizeBasic_BufferState) {
    setSizeBasicHelper(ISurfaceComposerClient::eFXSurfaceBufferState);
}

TEST_P(LayerTypeTransactionTest, SetSizeInvalid) {
    // cannot test robustness against invalid sizes (zero or really huge)
}

TEST_P(LayerTypeTransactionTest, SetSizeWithScaleToWindow) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    // setSize is immediate with SCALE_TO_WINDOW, unlike setPosition
    Transaction()
            .setSize(layer, 64, 64)
            .setOverrideScalingMode(layer, NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW)
            .apply();
    screenshot()->expectColor(Rect(0, 0, 64, 64), Color::RED);
}

TEST_P(LayerTypeTransactionTest, SetZBasic) {
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));

    Transaction().setLayer(layerR, mLayerZBase + 1).apply();
    {
        SCOPED_TRACE("layerR");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    Transaction().setLayer(layerG, mLayerZBase + 2).apply();
    {
        SCOPED_TRACE("layerG");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::GREEN);
    }
}

TEST_P(LayerTypeTransactionTest, SetZNegative) {
    sp<SurfaceControl> parent =
            LayerTransactionTest::createLayer("Parent", mDisplayWidth, mDisplayHeight,
                                              ISurfaceComposerClient::eFXSurfaceContainer);
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));

    Transaction()
            .reparent(layerR, parent->getHandle())
            .reparent(layerG, parent->getHandle())
            .apply();
    Transaction().setLayer(layerR, -1).setLayer(layerG, -2).apply();
    {
        SCOPED_TRACE("layerR");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    Transaction().setLayer(layerR, -3).apply();
    {
        SCOPED_TRACE("layerG");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::GREEN);
    }
}

TEST_P(LayerTypeTransactionTest, SetRelativeZBasic) {
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));

    Transaction()
            .setPosition(layerG, 16, 16)
            .setRelativeLayer(layerG, layerR->getHandle(), 1)
            .apply();
    {
        SCOPED_TRACE("layerG above");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 16, 16), Color::RED);
        shot->expectColor(Rect(16, 16, 48, 48), Color::GREEN);
    }

    Transaction().setRelativeLayer(layerG, layerR->getHandle(), -1).apply();
    {
        SCOPED_TRACE("layerG below");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectColor(Rect(32, 32, 48, 48), Color::GREEN);
    }
}

TEST_P(LayerTypeTransactionTest, SetRelativeZNegative) {
    sp<SurfaceControl> parent =
            LayerTransactionTest::createLayer("Parent", mDisplayWidth, mDisplayHeight,
                                              ISurfaceComposerClient::eFXSurfaceContainer);
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    sp<SurfaceControl> layerB;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerB = createLayer("test B", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerB, Color::BLUE, 32, 32));

    Transaction()
            .reparent(layerB, parent->getHandle())
            .apply();

    // layerR = mLayerZBase, layerG = layerR - 1, layerB = -2
    Transaction().setRelativeLayer(layerG, layerR->getHandle(), -1).setLayer(layerB, -2).apply();

    std::unique_ptr<ScreenCapture> screenshot;
    // only layerB is in this range
    sp<IBinder> parentHandle = parent->getHandle();
    ScreenCapture::captureLayers(&screenshot, parentHandle);
    screenshot->expectColor(Rect(0, 0, 32, 32), Color::BLUE);
}

TEST_P(LayerTypeTransactionTest, SetRelativeZGroup) {
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    sp<SurfaceControl> layerB;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerB = createLayer("test B", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerB, Color::BLUE, 32, 32));

    // layerR = 0, layerG = layerR + 3, layerB = 2
    Transaction()
            .setPosition(layerG, 8, 8)
            .setRelativeLayer(layerG, layerR->getHandle(), 3)
            .setPosition(layerB, 16, 16)
            .setLayer(layerB, mLayerZBase + 2)
            .apply();
    {
        SCOPED_TRACE("(layerR < layerG) < layerB");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 8, 8), Color::RED);
        shot->expectColor(Rect(8, 8, 16, 16), Color::GREEN);
        shot->expectColor(Rect(16, 16, 48, 48), Color::BLUE);
    }

    // layerR = 4, layerG = layerR + 3, layerB = 2
    Transaction().setLayer(layerR, mLayerZBase + 4).apply();
    {
        SCOPED_TRACE("layerB < (layerR < layerG)");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 8, 8), Color::RED);
        shot->expectColor(Rect(8, 8, 40, 40), Color::GREEN);
        shot->expectColor(Rect(40, 40, 48, 48), Color::BLUE);
    }

    // layerR = 4, layerG = layerR - 3, layerB = 2
    Transaction().setRelativeLayer(layerG, layerR->getHandle(), -3).apply();
    {
        SCOPED_TRACE("layerB < (layerG < layerR)");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectColor(Rect(32, 32, 40, 40), Color::GREEN);
        shot->expectColor(Rect(40, 40, 48, 48), Color::BLUE);
    }

    // restore to absolute z
    // layerR = 4, layerG = 0, layerB = 2
    Transaction().setLayer(layerG, mLayerZBase).apply();
    {
        SCOPED_TRACE("layerG < layerB < layerR");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectColor(Rect(32, 32, 48, 48), Color::BLUE);
    }

    // layerR should not affect layerG anymore
    // layerR = 1, layerG = 0, layerB = 2
    Transaction().setLayer(layerR, mLayerZBase + 1).apply();
    {
        SCOPED_TRACE("layerG < layerR < layerB");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 16, 16), Color::RED);
        shot->expectColor(Rect(16, 16, 48, 48), Color::BLUE);
    }
}

TEST_P(LayerTypeTransactionTest, SetRelativeZBug64572777) {
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;

    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));

    Transaction()
            .setPosition(layerG, 16, 16)
            .setRelativeLayer(layerG, layerR->getHandle(), 1)
            .apply();

    mClient->destroySurface(layerG->getHandle());
    // layerG should have been removed
    screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
}

TEST_P(LayerTypeTransactionTest, SetFlagsHidden) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    Transaction().setFlags(layer, layer_state_t::eLayerHidden, layer_state_t::eLayerHidden).apply();
    {
        SCOPED_TRACE("layer hidden");
        screenshot()->expectColor(Rect(0, 0, mDisplayWidth, mDisplayHeight), Color::BLACK);
    }

    Transaction().setFlags(layer, 0, layer_state_t::eLayerHidden).apply();
    {
        SCOPED_TRACE("layer shown");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }
}

TEST_P(LayerTypeTransactionTest, SetFlagsOpaque) {
    const Color translucentRed = {100, 0, 0, 100};
    sp<SurfaceControl> layerR;
    sp<SurfaceControl> layerG;
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, translucentRed, 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerG = createLayer("test G", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerG, Color::GREEN, 32, 32));

    Transaction()
            .setLayer(layerR, mLayerZBase + 1)
            .setFlags(layerR, layer_state_t::eLayerOpaque, layer_state_t::eLayerOpaque)
            .apply();
    {
        SCOPED_TRACE("layerR opaque");
        screenshot()->expectColor(Rect(0, 0, 32, 32), {100, 0, 0, 255});
    }

    Transaction().setFlags(layerR, 0, layer_state_t::eLayerOpaque).apply();
    {
        SCOPED_TRACE("layerR translucent");
        const uint8_t g = uint8_t(255 - translucentRed.a);
        screenshot()->expectColor(Rect(0, 0, 32, 32), {100, g, 0, 255});
    }
}

TEST_P(LayerTypeTransactionTest, SetFlagsSecure) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    sp<ISurfaceComposer> composer = ComposerService::getComposerService();
    sp<GraphicBuffer> outBuffer;
    Transaction()
            .setFlags(layer, layer_state_t::eLayerSecure, layer_state_t::eLayerSecure)
            .apply(true);
    ASSERT_EQ(PERMISSION_DENIED,
              composer->captureScreen(mDisplay, &outBuffer, Rect(), 0, 0, false));

    Transaction().setFlags(layer, 0, layer_state_t::eLayerSecure).apply(true);
    ASSERT_EQ(NO_ERROR,
              composer->captureScreen(mDisplay, &outBuffer, Rect(), 0, 0, false));
}

TEST_F(LayerTransactionTest, SetTransparentRegionHintBasic_BufferQueue) {
    const Rect top(0, 0, 32, 16);
    const Rect bottom(0, 16, 32, 32);
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));

    ANativeWindow_Buffer buffer;
    ASSERT_NO_FATAL_FAILURE(buffer = getBufferQueueLayerBuffer(layer));
    ASSERT_NO_FATAL_FAILURE(fillANativeWindowBufferColor(buffer, top, Color::TRANSPARENT));
    ASSERT_NO_FATAL_FAILURE(fillANativeWindowBufferColor(buffer, bottom, Color::RED));
    // setTransparentRegionHint always applies to the following buffer
    Transaction().setTransparentRegionHint(layer, Region(top)).apply();
    ASSERT_NO_FATAL_FAILURE(postBufferQueueLayerBuffer(layer));
    {
        SCOPED_TRACE("top transparent");
        auto shot = screenshot();
        shot->expectColor(top, Color::BLACK);
        shot->expectColor(bottom, Color::RED);
    }

    Transaction().setTransparentRegionHint(layer, Region(bottom)).apply();
    {
        SCOPED_TRACE("transparent region hint pending");
        auto shot = screenshot();
        shot->expectColor(top, Color::BLACK);
        shot->expectColor(bottom, Color::RED);
    }

    ASSERT_NO_FATAL_FAILURE(buffer = getBufferQueueLayerBuffer(layer));
    ASSERT_NO_FATAL_FAILURE(fillANativeWindowBufferColor(buffer, top, Color::RED));
    ASSERT_NO_FATAL_FAILURE(fillANativeWindowBufferColor(buffer, bottom, Color::TRANSPARENT));
    ASSERT_NO_FATAL_FAILURE(postBufferQueueLayerBuffer(layer));
    {
        SCOPED_TRACE("bottom transparent");
        auto shot = screenshot();
        shot->expectColor(top, Color::RED);
        shot->expectColor(bottom, Color::BLACK);
    }
}

TEST_F(LayerTransactionTest, SetTransparentRegionHintBasic_BufferState) {
    const Rect top(0, 0, 32, 16);
    const Rect bottom(0, 16, 32, 32);
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1,
                              BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                      BufferUsage::COMPOSER_OVERLAY,
                              "test");

    ASSERT_NO_FATAL_FAILURE(fillGraphicBufferColor(buffer, top, Color::TRANSPARENT));
    ASSERT_NO_FATAL_FAILURE(fillGraphicBufferColor(buffer, bottom, Color::RED));
    Transaction()
            .setTransparentRegionHint(layer, Region(top))
            .setBuffer(layer, buffer)
            .setSize(layer, 32, 32)
            .apply();
    {
        SCOPED_TRACE("top transparent");
        auto shot = screenshot();
        shot->expectColor(top, Color::BLACK);
        shot->expectColor(bottom, Color::RED);
    }

    Transaction().setTransparentRegionHint(layer, Region(bottom)).apply();
    {
        SCOPED_TRACE("transparent region hint intermediate");
        auto shot = screenshot();
        shot->expectColor(top, Color::BLACK);
        shot->expectColor(bottom, Color::BLACK);
    }

    buffer = new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1,
                               BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                       BufferUsage::COMPOSER_OVERLAY,
                               "test");

    ASSERT_NO_FATAL_FAILURE(fillGraphicBufferColor(buffer, top, Color::RED));
    ASSERT_NO_FATAL_FAILURE(fillGraphicBufferColor(buffer, bottom, Color::TRANSPARENT));
    Transaction().setBuffer(layer, buffer).setSize(layer, 32, 32).apply();
    {
        SCOPED_TRACE("bottom transparent");
        auto shot = screenshot();
        shot->expectColor(top, Color::RED);
        shot->expectColor(bottom, Color::BLACK);
    }
}

TEST_P(LayerTypeTransactionTest, SetTransparentRegionHintOutOfBounds) {
    sp<SurfaceControl> layerTransparent;
    sp<SurfaceControl> layerR;
    ASSERT_NO_FATAL_FAILURE(layerTransparent = createLayer("test transparent", 32, 32));
    ASSERT_NO_FATAL_FAILURE(layerR = createLayer("test R", 32, 32));

    // check that transparent region hint is bound by the layer size
    Transaction()
            .setTransparentRegionHint(layerTransparent,
                                      Region(Rect(0, 0, mDisplayWidth, mDisplayHeight)))
            .setPosition(layerR, 16, 16)
            .setLayer(layerR, mLayerZBase + 1)
            .apply();
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerTransparent, Color::TRANSPARENT, 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerR, Color::RED, 32, 32));
    screenshot()->expectColor(Rect(16, 16, 48, 48), Color::RED);
}

TEST_P(LayerTypeTransactionTest, SetAlphaBasic) {
    sp<SurfaceControl> layer1;
    sp<SurfaceControl> layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createLayer("test 1", 32, 32));
    ASSERT_NO_FATAL_FAILURE(layer2 = createLayer("test 2", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer1, {64, 0, 0, 255}, 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer2, {0, 64, 0, 255}, 32, 32));

    Transaction()
            .setAlpha(layer1, 0.25f)
            .setAlpha(layer2, 0.75f)
            .setPosition(layer2, 16, 0)
            .setLayer(layer2, mLayerZBase + 1)
            .apply();
    {
        auto shot = screenshot();
        uint8_t r = 16; // 64 * 0.25f
        uint8_t g = 48; // 64 * 0.75f
        shot->expectColor(Rect(0, 0, 16, 32), {r, 0, 0, 255});
        shot->expectColor(Rect(32, 0, 48, 32), {0, g, 0, 255});

        r /= 4; // r * (1.0f - 0.75f)
        shot->expectColor(Rect(16, 0, 32, 32), {r, g, 0, 255});
    }
}

TEST_P(LayerTypeTransactionTest, SetAlphaClamped) {
    const Color color = {64, 0, 0, 255};
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, color, 32, 32));

    Transaction().setAlpha(layer, 2.0f).apply();
    {
        SCOPED_TRACE("clamped to 1.0f");
        screenshot()->expectColor(Rect(0, 0, 32, 32), color);
    }

    Transaction().setAlpha(layer, -1.0f).apply();
    {
        SCOPED_TRACE("clamped to 0.0f");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    }
}

TEST_F(LayerTransactionTest, SetColorBasic) {
    sp<SurfaceControl> bufferLayer;
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(bufferLayer = createLayer("test bg", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(bufferLayer, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(
            colorLayer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceColor));

    Transaction().setLayer(colorLayer, mLayerZBase + 1).apply();
    {
        SCOPED_TRACE("default color");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    }

    const half3 color(15.0f / 255.0f, 51.0f / 255.0f, 85.0f / 255.0f);
    const Color expected = {15, 51, 85, 255};
    // this is handwavy, but the precison loss scaled by 255 (8-bit per
    // channel) should be less than one
    const uint8_t tolerance = 1;
    Transaction().setColor(colorLayer, color).apply();
    {
        SCOPED_TRACE("new color");
        screenshot()->expectColor(Rect(0, 0, 32, 32), expected, tolerance);
    }
}

TEST_F(LayerTransactionTest, SetColorClamped) {
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(
            colorLayer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceColor));

    Transaction().setColor(colorLayer, half3(2.0f, -1.0f, 0.0f)).apply();
    screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
}

TEST_F(LayerTransactionTest, SetColorWithAlpha) {
    sp<SurfaceControl> bufferLayer;
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(bufferLayer = createLayer("test bg", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(bufferLayer, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(
            colorLayer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceColor));

    const half3 color(15.0f / 255.0f, 51.0f / 255.0f, 85.0f / 255.0f);
    const float alpha = 0.25f;
    const ubyte3 expected((vec3(color) * alpha + vec3(1.0f, 0.0f, 0.0f) * (1.0f - alpha)) * 255.0f);
    // this is handwavy, but the precison loss scaled by 255 (8-bit per
    // channel) should be less than one
    const uint8_t tolerance = 1;
    Transaction()
            .setColor(colorLayer, color)
            .setAlpha(colorLayer, alpha)
            .setLayer(colorLayer, mLayerZBase + 1)
            .apply();
    screenshot()->expectColor(Rect(0, 0, 32, 32), {expected.r, expected.g, expected.b, 255},
                              tolerance);
}

TEST_F(LayerTransactionTest, SetColorWithParentAlpha_Bug74220420) {
    sp<SurfaceControl> bufferLayer;
    sp<SurfaceControl> parentLayer;
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(bufferLayer = createLayer("test bg", 32, 32));
    ASSERT_NO_FATAL_FAILURE(parentLayer = createLayer("parentWithAlpha", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(bufferLayer, Color::RED, 32, 32));
    ASSERT_NO_FATAL_FAILURE(colorLayer = createLayer(
            "childWithColor", 32, 32, ISurfaceComposerClient::eFXSurfaceColor));

    const half3 color(15.0f / 255.0f, 51.0f / 255.0f, 85.0f / 255.0f);
    const float alpha = 0.25f;
    const ubyte3 expected((vec3(color) * alpha + vec3(1.0f, 0.0f, 0.0f) * (1.0f - alpha)) * 255.0f);
    // this is handwavy, but the precision loss scaled by 255 (8-bit per
    // channel) should be less than one
    const uint8_t tolerance = 1;
    Transaction()
            .reparent(colorLayer, parentLayer->getHandle())
            .setColor(colorLayer, color)
            .setAlpha(parentLayer, alpha)
            .setLayer(parentLayer, mLayerZBase + 1)
            .apply();
    screenshot()->expectColor(Rect(0, 0, 32, 32), {expected.r, expected.g, expected.b, 255},
                              tolerance);
}

TEST_P(LayerTypeTransactionTest, SetColorWithBuffer) {
    sp<SurfaceControl> bufferLayer;
    ASSERT_NO_FATAL_FAILURE(bufferLayer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(bufferLayer, Color::RED, 32, 32));

    // color is ignored
    Transaction().setColor(bufferLayer, half3(0.0f, 1.0f, 0.0f)).apply();
    screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
}

TEST_P(LayerTypeTransactionTest, SetLayerStackBasic) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    Transaction().setLayerStack(layer, mDisplayLayerStack + 1).apply();
    {
        SCOPED_TRACE("non-existing layer stack");
        screenshot()->expectColor(Rect(0, 0, mDisplayWidth, mDisplayHeight), Color::BLACK);
    }

    Transaction().setLayerStack(layer, mDisplayLayerStack).apply();
    {
        SCOPED_TRACE("original layer stack");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }
}

TEST_P(LayerTypeTransactionTest, SetMatrixBasic) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(
            fillLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN, Color::BLUE, Color::WHITE));

    Transaction().setMatrix(layer, 1.0f, 0.0f, 0.0f, 1.0f).setPosition(layer, 0, 0).apply();
    {
        SCOPED_TRACE("IDENTITY");
        screenshot()->expectQuadrant(Rect(0, 0, 32, 32), Color::RED, Color::GREEN, Color::BLUE,
                                     Color::WHITE);
    }

    Transaction().setMatrix(layer, -1.0f, 0.0f, 0.0f, 1.0f).setPosition(layer, 32, 0).apply();
    {
        SCOPED_TRACE("FLIP_H");
        screenshot()->expectQuadrant(Rect(0, 0, 32, 32), Color::GREEN, Color::RED, Color::WHITE,
                                     Color::BLUE);
    }

    Transaction().setMatrix(layer, 1.0f, 0.0f, 0.0f, -1.0f).setPosition(layer, 0, 32).apply();
    {
        SCOPED_TRACE("FLIP_V");
        screenshot()->expectQuadrant(Rect(0, 0, 32, 32), Color::BLUE, Color::WHITE, Color::RED,
                                     Color::GREEN);
    }

    Transaction().setMatrix(layer, 0.0f, 1.0f, -1.0f, 0.0f).setPosition(layer, 32, 0).apply();
    {
        SCOPED_TRACE("ROT_90");
        screenshot()->expectQuadrant(Rect(0, 0, 32, 32), Color::BLUE, Color::RED, Color::WHITE,
                                     Color::GREEN);
    }

    Transaction().setMatrix(layer, 2.0f, 0.0f, 0.0f, 2.0f).setPosition(layer, 0, 0).apply();
    {
        SCOPED_TRACE("SCALE");
        screenshot()->expectQuadrant(Rect(0, 0, 64, 64), Color::RED, Color::GREEN, Color::BLUE,
                                     Color::WHITE, true /* filtered */);
    }
}

TEST_P(LayerTypeTransactionTest, SetMatrixRot45) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(
            fillLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN, Color::BLUE, Color::WHITE));

    const float rot = M_SQRT1_2; // 45 degrees
    const float trans = M_SQRT2 * 16.0f;
    Transaction().setMatrix(layer, rot, rot, -rot, rot).setPosition(layer, trans, 0).apply();

    auto shot = screenshot();
    // check a 8x8 region inside each color
    auto get8x8Rect = [](int32_t centerX, int32_t centerY) {
        const int32_t halfL = 4;
        return Rect(centerX - halfL, centerY - halfL, centerX + halfL, centerY + halfL);
    };
    const int32_t unit = int32_t(trans / 2);
    shot->expectColor(get8x8Rect(2 * unit, 1 * unit), Color::RED);
    shot->expectColor(get8x8Rect(3 * unit, 2 * unit), Color::GREEN);
    shot->expectColor(get8x8Rect(1 * unit, 2 * unit), Color::BLUE);
    shot->expectColor(get8x8Rect(2 * unit, 3 * unit), Color::WHITE);
}

void LayerTransactionTest::setMatrixWithResizeHelper(uint32_t layerType) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32, layerType));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layer, Color::RED, 32, 32));

    // setMatrix is applied after any pending resize, unlike setPosition
    Transaction().setMatrix(layer, 2.0f, 0.0f, 0.0f, 2.0f).setSize(layer, 64, 64).apply();
    {
        SCOPED_TRACE("resize pending");
        auto shot = screenshot();
        Rect rect;
        switch (layerType) {
            case ISurfaceComposerClient::eFXSurfaceBufferQueue:
                rect = {0, 0, 32, 32};
                break;
            case ISurfaceComposerClient::eFXSurfaceBufferState:
                rect = {0, 0, 128, 128};
                break;
            default:
                ASSERT_FALSE(true) << "Unsupported layer type";
        }
        shot->expectColor(rect, Color::RED);
        shot->expectBorder(rect, Color::BLACK);
    }

    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layerType, layer, Color::RED, 64, 64));
    {
        SCOPED_TRACE("resize applied");
        screenshot()->expectColor(Rect(0, 0, 128, 128), Color::RED);
    }
}

TEST_F(LayerTransactionTest, SetMatrixWithResize_BufferQueue) {
    ASSERT_NO_FATAL_FAILURE(
            setMatrixWithResizeHelper(ISurfaceComposerClient::eFXSurfaceBufferQueue));
}

TEST_F(LayerTransactionTest, SetMatrixWithResize_BufferState) {
    ASSERT_NO_FATAL_FAILURE(
            setMatrixWithResizeHelper(ISurfaceComposerClient::eFXSurfaceBufferState));
}

TEST_P(LayerTypeTransactionTest, SetMatrixWithScaleToWindow) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillLayerColor(layer, Color::RED, 32, 32));

    // setMatrix is immediate with SCALE_TO_WINDOW, unlike setPosition
    Transaction()
            .setMatrix(layer, 2.0f, 0.0f, 0.0f, 2.0f)
            .setSize(layer, 64, 64)
            .setOverrideScalingMode(layer, NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW)
            .apply();
    screenshot()->expectColor(Rect(0, 0, 128, 128), Color::RED);
}

TEST_P(LayerTypeTransactionTest, SetOverrideScalingModeBasic) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(
            fillLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN, Color::BLUE, Color::WHITE));

    // XXX SCALE_CROP is not respected; calling setSize and
    // setOverrideScalingMode in separate transactions does not work
    // (b/69315456)
    Transaction()
            .setSize(layer, 64, 16)
            .setOverrideScalingMode(layer, NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW)
            .apply();
    {
        SCOPED_TRACE("SCALE_TO_WINDOW");
        screenshot()->expectQuadrant(Rect(0, 0, 64, 16), Color::RED, Color::GREEN, Color::BLUE,
                                     Color::WHITE, true /* filtered */);
    }
}

TEST_P(LayerTypeTransactionTest, RefreshRateIsInitialized) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));

    sp<IBinder> handle = layer->getHandle();
    ASSERT_TRUE(handle != nullptr);

    FrameStats frameStats;
    mClient->getLayerFrameStats(handle, &frameStats);

    ASSERT_GT(frameStats.refreshPeriodNano, static_cast<nsecs_t>(0));
}

TEST_F(LayerTransactionTest, SetCropBasic_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));
    const Rect crop(8, 8, 24, 24);

    Transaction().setCrop_legacy(layer, crop).apply();
    auto shot = screenshot();
    shot->expectColor(crop, Color::RED);
    shot->expectBorder(crop, Color::BLACK);
}

TEST_F(LayerTransactionTest, SetCropBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));
    const Rect crop(8, 8, 24, 24);

    Transaction().setCrop(layer, crop).apply();
    auto shot = screenshot();
    shot->expectColor(crop, Color::RED);
    shot->expectBorder(crop, Color::BLACK);
}

TEST_F(LayerTransactionTest, SetCropEmpty_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    {
        SCOPED_TRACE("empty rect");
        Transaction().setCrop_legacy(layer, Rect(8, 8, 8, 8)).apply();
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    {
        SCOPED_TRACE("negative rect");
        Transaction().setCrop_legacy(layer, Rect(8, 8, 0, 0)).apply();
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }
}

TEST_F(LayerTransactionTest, SetCropEmpty_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    {
        SCOPED_TRACE("empty rect");
        Transaction().setCrop(layer, Rect(8, 8, 8, 8)).apply();
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    {
        SCOPED_TRACE("negative rect");
        Transaction().setCrop(layer, Rect(8, 8, 0, 0)).apply();
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }
}

TEST_F(LayerTransactionTest, SetCropOutOfBounds_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    Transaction().setCrop_legacy(layer, Rect(-128, -64, 128, 64)).apply();
    auto shot = screenshot();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_F(LayerTransactionTest, SetCropOutOfBounds_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    Transaction().setCrop(layer, Rect(-128, -64, 128, 64)).apply();
    auto shot = screenshot();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_F(LayerTransactionTest, SetCropWithTranslation_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    const Point position(32, 32);
    const Rect crop(8, 8, 24, 24);
    Transaction().setPosition(layer, position.x, position.y).setCrop_legacy(layer, crop).apply();
    auto shot = screenshot();
    shot->expectColor(crop + position, Color::RED);
    shot->expectBorder(crop + position, Color::BLACK);
}

TEST_F(LayerTransactionTest, SetCropWithTranslation_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    const Point position(32, 32);
    const Rect crop(8, 8, 24, 24);
    Transaction().setPosition(layer, position.x, position.y).setCrop(layer, crop).apply();
    auto shot = screenshot();
    shot->expectColor(crop + position, Color::RED);
    shot->expectBorder(crop + position, Color::BLACK);
}

TEST_F(LayerTransactionTest, SetCropWithScale_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    // crop is affected by matrix
    Transaction()
            .setMatrix(layer, 2.0f, 0.0f, 0.0f, 2.0f)
            .setCrop_legacy(layer, Rect(8, 8, 24, 24))
            .apply();
    auto shot = screenshot();
    shot->expectColor(Rect(16, 16, 48, 48), Color::RED);
    shot->expectBorder(Rect(16, 16, 48, 48), Color::BLACK);
}

TEST_F(LayerTransactionTest, SetCropWithScale_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    // crop is affected by matrix
    Transaction()
            .setMatrix(layer, 2.0f, 0.0f, 0.0f, 2.0f)
            .setCrop(layer, Rect(8, 8, 24, 24))
            .apply();
    auto shot = screenshot();
    shot->expectColor(Rect(16, 16, 48, 48), Color::RED);
    shot->expectBorder(Rect(16, 16, 48, 48), Color::BLACK);
}

TEST_F(LayerTransactionTest, SetCropWithResize_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    // setCrop_legacy is applied immediately by default, with or without resize pending
    Transaction().setCrop_legacy(layer, Rect(8, 8, 24, 24)).setSize(layer, 16, 16).apply();
    {
        SCOPED_TRACE("resize pending");
        auto shot = screenshot();
        shot->expectColor(Rect(8, 8, 24, 24), Color::RED);
        shot->expectBorder(Rect(8, 8, 24, 24), Color::BLACK);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 16, 16));
    {
        SCOPED_TRACE("resize applied");
        auto shot = screenshot();
        shot->expectColor(Rect(8, 8, 16, 16), Color::RED);
        shot->expectBorder(Rect(8, 8, 16, 16), Color::BLACK);
    }
}

TEST_F(LayerTransactionTest, SetCropWithResize_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    // setCrop_legacy is applied immediately by default, with or without resize pending
    Transaction().setCrop(layer, Rect(8, 8, 24, 24)).setSize(layer, 16, 16).apply();
    {
        SCOPED_TRACE("new buffer pending");
        auto shot = screenshot();
        shot->expectColor(Rect(8, 8, 16, 16), Color::RED);
        shot->expectBorder(Rect(8, 8, 16, 16), Color::BLACK);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 16, 16));
    {
        SCOPED_TRACE("new buffer");
        auto shot = screenshot();
        shot->expectColor(Rect(8, 8, 16, 16), Color::RED);
        shot->expectBorder(Rect(8, 8, 16, 16), Color::BLACK);
    }
}

TEST_F(LayerTransactionTest, SetCropWithNextResize_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    // request setCrop_legacy to be applied with the next resize
    Transaction()
            .setCrop_legacy(layer, Rect(8, 8, 24, 24))
            .setGeometryAppliesWithResize(layer)
            .apply();
    {
        SCOPED_TRACE("waiting for next resize");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    Transaction().setCrop_legacy(layer, Rect(4, 4, 12, 12)).apply();
    {
        SCOPED_TRACE("pending crop modified");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    Transaction().setSize(layer, 16, 16).apply();
    {
        SCOPED_TRACE("resize pending");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::RED);
    }

    // finally resize
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 16, 16));
    {
        SCOPED_TRACE("new crop applied");
        auto shot = screenshot();
        shot->expectColor(Rect(4, 4, 12, 12), Color::RED);
        shot->expectBorder(Rect(4, 4, 12, 12), Color::BLACK);
    }
}

TEST_F(LayerTransactionTest, SetCropWithNextResize_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    // request setCrop_legacy to be applied with the next resize
    Transaction().setCrop(layer, Rect(8, 8, 24, 24)).setGeometryAppliesWithResize(layer).apply();
    {
        SCOPED_TRACE("set crop 1");
        screenshot()->expectColor(Rect(8, 8, 24, 24), Color::RED);
    }

    Transaction().setCrop(layer, Rect(4, 4, 12, 12)).apply();
    {
        SCOPED_TRACE("set crop 2");
        screenshot()->expectColor(Rect(4, 4, 12, 12), Color::RED);
    }

    Transaction().setSize(layer, 16, 16).apply();
    {
        SCOPED_TRACE("resize");
        screenshot()->expectColor(Rect(4, 4, 12, 12), Color::RED);
    }

    // finally resize
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 16, 16));
    {
        SCOPED_TRACE("new buffer");
        auto shot = screenshot();
        shot->expectColor(Rect(4, 4, 12, 12), Color::RED);
        shot->expectBorder(Rect(4, 4, 12, 12), Color::BLACK);
    }
}

TEST_F(LayerTransactionTest, SetCropWithNextResizeScaleToWindow_BufferQueue) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createLayer("test", 32, 32));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 32, 32));

    // setCrop_legacy is not immediate even with SCALE_TO_WINDOW override
    Transaction()
            .setCrop_legacy(layer, Rect(4, 4, 12, 12))
            .setSize(layer, 16, 16)
            .setOverrideScalingMode(layer, NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW)
            .setGeometryAppliesWithResize(layer)
            .apply();
    {
        SCOPED_TRACE("new crop pending");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 16, 16), Color::RED);
        shot->expectBorder(Rect(0, 0, 16, 16), Color::BLACK);
    }

    // XXX crop is never latched without other geometry change (b/69315677)
    Transaction().setPosition(layer, 1, 0).setGeometryAppliesWithResize(layer).apply();
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(layer, Color::RED, 16, 16));
    Transaction().setPosition(layer, 0, 0).apply();
    {
        SCOPED_TRACE("new crop applied");
        auto shot = screenshot();
        shot->expectColor(Rect(4, 4, 12, 12), Color::RED);
        shot->expectBorder(Rect(4, 4, 12, 12), Color::BLACK);
    }
}

TEST_F(LayerTransactionTest, SetCropWithNextResizeScaleToWindow_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    // all properties are applied immediate so setGeometryAppliesWithResize has no effect
    Transaction()
            .setCrop(layer, Rect(4, 4, 12, 12))
            .setSize(layer, 16, 16)
            .setOverrideScalingMode(layer, NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW)
            .setGeometryAppliesWithResize(layer)
            .apply();
    {
        SCOPED_TRACE("new crop pending");
        auto shot = screenshot();
        shot->expectColor(Rect(4, 4, 12, 12), Color::RED);
        shot->expectBorder(Rect(4, 4, 12, 12), Color::BLACK);
    }

    Transaction().setPosition(layer, 1, 0).setGeometryAppliesWithResize(layer).apply();
    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 16, 16));
    Transaction().setPosition(layer, 0, 0).apply();
    {
        SCOPED_TRACE("new crop applied");
        auto shot = screenshot();
        shot->expectColor(Rect(4, 4, 12, 12), Color::RED);
        shot->expectBorder(Rect(4, 4, 12, 12), Color::BLACK);
    }
}

TEST_F(LayerTransactionTest, SetBufferBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    auto shot = screenshot();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_F(LayerTransactionTest, SetBufferMultipleBuffers_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    {
        SCOPED_TRACE("set buffer 1");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::BLUE, 32, 32));

    {
        SCOPED_TRACE("set buffer 2");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::BLUE);
        shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::RED, 32, 32));

    {
        SCOPED_TRACE("set buffer 3");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
        shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
    }
}

TEST_F(LayerTransactionTest, SetBufferMultipleLayers_BufferState) {
    sp<SurfaceControl> layer1;
    ASSERT_NO_FATAL_FAILURE(
            layer1 = createLayer("test", 64, 64, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<SurfaceControl> layer2;
    ASSERT_NO_FATAL_FAILURE(
            layer2 = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer1, Color::RED, 64, 64));

    {
        SCOPED_TRACE("set layer 1 buffer red");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 64, 64), Color::RED);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer2, Color::BLUE, 32, 32));

    {
        SCOPED_TRACE("set layer 2 buffer blue");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::BLUE);
        shot->expectColor(Rect(0, 32, 64, 64), Color::RED);
        shot->expectColor(Rect(0, 32, 32, 64), Color::RED);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer1, Color::GREEN, 64, 64));
    {
        SCOPED_TRACE("set layer 1 buffer green");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::BLUE);
        shot->expectColor(Rect(0, 32, 64, 64), Color::GREEN);
        shot->expectColor(Rect(0, 32, 32, 64), Color::GREEN);
    }

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer2, Color::WHITE, 32, 32));

    {
        SCOPED_TRACE("set layer 2 buffer white");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 32, 32), Color::WHITE);
        shot->expectColor(Rect(0, 32, 64, 64), Color::GREEN);
        shot->expectColor(Rect(0, 32, 32, 64), Color::GREEN);
    }
}

TEST_F(LayerTransactionTest, SetTransformRotate90_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN,
                                                         Color::BLUE, Color::WHITE));

    Transaction().setTransform(layer, NATIVE_WINDOW_TRANSFORM_ROT_90).apply();

    screenshot()->expectQuadrant(Rect(0, 0, 32, 32), Color::BLUE, Color::RED, Color::WHITE,
                                 Color::GREEN, true /* filtered */);
}

TEST_F(LayerTransactionTest, SetTransformFlipH_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN,
                                                         Color::BLUE, Color::WHITE));

    Transaction().setTransform(layer, NATIVE_WINDOW_TRANSFORM_FLIP_H).apply();

    screenshot()->expectQuadrant(Rect(0, 0, 32, 32), Color::GREEN, Color::RED, Color::WHITE,
                                 Color::BLUE, true /* filtered */);
}

TEST_F(LayerTransactionTest, SetTransformFlipV_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerQuadrant(layer, 32, 32, Color::RED, Color::GREEN,
                                                         Color::BLUE, Color::WHITE));

    Transaction().setTransform(layer, NATIVE_WINDOW_TRANSFORM_FLIP_V).apply();

    screenshot()->expectQuadrant(Rect(0, 0, 32, 32), Color::BLUE, Color::WHITE, Color::RED,
                                 Color::GREEN, true /* filtered */);
}

TEST_F(LayerTransactionTest, SetTransformToDisplayInverse_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    Transaction().setTransformToDisplayInverse(layer, false).apply();

    ASSERT_NO_FATAL_FAILURE(fillBufferStateLayerColor(layer, Color::GREEN, 32, 32));

    Transaction().setTransformToDisplayInverse(layer, true).apply();
}

TEST_F(LayerTransactionTest, SetFenceBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1,
                              BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                      BufferUsage::COMPOSER_OVERLAY,
                              "test");
    fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    sp<Fence> fence = Fence::NO_FENCE;

    Transaction()
            .setBuffer(layer, buffer)
            .setAcquireFence(layer, fence)
            .setSize(layer, 32, 32)
            .apply();

    auto shot = screenshot();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_F(LayerTransactionTest, SetDataspaceBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1,
                              BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                      BufferUsage::COMPOSER_OVERLAY,
                              "test");
    fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    Transaction()
            .setBuffer(layer, buffer)
            .setDataspace(layer, ui::Dataspace::UNKNOWN)
            .setSize(layer, 32, 32)
            .apply();

    auto shot = screenshot();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_F(LayerTransactionTest, SetHdrMetadataBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1,
                              BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                      BufferUsage::COMPOSER_OVERLAY,
                              "test");
    fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    HdrMetadata hdrMetadata;
    hdrMetadata.validTypes = 0;
    Transaction()
            .setBuffer(layer, buffer)
            .setHdrMetadata(layer, hdrMetadata)
            .setSize(layer, 32, 32)
            .apply();

    auto shot = screenshot();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_F(LayerTransactionTest, SetSurfaceDamageRegionBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1,
                              BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                      BufferUsage::COMPOSER_OVERLAY,
                              "test");
    fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    Region region;
    region.set(32, 32);
    Transaction()
            .setBuffer(layer, buffer)
            .setSurfaceDamageRegion(layer, region)
            .setSize(layer, 32, 32)
            .apply();

    auto shot = screenshot();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_F(LayerTransactionTest, SetApiBasic_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    sp<GraphicBuffer> buffer =
            new GraphicBuffer(32, 32, PIXEL_FORMAT_RGBA_8888, 1,
                              BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                      BufferUsage::COMPOSER_OVERLAY,
                              "test");
    fillGraphicBufferColor(buffer, Rect(0, 0, 32, 32), Color::RED);

    Transaction()
            .setBuffer(layer, buffer)
            .setApi(layer, NATIVE_WINDOW_API_CPU)
            .setSize(layer, 32, 32)
            .apply();

    auto shot = screenshot();
    shot->expectColor(Rect(0, 0, 32, 32), Color::RED);
    shot->expectBorder(Rect(0, 0, 32, 32), Color::BLACK);
}

TEST_F(LayerTransactionTest, SetSidebandStreamNull_BufferState) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(
            layer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceBufferState));

    // verify this doesn't cause a crash
    Transaction().setSidebandStream(layer, nullptr).apply();
}

class ColorTransformHelper {
public:
    static void DegammaColorSingle(half& s) {
        if (s <= 0.03928f)
            s = s / 12.92f;
        else
            s = pow((s + 0.055f) / 1.055f, 2.4f);
    }

    static void DegammaColor(half3& color) {
        DegammaColorSingle(color.r);
        DegammaColorSingle(color.g);
        DegammaColorSingle(color.b);
    }

    static void GammaColorSingle(half& s) {
        if (s <= 0.0031308f) {
            s = s * 12.92f;
        } else {
            s = 1.055f * pow(s, (1.0f / 2.4f)) - 0.055f;
        }
    }

    static void GammaColor(half3& color) {
        GammaColorSingle(color.r);
        GammaColorSingle(color.g);
        GammaColorSingle(color.b);
    }

    static void applyMatrix(half3& color, const mat3& mat) {
        half3 ret = half3(0);

        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                ret[i] = ret[i] + color[j] * mat[j][i];
            }
        }
        color = ret;
    }
};

TEST_F(LayerTransactionTest, SetColorTransformBasic) {
    sp<SurfaceControl> colorLayer;
    ASSERT_NO_FATAL_FAILURE(
            colorLayer = createLayer("test", 32, 32, ISurfaceComposerClient::eFXSurfaceColor));

    Transaction().setLayer(colorLayer, mLayerZBase + 1).apply();
    {
        SCOPED_TRACE("default color");
        screenshot()->expectColor(Rect(0, 0, 32, 32), Color::BLACK);
    }

    const half3 color(50.0f / 255.0f, 100.0f / 255.0f, 150.0f / 255.0f);
    half3 expected = color;
    mat3 matrix;
    matrix[0][0] = 0.3; matrix[1][0] = 0.59; matrix[2][0] = 0.11;
    matrix[0][1] = 0.3; matrix[1][1] = 0.59; matrix[2][1] = 0.11;
    matrix[0][2] = 0.3; matrix[1][2] = 0.59; matrix[2][2] = 0.11;

    // degamma before applying the matrix
    if (mColorManagementUsed) {
        ColorTransformHelper::DegammaColor(expected);
    }

    ColorTransformHelper::applyMatrix(expected, matrix);

    if (mColorManagementUsed) {
        ColorTransformHelper::GammaColor(expected);
    }

    const Color expectedColor = {uint8_t(expected.r * 255), uint8_t(expected.g * 255),
                                 uint8_t(expected.b * 255), 255};

    // this is handwavy, but the precison loss scaled by 255 (8-bit per
    // channel) should be less than one
    const uint8_t tolerance = 1;

    Transaction().setColor(colorLayer, color)
        .setColorTransform(colorLayer, matrix, vec3()).apply();
    {
        SCOPED_TRACE("new color");
        screenshot()->expectColor(Rect(0, 0, 32, 32), expectedColor, tolerance);
    }
}

class ExpectedResult {
public:
    enum Transaction {
        NOT_PRESENTED = 0,
        PRESENTED,
    };

    enum Buffer {
        NOT_ACQUIRED = 0,
        ACQUIRED,
    };

    enum PreviousBuffer {
        NOT_RELEASED = 0,
        RELEASED,
    };

    void reset() {
        mTransactionResult = ExpectedResult::Transaction::NOT_PRESENTED;
        mExpectedSurfaceResults.clear();
    }

    void addSurface(ExpectedResult::Transaction transactionResult, const sp<SurfaceControl>& layer,
                    ExpectedResult::Buffer bufferResult = NOT_ACQUIRED,
                    ExpectedResult::PreviousBuffer previousBufferResult = NOT_RELEASED) {
        mTransactionResult = transactionResult;
        mExpectedSurfaceResults.emplace(std::piecewise_construct,
                                        std::forward_as_tuple(layer->getHandle()),
                                        std::forward_as_tuple(bufferResult, previousBufferResult));
    }

    void addSurfaces(ExpectedResult::Transaction transactionResult,
                     const std::vector<sp<SurfaceControl>>& layers,
                     ExpectedResult::Buffer bufferResult = NOT_ACQUIRED,
                     ExpectedResult::PreviousBuffer previousBufferResult = NOT_RELEASED) {
        for (const auto& layer : layers) {
            addSurface(transactionResult, layer, bufferResult, previousBufferResult);
        }
    }

    void verifyTransactionStats(const TransactionStats& transactionStats) const {
        const auto& [latchTime, presentTime, surfaceStats] = transactionStats;
        if (mTransactionResult == ExpectedResult::Transaction::PRESENTED) {
            ASSERT_GE(latchTime, 0) << "bad latch time";
            ASSERT_GE(presentTime, 0) << "bad present time";
        } else {
            ASSERT_EQ(presentTime, -1) << "transaction shouldn't have been presented";
            ASSERT_EQ(latchTime, -1) << "unpresented transactions shouldn't be latched";
        }

        ASSERT_EQ(surfaceStats.size(), mExpectedSurfaceResults.size())
                << "wrong number of surfaces";

        for (const auto& stats : surfaceStats) {
            const auto& expectedSurfaceResult = mExpectedSurfaceResults.find(stats.surfaceControl);
            ASSERT_NE(expectedSurfaceResult, mExpectedSurfaceResults.end())
                    << "unexpected surface control";
            expectedSurfaceResult->second.verifySurfaceStats(stats, latchTime);
        }
    }

private:
    class ExpectedSurfaceResult {
    public:
        ExpectedSurfaceResult(ExpectedResult::Buffer bufferResult,
                              ExpectedResult::PreviousBuffer previousBufferResult)
              : mBufferResult(bufferResult), mPreviousBufferResult(previousBufferResult) {}

        void verifySurfaceStats(const SurfaceStats& surfaceStats, nsecs_t latchTime) const {
            const auto& [surfaceControl, acquireTime, releasePreviousBuffer] = surfaceStats;

            ASSERT_EQ(acquireTime > 0, mBufferResult == ExpectedResult::Buffer::ACQUIRED)
                    << "bad acquire time";
            ASSERT_LE(acquireTime, latchTime) << "acquire time should be <= latch time";
            ASSERT_EQ(releasePreviousBuffer,
                      mPreviousBufferResult == ExpectedResult::PreviousBuffer::RELEASED)
                    << "bad previous buffer released";
        }

    private:
        ExpectedResult::Buffer mBufferResult;
        ExpectedResult::PreviousBuffer mPreviousBufferResult;
    };

    struct IBinderHash {
        std::size_t operator()(const sp<IBinder>& strongPointer) const {
            return std::hash<IBinder*>{}(strongPointer.get());
        }
    };
    ExpectedResult::Transaction mTransactionResult = ExpectedResult::Transaction::NOT_PRESENTED;
    std::unordered_map<sp<IBinder>, ExpectedSurfaceResult, IBinderHash> mExpectedSurfaceResults;
};

class CallbackHelper {
public:
    static void function(void* callbackContext, const TransactionStats& transactionStats) {
        if (!callbackContext) {
            ALOGE("failed to get callback context");
        }
        CallbackHelper* helper = static_cast<CallbackHelper*>(callbackContext);
        std::lock_guard lock(helper->mMutex);
        helper->mTransactionStatsQueue.push(transactionStats);
        helper->mConditionVariable.notify_all();
    }

    void getTransactionStats(TransactionStats* outStats) {
        std::unique_lock lock(mMutex);

        if (mTransactionStatsQueue.empty()) {
            ASSERT_NE(mConditionVariable.wait_for(lock, std::chrono::seconds(3)),
                      std::cv_status::timeout)
                    << "did not receive callback";
        }

        *outStats = std::move(mTransactionStatsQueue.front());
        mTransactionStatsQueue.pop();
    }

    void verifyFinalState() {
        // Wait to see if there are extra callbacks
        std::this_thread::sleep_for(500ms);

        std::lock_guard lock(mMutex);
        EXPECT_EQ(mTransactionStatsQueue.size(), 0) << "extra callbacks received";
        mTransactionStatsQueue = {};
    }

    void* getContext() { return static_cast<void*>(this); }

    std::mutex mMutex;
    std::condition_variable mConditionVariable;
    std::queue<TransactionStats> mTransactionStatsQueue;
};

class LayerCallbackTest : public LayerTransactionTest {
protected:
    virtual sp<SurfaceControl> createBufferStateLayer() {
        return createLayer(mClient, "test", mWidth, mHeight,
                           ISurfaceComposerClient::eFXSurfaceBufferState);
    }

    virtual void fillTransaction(Transaction& transaction, CallbackHelper* callbackHelper,
                                 const sp<SurfaceControl>& layer = nullptr) {
        if (layer) {
            sp<GraphicBuffer> buffer =
                    new GraphicBuffer(mWidth, mHeight, PIXEL_FORMAT_RGBA_8888, 1,
                                      BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
                                              BufferUsage::COMPOSER_OVERLAY |
                                              BufferUsage::GPU_TEXTURE,
                                      "test");
            fillGraphicBufferColor(buffer, Rect(0, 0, mWidth, mHeight), Color::RED);

            sp<Fence> fence = new Fence(-1);

            transaction.setBuffer(layer, buffer)
                    .setAcquireFence(layer, fence)
                    .setSize(layer, mWidth, mHeight);
        }

        transaction.addTransactionCompletedCallback(callbackHelper->function,
                                                    callbackHelper->getContext());
    }

    void waitForCallback(CallbackHelper& helper, const ExpectedResult& expectedResult,
                         bool finalState = false) {
        TransactionStats transactionStats;
        ASSERT_NO_FATAL_FAILURE(helper.getTransactionStats(&transactionStats));
        EXPECT_NO_FATAL_FAILURE(expectedResult.verifyTransactionStats(transactionStats));

        if (finalState) {
            ASSERT_NO_FATAL_FAILURE(helper.verifyFinalState());
        }
    }

    void waitForCallbacks(CallbackHelper& helper,
                          const std::vector<ExpectedResult>& expectedResults,
                          bool finalState = false) {
        for (const auto& expectedResult : expectedResults) {
            waitForCallback(helper, expectedResult);
        }
        if (finalState) {
            ASSERT_NO_FATAL_FAILURE(helper.verifyFinalState());
        }
    }

    uint32_t mWidth = 32;
    uint32_t mHeight = 32;
};

TEST_F(LayerCallbackTest, Basic) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    fillTransaction(transaction, &callback, layer);

    transaction.apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, NoBuffer) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    fillTransaction(transaction, &callback);

    transaction.setPosition(layer, mWidth, mHeight).apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::NOT_PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, NoStateChange) {
    Transaction transaction;
    CallbackHelper callback;
    fillTransaction(transaction, &callback);

    transaction.apply();

    ExpectedResult expected;
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, OffScreen) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    fillTransaction(transaction, &callback, layer);

    transaction.setPosition(layer, -100, -100).apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, Merge) {
    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createBufferStateLayer());
    ASSERT_NO_FATAL_FAILURE(layer2 = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    fillTransaction(transaction1, &callback1, layer1);
    fillTransaction(transaction2, &callback2, layer2);

    transaction2.setPosition(layer2, mWidth, mHeight).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, Merge_SameCallback) {
    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createBufferStateLayer());
    ASSERT_NO_FATAL_FAILURE(layer2 = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback;
    fillTransaction(transaction1, &callback, layer1);
    fillTransaction(transaction2, &callback, layer2);

    transaction2.merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, true));
}

TEST_F(LayerCallbackTest, Merge_SameLayer) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    fillTransaction(transaction1, &callback1, layer);
    fillTransaction(transaction2, &callback2, layer);

    transaction2.merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, Merge_SingleBuffer) {
    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createBufferStateLayer());
    ASSERT_NO_FATAL_FAILURE(layer2 = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    fillTransaction(transaction1, &callback1, layer1);
    fillTransaction(transaction2, &callback2);

    transaction2.setPosition(layer2, mWidth, mHeight).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, Merge_DifferentClients) {
    sp<SurfaceComposerClient> client1(new SurfaceComposerClient),
            client2(new SurfaceComposerClient);

    ASSERT_EQ(NO_ERROR, client1->initCheck()) << "failed to create SurfaceComposerClient";
    ASSERT_EQ(NO_ERROR, client2->initCheck()) << "failed to create SurfaceComposerClient";

    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createLayer(client1, "test", mWidth, mHeight,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(layer2 = createLayer(client2, "test", mWidth, mHeight,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    fillTransaction(transaction1, &callback1, layer1);
    fillTransaction(transaction2, &callback2, layer2);

    transaction2.setPosition(layer2, mWidth, mHeight).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, MultipleTransactions) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    for (size_t i = 0; i < 10; i++) {
        fillTransaction(transaction, &callback, layer);

        transaction.apply();

        ExpectedResult expected;
        expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                            ExpectedResult::Buffer::NOT_ACQUIRED,
                            (i == 0) ? ExpectedResult::PreviousBuffer::NOT_RELEASED
                                     : ExpectedResult::PreviousBuffer::RELEASED);
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected));
    }
    ASSERT_NO_FATAL_FAILURE(callback.verifyFinalState());
}

TEST_F(LayerCallbackTest, MultipleTransactions_NoStateChange) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    for (size_t i = 0; i < 10; i++) {
        ExpectedResult expected;

        if (i == 0) {
            fillTransaction(transaction, &callback, layer);
            expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
        } else {
            fillTransaction(transaction, &callback);
        }

        transaction.apply();

        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected));
    }
    ASSERT_NO_FATAL_FAILURE(callback.verifyFinalState());
}

TEST_F(LayerCallbackTest, MultipleTransactions_SameStateChange) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    for (size_t i = 0; i < 10; i++) {
        if (i == 0) {
            fillTransaction(transaction, &callback, layer);
        } else {
            fillTransaction(transaction, &callback);
        }

        transaction.setPosition(layer, mWidth, mHeight).apply();

        ExpectedResult expected;
        expected.addSurface((i == 0) ? ExpectedResult::Transaction::PRESENTED
                                     : ExpectedResult::Transaction::NOT_PRESENTED,
                            layer);
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expected, i == 0));
    }
    ASSERT_NO_FATAL_FAILURE(callback.verifyFinalState());
}

TEST_F(LayerCallbackTest, MultipleTransactions_Merge) {
    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createBufferStateLayer());
    ASSERT_NO_FATAL_FAILURE(layer2 = createBufferStateLayer());

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    for (size_t i = 0; i < 10; i++) {
        fillTransaction(transaction1, &callback1, layer1);
        fillTransaction(transaction2, &callback2, layer2);

        transaction2.setPosition(layer2, mWidth, mHeight).merge(std::move(transaction1)).apply();

        ExpectedResult expected;
        expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2},
                             ExpectedResult::Buffer::NOT_ACQUIRED,
                             (i == 0) ? ExpectedResult::PreviousBuffer::NOT_RELEASED
                                      : ExpectedResult::PreviousBuffer::RELEASED);
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected));
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected));
    }
    ASSERT_NO_FATAL_FAILURE(callback1.verifyFinalState());
    ASSERT_NO_FATAL_FAILURE(callback2.verifyFinalState());
}

TEST_F(LayerCallbackTest, MultipleTransactions_Merge_DifferentClients) {
    sp<SurfaceComposerClient> client1(new SurfaceComposerClient),
            client2(new SurfaceComposerClient);
    ASSERT_EQ(NO_ERROR, client1->initCheck()) << "failed to create SurfaceComposerClient";
    ASSERT_EQ(NO_ERROR, client2->initCheck()) << "failed to create SurfaceComposerClient";

    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createLayer(client1, "test", mWidth, mHeight,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(layer2 = createLayer(client2, "test", mWidth, mHeight,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;
    for (size_t i = 0; i < 10; i++) {
        fillTransaction(transaction1, &callback1, layer1);
        fillTransaction(transaction2, &callback2, layer2);

        transaction2.setPosition(layer2, mWidth, mHeight).merge(std::move(transaction1)).apply();

        ExpectedResult expected;
        expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2},
                             ExpectedResult::Buffer::NOT_ACQUIRED,
                             (i == 0) ? ExpectedResult::PreviousBuffer::NOT_RELEASED
                                      : ExpectedResult::PreviousBuffer::RELEASED);
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected));
        EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected));
    }
    ASSERT_NO_FATAL_FAILURE(callback1.verifyFinalState());
    ASSERT_NO_FATAL_FAILURE(callback2.verifyFinalState());
}

TEST_F(LayerCallbackTest, MultipleTransactions_Merge_DifferentClients_NoStateChange) {
    sp<SurfaceComposerClient> client1(new SurfaceComposerClient),
            client2(new SurfaceComposerClient);
    ASSERT_EQ(NO_ERROR, client1->initCheck()) << "failed to create SurfaceComposerClient";
    ASSERT_EQ(NO_ERROR, client2->initCheck()) << "failed to create SurfaceComposerClient";

    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createLayer(client1, "test", mWidth, mHeight,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(layer2 = createLayer(client2, "test", mWidth, mHeight,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;

    // Normal call to set up test
    fillTransaction(transaction1, &callback1, layer1);
    fillTransaction(transaction2, &callback2, layer2);

    transaction2.setPosition(layer2, mWidth, mHeight).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
    expected.reset();

    // Test
    fillTransaction(transaction1, &callback1);
    fillTransaction(transaction2, &callback2);

    transaction2.merge(std::move(transaction1)).apply();

    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, MultipleTransactions_Merge_DifferentClients_SameStateChange) {
    sp<SurfaceComposerClient> client1(new SurfaceComposerClient),
            client2(new SurfaceComposerClient);

    ASSERT_EQ(NO_ERROR, client1->initCheck()) << "failed to create SurfaceComposerClient";
    ASSERT_EQ(NO_ERROR, client2->initCheck()) << "failed to create SurfaceComposerClient";

    sp<SurfaceControl> layer1, layer2;
    ASSERT_NO_FATAL_FAILURE(layer1 = createLayer(client1, "test", mWidth, mHeight,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));
    ASSERT_NO_FATAL_FAILURE(layer2 = createLayer(client2, "test", mWidth, mHeight,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState));

    Transaction transaction1, transaction2;
    CallbackHelper callback1, callback2;

    // Normal call to set up test
    fillTransaction(transaction1, &callback1, layer1);
    fillTransaction(transaction2, &callback2, layer2);

    transaction2.setPosition(layer2, mWidth, mHeight).merge(std::move(transaction1)).apply();

    ExpectedResult expected;
    expected.addSurfaces(ExpectedResult::Transaction::PRESENTED, {layer1, layer2});
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
    expected.reset();

    // Test
    fillTransaction(transaction1, &callback1);
    fillTransaction(transaction2, &callback2);

    transaction2.setPosition(layer2, mWidth, mHeight).merge(std::move(transaction1)).apply();

    expected.addSurface(ExpectedResult::Transaction::NOT_PRESENTED, layer2);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback1, expected, true));
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback2, expected, true));
}

TEST_F(LayerCallbackTest, MultipleTransactions_SingleFrame) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    std::vector<ExpectedResult> expectedResults(50);
    ExpectedResult::PreviousBuffer previousBufferResult =
            ExpectedResult::PreviousBuffer::NOT_RELEASED;
    for (auto& expected : expectedResults) {
        expected.reset();
        expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer,
                            ExpectedResult::Buffer::NOT_ACQUIRED, previousBufferResult);
        previousBufferResult = ExpectedResult::PreviousBuffer::RELEASED;

        fillTransaction(transaction, &callback, layer);

        transaction.apply();
        std::this_thread::sleep_for(200ms);
    }
    EXPECT_NO_FATAL_FAILURE(waitForCallbacks(callback, expectedResults, true));
}

TEST_F(LayerCallbackTest, MultipleTransactions_SingleFrame_NoStateChange) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    Transaction transaction;
    CallbackHelper callback;
    std::vector<ExpectedResult> expectedResults(50);
    bool first = true;
    for (auto& expected : expectedResults) {
        expected.reset();

        if (first) {
            fillTransaction(transaction, &callback, layer);
            expected.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
            first = false;
        } else {
            fillTransaction(transaction, &callback);
        }

        transaction.apply();
        std::this_thread::sleep_for(200ms);
    }
    EXPECT_NO_FATAL_FAILURE(waitForCallbacks(callback, expectedResults, true));
}

TEST_F(LayerCallbackTest, MultipleTransactions_SingleFrame_SameStateChange) {
    sp<SurfaceControl> layer;
    ASSERT_NO_FATAL_FAILURE(layer = createBufferStateLayer());

    // Normal call to set up test
    Transaction transaction;
    CallbackHelper callback;
    fillTransaction(transaction, &callback, layer);

    transaction.setPosition(layer, mWidth, mHeight).apply();

    ExpectedResult expectedResult;
    expectedResult.addSurface(ExpectedResult::Transaction::PRESENTED, layer);
    EXPECT_NO_FATAL_FAILURE(waitForCallback(callback, expectedResult, true));

    // Test
    std::vector<ExpectedResult> expectedResults(50);
    for (auto& expected : expectedResults) {
        expected.reset();
        expected.addSurface(ExpectedResult::Transaction::NOT_PRESENTED, layer);

        fillTransaction(transaction, &callback);

        transaction.setPosition(layer, mWidth, mHeight).apply();

        std::this_thread::sleep_for(200ms);
    }
    EXPECT_NO_FATAL_FAILURE(waitForCallbacks(callback, expectedResults, true));
}

class LayerUpdateTest : public LayerTransactionTest {
protected:
    virtual void SetUp() {
        LayerTransactionTest::SetUp();
        ASSERT_EQ(NO_ERROR, mClient->initCheck());

        sp<IBinder> display(
                SurfaceComposerClient::getBuiltInDisplay(ISurfaceComposer::eDisplayIdMain));
        DisplayInfo info;
        SurfaceComposerClient::getDisplayInfo(display, &info);

        ssize_t displayWidth = info.w;
        ssize_t displayHeight = info.h;

        // Background surface
        mBGSurfaceControl = createLayer(String8("BG Test Surface"), displayWidth,
                                               displayHeight, 0);
        ASSERT_TRUE(mBGSurfaceControl != nullptr);
        ASSERT_TRUE(mBGSurfaceControl->isValid());
        fillSurfaceRGBA8(mBGSurfaceControl, 63, 63, 195);

        // Foreground surface
        mFGSurfaceControl = createLayer(String8("FG Test Surface"), 64, 64, 0);

        ASSERT_TRUE(mFGSurfaceControl != nullptr);
        ASSERT_TRUE(mFGSurfaceControl->isValid());

        fillSurfaceRGBA8(mFGSurfaceControl, 195, 63, 63);

        // Synchronization surface
        mSyncSurfaceControl = createLayer(String8("Sync Test Surface"), 1, 1, 0);
        ASSERT_TRUE(mSyncSurfaceControl != nullptr);
        ASSERT_TRUE(mSyncSurfaceControl->isValid());

        fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);

        asTransaction([&](Transaction& t) {
            t.setDisplayLayerStack(display, 0);

            t.setLayer(mBGSurfaceControl, INT32_MAX - 2).show(mBGSurfaceControl);

            t.setLayer(mFGSurfaceControl, INT32_MAX - 1)
                    .setPosition(mFGSurfaceControl, 64, 64)
                    .show(mFGSurfaceControl);

            t.setLayer(mSyncSurfaceControl, INT32_MAX - 1)
                    .setPosition(mSyncSurfaceControl, displayWidth - 2, displayHeight - 2)
                    .show(mSyncSurfaceControl);
        });
    }

    virtual void TearDown() {
        LayerTransactionTest::TearDown();
        mBGSurfaceControl = 0;
        mFGSurfaceControl = 0;
        mSyncSurfaceControl = 0;
    }

    void waitForPostedBuffers() {
        // Since the sync surface is in synchronous mode (i.e. double buffered)
        // posting three buffers to it should ensure that at least two
        // SurfaceFlinger::handlePageFlip calls have been made, which should
        // guaranteed that a buffer posted to another Surface has been retired.
        fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);
        fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);
        fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);
    }

    void asTransaction(const std::function<void(Transaction&)>& exec) {
        Transaction t;
        exec(t);
        t.apply(true);
    }

    sp<SurfaceControl> mBGSurfaceControl;
    sp<SurfaceControl> mFGSurfaceControl;

    // This surface is used to ensure that the buffers posted to
    // mFGSurfaceControl have been picked up by SurfaceFlinger.
    sp<SurfaceControl> mSyncSurfaceControl;
};

TEST_F(LayerUpdateTest, RelativesAreNotDetached) {

    std::unique_ptr<ScreenCapture> sc;

    sp<SurfaceControl> relative = createLayer(String8("relativeTestSurface"), 10, 10, 0);
    fillSurfaceRGBA8(relative, 10, 10, 10);
    waitForPostedBuffers();

    Transaction{}
            .setRelativeLayer(relative, mFGSurfaceControl->getHandle(), 1)
            .setPosition(relative, 64, 64)
            .apply();

    {
        // The relative should be on top of the FG control.
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(64, 64, 10, 10, 10);
    }
    Transaction{}.detachChildren(mFGSurfaceControl).apply();

    {
        // Nothing should change at this point.
        ScreenCapture::captureScreen(&sc);
        sc->checkPixel(64, 64, 10, 10, 10);
    }

    Transaction{}.hide(relative).apply();

    {
        // Ensure that the relative was actually hidden, rather than
        // being left in the detached but visible state.
        ScreenCapture::captureScreen(&sc);
        sc->expectFGColor(64, 64);
    }
}

class GeometryLatchingTest : public LayerUpdateTest {
protected:
    void EXPECT_INITIAL_STATE(const char* trace) {
        SCOPED_TRACE(trace);
        ScreenCapture::captureScreen(&sc);
        // We find the leading edge of the FG surface.
        sc->expectFGColor(127, 127);
        sc->expectBGColor(128, 128);
    }

    void lockAndFillFGBuffer() { fillSurfaceRGBA8(mFGSurfaceControl, 195, 63, 63, false); }

    void unlockFGBuffer() {
        sp<Surface> s = mFGSurfaceControl->getSurface();
        ASSERT_EQ(NO_ERROR, s->unlockAndPost());
        waitForPostedBuffers();
    }

    void completeFGResize() {
        fillSurfaceRGBA8(mFGSurfaceControl, 195, 63, 63);
        waitForPostedBuffers();
    }
    void restoreInitialState() {
        asTransaction([&](Transaction& t) {
            t.setSize(mFGSurfaceControl, 64, 64);
            t.setPosition(mFGSurfaceControl, 64, 64);
            t.setCrop_legacy(mFGSurfaceControl, Rect(0, 0, 64, 64));
        });

        EXPECT_INITIAL_STATE("After restoring initial state");
    }
    std::unique_ptr<ScreenCapture> sc;
};

class CropLatchingTest : public GeometryLatchingTest {
protected:
    void EXPECT_CROPPED_STATE(const char* trace) {
        SCOPED_TRACE(trace);
        ScreenCapture::captureScreen(&sc);
        // The edge should be moved back one pixel by our crop.
        sc->expectFGColor(126, 126);
        sc->expectBGColor(127, 127);
        sc->expectBGColor(128, 128);
    }

    void EXPECT_RESIZE_STATE(const char* trace) {
        SCOPED_TRACE(trace);
        ScreenCapture::captureScreen(&sc);
        // The FG is now resized too 128,128 at 64,64
        sc->expectFGColor(64, 64);
        sc->expectFGColor(191, 191);
        sc->expectBGColor(192, 192);
    }
};

TEST_F(LayerUpdateTest, DeferredTransactionTest) {
    std::unique_ptr<ScreenCapture> sc;
    {
        SCOPED_TRACE("before anything");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(32, 32);
        sc->expectFGColor(96, 96);
        sc->expectBGColor(160, 160);
    }

    // set up two deferred transactions on different frames
    asTransaction([&](Transaction& t) {
        t.setAlpha(mFGSurfaceControl, 0.75);
        t.deferTransactionUntil_legacy(mFGSurfaceControl, mSyncSurfaceControl->getHandle(),
                                       mSyncSurfaceControl->getSurface()->getNextFrameNumber());
    });

    asTransaction([&](Transaction& t) {
        t.setPosition(mFGSurfaceControl, 128, 128);
        t.deferTransactionUntil_legacy(mFGSurfaceControl, mSyncSurfaceControl->getHandle(),
                                       mSyncSurfaceControl->getSurface()->getNextFrameNumber() + 1);
    });

    {
        SCOPED_TRACE("before any trigger");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(32, 32);
        sc->expectFGColor(96, 96);
        sc->expectBGColor(160, 160);
    }

    // should trigger the first deferred transaction, but not the second one
    fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);
    {
        SCOPED_TRACE("after first trigger");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(32, 32);
        sc->checkPixel(96, 96, 162, 63, 96);
        sc->expectBGColor(160, 160);
    }

    // should show up immediately since it's not deferred
    asTransaction([&](Transaction& t) { t.setAlpha(mFGSurfaceControl, 1.0); });

    // trigger the second deferred transaction
    fillSurfaceRGBA8(mSyncSurfaceControl, 31, 31, 31);
    {
        SCOPED_TRACE("after second trigger");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(32, 32);
        sc->expectBGColor(96, 96);
        sc->expectFGColor(160, 160);
    }
}

TEST_F(LayerUpdateTest, LayerWithNoBuffersResizesImmediately) {
    std::unique_ptr<ScreenCapture> sc;

    sp<SurfaceControl> childNoBuffer =
            mClient->createSurface(String8("Bufferless child"), 10, 10,
                                           PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    sp<SurfaceControl> childBuffer =
            mClient->createSurface(String8("Buffered child"), 20, 20,
                                           PIXEL_FORMAT_RGBA_8888, 0, childNoBuffer.get());
    fillSurfaceRGBA8(childBuffer, 200, 200, 200);
    SurfaceComposerClient::Transaction{}
            .setCrop_legacy(childNoBuffer, Rect(0, 0, 10, 10))
            .show(childNoBuffer)
            .show(childBuffer)
            .apply(true);
    {
        ScreenCapture::captureScreen(&sc);
        sc->expectChildColor(73, 73);
        sc->expectFGColor(74, 74);
    }
    SurfaceComposerClient::Transaction{}
            .setCrop_legacy(childNoBuffer, Rect(0, 0, 20, 20))
            .apply(true);
    {
        ScreenCapture::captureScreen(&sc);
        sc->expectChildColor(73, 73);
        sc->expectChildColor(74, 74);
    }
}

TEST_F(LayerUpdateTest, MergingTransactions) {
    std::unique_ptr<ScreenCapture> sc;
    {
        SCOPED_TRACE("before move");
        ScreenCapture::captureScreen(&sc);
        sc->expectBGColor(0, 12);
        sc->expectFGColor(75, 75);
        sc->expectBGColor(145, 145);
    }

    Transaction t1, t2;
    t1.setPosition(mFGSurfaceControl, 128, 128);
    t2.setPosition(mFGSurfaceControl, 0, 0);
    // We expect that the position update from t2 now
    // overwrites the position update from t1.
    t1.merge(std::move(t2));
    t1.apply();

    {
        ScreenCapture::captureScreen(&sc);
        sc->expectFGColor(1, 1);
    }
}

class ChildLayerTest : public LayerUpdateTest {
protected:
    void SetUp() override {
        LayerUpdateTest::SetUp();
        mChild = mClient->createSurface(String8("Child surface"), 10, 10,
                                                PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
        fillSurfaceRGBA8(mChild, 200, 200, 200);

        {
            SCOPED_TRACE("before anything");
            mCapture = screenshot();
            mCapture->expectChildColor(64, 64);
        }
    }
    void TearDown() override {
        LayerUpdateTest::TearDown();
        mChild = 0;
    }

    sp<SurfaceControl> mChild;
    std::unique_ptr<ScreenCapture> mCapture;
};

TEST_F(ChildLayerTest, ChildLayerPositioning) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        mCapture = screenshot();
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }

    asTransaction([&](Transaction& t) { t.setPosition(mFGSurfaceControl, 0, 0); });

    {
        mCapture = screenshot();
        // Top left of foreground should now be at 0, 0
        mCapture->expectFGColor(0, 0);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(10, 10);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(20, 20);
    }
}

TEST_F(ChildLayerTest, ChildLayerCropping) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 0, 0);
        t.setPosition(mFGSurfaceControl, 0, 0);
        t.setCrop_legacy(mFGSurfaceControl, Rect(0, 0, 5, 5));
    });

    {
        mCapture = screenshot();
        mCapture->expectChildColor(0, 0);
        mCapture->expectChildColor(4, 4);
        mCapture->expectBGColor(5, 5);
    }
}

TEST_F(ChildLayerTest, ChildLayerConstraints) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mFGSurfaceControl, 0, 0);
        t.setPosition(mChild, 63, 63);
    });

    {
        mCapture = screenshot();
        mCapture->expectFGColor(0, 0);
        // Last pixel in foreground should now be the child.
        mCapture->expectChildColor(63, 63);
        // But the child should be constrained and the next pixel
        // must be the background
        mCapture->expectBGColor(64, 64);
    }
}

TEST_F(ChildLayerTest, ChildLayerScaling) {
    asTransaction([&](Transaction& t) { t.setPosition(mFGSurfaceControl, 0, 0); });

    // Find the boundary between the parent and child
    {
        mCapture = screenshot();
        mCapture->expectChildColor(9, 9);
        mCapture->expectFGColor(10, 10);
    }

    asTransaction([&](Transaction& t) { t.setMatrix(mFGSurfaceControl, 2.0, 0, 0, 2.0); });

    // The boundary should be twice as far from the origin now.
    // The pixels from the last test should all be child now
    {
        mCapture = screenshot();
        mCapture->expectChildColor(9, 9);
        mCapture->expectChildColor(10, 10);
        mCapture->expectChildColor(19, 19);
        mCapture->expectFGColor(20, 20);
    }
}

TEST_F(ChildLayerTest, ChildLayerAlpha) {
    fillSurfaceRGBA8(mBGSurfaceControl, 0, 0, 254);
    fillSurfaceRGBA8(mFGSurfaceControl, 254, 0, 0);
    fillSurfaceRGBA8(mChild, 0, 254, 0);
    waitForPostedBuffers();

    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 0, 0);
        t.setPosition(mFGSurfaceControl, 0, 0);
    });

    {
        mCapture = screenshot();
        // Unblended child color
        mCapture->checkPixel(0, 0, 0, 254, 0);
    }

    asTransaction([&](Transaction& t) { t.setAlpha(mChild, 0.5); });

    {
        mCapture = screenshot();
        // Child and BG blended.
        mCapture->checkPixel(0, 0, 127, 127, 0);
    }

    asTransaction([&](Transaction& t) { t.setAlpha(mFGSurfaceControl, 0.5); });

    {
        mCapture = screenshot();
        // Child and BG blended.
        mCapture->checkPixel(0, 0, 95, 64, 95);
    }
}

TEST_F(ChildLayerTest, ReparentChildren) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        mCapture = screenshot();
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }

    asTransaction([&](Transaction& t) {
        t.reparentChildren(mFGSurfaceControl, mBGSurfaceControl->getHandle());
    });

    {
        mCapture = screenshot();
        mCapture->expectFGColor(64, 64);
        // In reparenting we should have exposed the entire foreground surface.
        mCapture->expectFGColor(74, 74);
        // And the child layer should now begin at 10, 10 (since the BG
        // layer is at (0, 0)).
        mCapture->expectBGColor(9, 9);
        mCapture->expectChildColor(10, 10);
    }
}

TEST_F(ChildLayerTest, ChildrenSurviveParentDestruction) {
    sp<SurfaceControl> mGrandChild =
        mClient->createSurface(String8("Grand Child"), 10, 10,
                PIXEL_FORMAT_RGBA_8888, 0, mChild.get());
    fillSurfaceRGBA8(mGrandChild, 111, 111, 111);

    {
        SCOPED_TRACE("Grandchild visible");
        ScreenCapture::captureScreen(&mCapture);
        mCapture->checkPixel(64, 64, 111, 111, 111);
    }

    mChild->clear();

    {
        SCOPED_TRACE("After destroying child");
        ScreenCapture::captureScreen(&mCapture);
        mCapture->expectFGColor(64, 64);
    }

    asTransaction([&](Transaction& t) {
         t.reparent(mGrandChild, mFGSurfaceControl->getHandle());
    });

    {
        SCOPED_TRACE("After reparenting grandchild");
        ScreenCapture::captureScreen(&mCapture);
        mCapture->checkPixel(64, 64, 111, 111, 111);
    }
}

TEST_F(ChildLayerTest, DetachChildrenSameClient) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        mCapture = screenshot();
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }


    asTransaction([&](Transaction& t) { t.detachChildren(mFGSurfaceControl); });

    asTransaction([&](Transaction& t) { t.hide(mChild); });

    // Since the child has the same client as the parent, it will not get
    // detached and will be hidden.
    {
        mCapture = screenshot();
        mCapture->expectFGColor(64, 64);
        mCapture->expectFGColor(74, 74);
        mCapture->expectFGColor(84, 84);
    }
}

TEST_F(ChildLayerTest, DetachChildrenDifferentClient) {
    sp<SurfaceComposerClient> mNewComposerClient = new SurfaceComposerClient;
    sp<SurfaceControl> mChildNewClient =
            mNewComposerClient->createSurface(String8("New Child Test Surface"), 10, 10,
                                              PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());

    ASSERT_TRUE(mChildNewClient != nullptr);
    ASSERT_TRUE(mChildNewClient->isValid());

    fillSurfaceRGBA8(mChildNewClient, 200, 200, 200);

    asTransaction([&](Transaction& t) {
        t.hide(mChild);
        t.show(mChildNewClient);
        t.setPosition(mChildNewClient, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        mCapture = screenshot();
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }

    asTransaction([&](Transaction& t) { t.detachChildren(mFGSurfaceControl); });

    asTransaction([&](Transaction& t) { t.hide(mChildNewClient); });

    // Nothing should have changed.
    {
        mCapture = screenshot();
        mCapture->expectFGColor(64, 64);
        mCapture->expectChildColor(74, 74);
        mCapture->expectFGColor(84, 84);
    }
}

TEST_F(ChildLayerTest, ChildrenInheritNonTransformScalingFromParent) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 0, 0);
        t.setPosition(mFGSurfaceControl, 0, 0);
    });

    {
        mCapture = screenshot();
        // We've positioned the child in the top left.
        mCapture->expectChildColor(0, 0);
        // But it's only 10x10.
        mCapture->expectFGColor(10, 10);
    }

    asTransaction([&](Transaction& t) {
        t.setOverrideScalingMode(mFGSurfaceControl, NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW);
        // We cause scaling by 2.
        t.setSize(mFGSurfaceControl, 128, 128);
    });

    {
        mCapture = screenshot();
        // We've positioned the child in the top left.
        mCapture->expectChildColor(0, 0);
        mCapture->expectChildColor(10, 10);
        mCapture->expectChildColor(19, 19);
        // And now it should be scaled all the way to 20x20
        mCapture->expectFGColor(20, 20);
    }
}

// Regression test for b/37673612
TEST_F(ChildLayerTest, ChildrenWithParentBufferTransform) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 0, 0);
        t.setPosition(mFGSurfaceControl, 0, 0);
    });

    {
        mCapture = screenshot();
        // We've positioned the child in the top left.
        mCapture->expectChildColor(0, 0);
        // But it's only 10x10.
        mCapture->expectFGColor(10, 10);
    }
    // We set things up as in b/37673612 so that there is a mismatch between the buffer size and
    // the WM specified state size.
    asTransaction([&](Transaction& t) { t.setSize(mFGSurfaceControl, 128, 64); });
    sp<Surface> s = mFGSurfaceControl->getSurface();
    auto anw = static_cast<ANativeWindow*>(s.get());
    native_window_set_buffers_transform(anw, NATIVE_WINDOW_TRANSFORM_ROT_90);
    native_window_set_buffers_dimensions(anw, 64, 128);
    fillSurfaceRGBA8(mFGSurfaceControl, 195, 63, 63);
    waitForPostedBuffers();

    {
        // The child should still be in the same place and not have any strange scaling as in
        // b/37673612.
        mCapture = screenshot();
        mCapture->expectChildColor(0, 0);
        mCapture->expectFGColor(10, 10);
    }
}

TEST_F(ChildLayerTest, Bug36858924) {
    // Destroy the child layer
    mChild.clear();

    // Now recreate it as hidden
    mChild = mClient->createSurface(String8("Child surface"), 10, 10,
                                            PIXEL_FORMAT_RGBA_8888, ISurfaceComposerClient::eHidden,
                                            mFGSurfaceControl.get());

    // Show the child layer in a deferred transaction
    asTransaction([&](Transaction& t) {
        t.deferTransactionUntil_legacy(mChild, mFGSurfaceControl->getHandle(),
                                       mFGSurfaceControl->getSurface()->getNextFrameNumber());
        t.show(mChild);
    });

    // Render the foreground surface a few times
    //
    // Prior to the bugfix for b/36858924, this would usually hang while trying to fill the third
    // frame because SurfaceFlinger would never process the deferred transaction and would therefore
    // never acquire/release the first buffer
    ALOGI("Filling 1");
    fillSurfaceRGBA8(mFGSurfaceControl, 0, 255, 0);
    ALOGI("Filling 2");
    fillSurfaceRGBA8(mFGSurfaceControl, 0, 0, 255);
    ALOGI("Filling 3");
    fillSurfaceRGBA8(mFGSurfaceControl, 255, 0, 0);
    ALOGI("Filling 4");
    fillSurfaceRGBA8(mFGSurfaceControl, 0, 255, 0);
}

TEST_F(ChildLayerTest, Reparent) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        mCapture = screenshot();
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }

    asTransaction([&](Transaction& t) { t.reparent(mChild, mBGSurfaceControl->getHandle()); });

    {
        mCapture = screenshot();
        mCapture->expectFGColor(64, 64);
        // In reparenting we should have exposed the entire foreground surface.
        mCapture->expectFGColor(74, 74);
        // And the child layer should now begin at 10, 10 (since the BG
        // layer is at (0, 0)).
        mCapture->expectBGColor(9, 9);
        mCapture->expectChildColor(10, 10);
    }
}

TEST_F(ChildLayerTest, ReparentToNoParent) {
    asTransaction([&](Transaction& t) {
        t.show(mChild);
        t.setPosition(mChild, 10, 10);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        mCapture = screenshot();
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // But 10 pixels in we should see the child surface
        mCapture->expectChildColor(74, 74);
        // And 10 more pixels we should be back to the foreground surface
        mCapture->expectFGColor(84, 84);
    }
    asTransaction([&](Transaction& t) { t.reparent(mChild, nullptr); });
    {
        mCapture = screenshot();
        // Nothing should have changed.
        mCapture->expectFGColor(64, 64);
        mCapture->expectChildColor(74, 74);
        mCapture->expectFGColor(84, 84);
    }
}

TEST_F(ChildLayerTest, ReparentFromNoParent) {
    sp<SurfaceControl> newSurface = createLayer(String8("New Surface"), 10, 10, 0);
    ASSERT_TRUE(newSurface != nullptr);
    ASSERT_TRUE(newSurface->isValid());

    fillSurfaceRGBA8(newSurface, 63, 195, 63);
    asTransaction([&](Transaction& t) {
        t.hide(mChild);
        t.show(newSurface);
        t.setPosition(newSurface, 10, 10);
        t.setLayer(newSurface, INT32_MAX - 2);
        t.setPosition(mFGSurfaceControl, 64, 64);
    });

    {
        mCapture = screenshot();
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // At 10, 10 we should see the new surface
        mCapture->checkPixel(10, 10, 63, 195, 63);
    }

    asTransaction([&](Transaction& t) { t.reparent(newSurface, mFGSurfaceControl->getHandle()); });

    {
        mCapture = screenshot();
        // newSurface will now be a child of mFGSurface so it will be 10, 10 offset from
        // mFGSurface, putting it at 74, 74.
        mCapture->expectFGColor(64, 64);
        mCapture->checkPixel(74, 74, 63, 195, 63);
        mCapture->expectFGColor(84, 84);
    }
}

TEST_F(ChildLayerTest, NestedChildren) {
    sp<SurfaceControl> grandchild =
            mClient->createSurface(String8("Grandchild surface"), 10, 10,
                                           PIXEL_FORMAT_RGBA_8888, 0, mChild.get());
    fillSurfaceRGBA8(grandchild, 50, 50, 50);

    {
        mCapture = screenshot();
        // Expect the grandchild to begin at 64, 64 because it's a child of mChild layer
        // which begins at 64, 64
        mCapture->checkPixel(64, 64, 50, 50, 50);
    }
}

TEST_F(ChildLayerTest, ChildLayerRelativeLayer) {
    sp<SurfaceControl> relative = createLayer(String8("Relative surface"), 128, 128, 0);
    fillSurfaceRGBA8(relative, 255, 255, 255);

    Transaction t;
    t.setLayer(relative, INT32_MAX)
            .setRelativeLayer(mChild, relative->getHandle(), 1)
            .setPosition(mFGSurfaceControl, 0, 0)
            .apply(true);

    // We expect that the child should have been elevated above our
    // INT_MAX layer even though it's not a child of it.
    {
        mCapture = screenshot();
        mCapture->expectChildColor(0, 0);
        mCapture->expectChildColor(9, 9);
        mCapture->checkPixel(10, 10, 255, 255, 255);
    }
}
class BoundlessLayerTest : public LayerUpdateTest {
protected:
    std::unique_ptr<ScreenCapture> mCapture;
};

// Verify setting a size on a buffer layer has no effect.
TEST_F(BoundlessLayerTest, BufferLayerIgnoresSize) {
    sp<SurfaceControl> bufferLayer =
            mClient->createSurface(String8("BufferLayer"), 45, 45, PIXEL_FORMAT_RGBA_8888, 0,
                                   mFGSurfaceControl.get());
    ASSERT_TRUE(bufferLayer != nullptr);
    ASSERT_TRUE(bufferLayer->isValid());
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(bufferLayer, Color::BLACK, 30, 30));
    asTransaction([&](Transaction& t) { t.show(bufferLayer); });
    {
        mCapture = screenshot();
        // Top left of background must now be visible
        mCapture->expectBGColor(0, 0);
        // Foreground Surface bounds must be color layer
        mCapture->expectColor(Rect(64, 64, 94, 94), Color::BLACK);
        // Buffer layer should not extend past buffer bounds
        mCapture->expectFGColor(95, 95);
    }
}

// Verify a boundless color layer will fill its parent bounds. The parent has a buffer size
// which will crop the color layer.
TEST_F(BoundlessLayerTest, BoundlessColorLayerFillsParentBufferBounds) {
    sp<SurfaceControl> colorLayer =
            mClient->createSurface(String8("ColorLayer"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceColor,
                                   mFGSurfaceControl.get());
    ASSERT_TRUE(colorLayer != nullptr);
    ASSERT_TRUE(colorLayer->isValid());
    asTransaction([&](Transaction& t) {
        t.setColor(colorLayer, half3{0, 0, 0});
        t.show(colorLayer);
    });
    {
        mCapture = screenshot();
        // Top left of background must now be visible
        mCapture->expectBGColor(0, 0);
        // Foreground Surface bounds must be color layer
        mCapture->expectColor(Rect(64, 64, 128, 128), Color::BLACK);
        // Color layer should not extend past foreground bounds
        mCapture->expectBGColor(129, 129);
    }
}

// Verify a boundless color layer will fill its parent bounds. The parent has no buffer but has
// a crop which will be used to crop the color layer.
TEST_F(BoundlessLayerTest, BoundlessColorLayerFillsParentCropBounds) {
    sp<SurfaceControl> cropLayer =
            mClient->createSurface(String8("CropLayer"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   0 /* flags */, mFGSurfaceControl.get());
    ASSERT_TRUE(cropLayer != nullptr);
    ASSERT_TRUE(cropLayer->isValid());
    sp<SurfaceControl> colorLayer =
            mClient->createSurface(String8("ColorLayer"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceColor, cropLayer.get());
    ASSERT_TRUE(colorLayer != nullptr);
    ASSERT_TRUE(colorLayer->isValid());
    asTransaction([&](Transaction& t) {
        t.setCrop_legacy(cropLayer, Rect(5, 5, 10, 10));
        t.setColor(colorLayer, half3{0, 0, 0});
        t.show(cropLayer);
        t.show(colorLayer);
    });
    {
        mCapture = screenshot();
        // Top left of background must now be visible
        mCapture->expectBGColor(0, 0);
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // 5 pixels from the foreground we should see the child surface
        mCapture->expectColor(Rect(69, 69, 74, 74), Color::BLACK);
        // 10 pixels from the foreground we should be back to the foreground surface
        mCapture->expectFGColor(74, 74);
    }
}

// Verify for boundless layer with no children, their transforms have no effect.
TEST_F(BoundlessLayerTest, BoundlessColorLayerTransformHasNoEffect) {
    sp<SurfaceControl> colorLayer =
            mClient->createSurface(String8("ColorLayer"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceColor,
                                   mFGSurfaceControl.get());
    ASSERT_TRUE(colorLayer != nullptr);
    ASSERT_TRUE(colorLayer->isValid());
    asTransaction([&](Transaction& t) {
        t.setPosition(colorLayer, 320, 320);
        t.setMatrix(colorLayer, 2, 0, 0, 2);
        t.setColor(colorLayer, half3{0, 0, 0});
        t.show(colorLayer);
    });
    {
        mCapture = screenshot();
        // Top left of background must now be visible
        mCapture->expectBGColor(0, 0);
        // Foreground Surface bounds must be color layer
        mCapture->expectColor(Rect(64, 64, 128, 128), Color::BLACK);
        // Color layer should not extend past foreground bounds
        mCapture->expectBGColor(129, 129);
    }
}

// Verify for boundless layer with children, their transforms have an effect.
TEST_F(BoundlessLayerTest, IntermediateBoundlessLayerCanSetTransform) {
    sp<SurfaceControl> boundlessLayerRightShift =
            mClient->createSurface(String8("BoundlessLayerRightShift"), 0, 0,
                                   PIXEL_FORMAT_RGBA_8888, 0 /* flags */, mFGSurfaceControl.get());
    ASSERT_TRUE(boundlessLayerRightShift != nullptr);
    ASSERT_TRUE(boundlessLayerRightShift->isValid());
    sp<SurfaceControl> boundlessLayerDownShift =
            mClient->createSurface(String8("BoundlessLayerLeftShift"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   0 /* flags */, boundlessLayerRightShift.get());
    ASSERT_TRUE(boundlessLayerDownShift != nullptr);
    ASSERT_TRUE(boundlessLayerDownShift->isValid());
    sp<SurfaceControl> colorLayer =
            mClient->createSurface(String8("ColorLayer"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceColor,
                                   boundlessLayerDownShift.get());
    ASSERT_TRUE(colorLayer != nullptr);
    ASSERT_TRUE(colorLayer->isValid());
    asTransaction([&](Transaction& t) {
        t.setPosition(boundlessLayerRightShift, 32, 0);
        t.show(boundlessLayerRightShift);
        t.setPosition(boundlessLayerDownShift, 0, 32);
        t.show(boundlessLayerDownShift);
        t.setCrop_legacy(colorLayer, Rect(0, 0, 64, 64));
        t.setColor(colorLayer, half3{0, 0, 0});
        t.show(colorLayer);
    });
    {
        mCapture = screenshot();
        // Top left of background must now be visible
        mCapture->expectBGColor(0, 0);
        // Top left of foreground must now be visible
        mCapture->expectFGColor(64, 64);
        // Foreground Surface bounds must be color layer
        mCapture->expectColor(Rect(96, 96, 128, 128), Color::BLACK);
        // Color layer should not extend past foreground bounds
        mCapture->expectBGColor(129, 129);
    }
}

// Verify child layers do not get clipped if they temporarily move into the negative
// coordinate space as the result of an intermediate transformation.
TEST_F(BoundlessLayerTest, IntermediateBoundlessLayerDoNotCrop) {
    sp<SurfaceControl> boundlessLayer =
            mClient->createSurface(String8("BoundlessLayer"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   0 /* flags */, mFGSurfaceControl.get());
    ASSERT_TRUE(boundlessLayer != nullptr);
    ASSERT_TRUE(boundlessLayer->isValid());
    sp<SurfaceControl> colorLayer =
            mClient->createSurface(String8("ColorLayer"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceColor, boundlessLayer.get());
    ASSERT_TRUE(colorLayer != nullptr);
    ASSERT_TRUE(colorLayer->isValid());
    asTransaction([&](Transaction& t) {
        // shift child layer off bounds. If this layer was not boundless, we will
        // expect the child layer to be cropped.
        t.setPosition(boundlessLayer, 32, 32);
        t.show(boundlessLayer);
        t.setCrop_legacy(colorLayer, Rect(0, 0, 64, 64));
        // undo shift by parent
        t.setPosition(colorLayer, -32, -32);
        t.setColor(colorLayer, half3{0, 0, 0});
        t.show(colorLayer);
    });
    {
        mCapture = screenshot();
        // Top left of background must now be visible
        mCapture->expectBGColor(0, 0);
        // Foreground Surface bounds must be color layer
        mCapture->expectColor(Rect(64, 64, 128, 128), Color::BLACK);
        // Color layer should not extend past foreground bounds
        mCapture->expectBGColor(129, 129);
    }
}

// Verify for boundless root layers with children, their transforms have an effect.
TEST_F(BoundlessLayerTest, RootBoundlessLayerCanSetTransform) {
    sp<SurfaceControl> rootBoundlessLayer =
            mClient->createSurface(String8("RootBoundlessLayer"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   0 /* flags */);
    ASSERT_TRUE(rootBoundlessLayer != nullptr);
    ASSERT_TRUE(rootBoundlessLayer->isValid());
    sp<SurfaceControl> colorLayer =
            mClient->createSurface(String8("ColorLayer"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                   ISurfaceComposerClient::eFXSurfaceColor,
                                   rootBoundlessLayer.get());
    ASSERT_TRUE(colorLayer != nullptr);
    ASSERT_TRUE(colorLayer->isValid());
    asTransaction([&](Transaction& t) {
        t.setLayer(rootBoundlessLayer, INT32_MAX - 1);
        t.setPosition(rootBoundlessLayer, 32, 32);
        t.show(rootBoundlessLayer);
        t.setCrop_legacy(colorLayer, Rect(0, 0, 64, 64));
        t.setColor(colorLayer, half3{0, 0, 0});
        t.show(colorLayer);
        t.hide(mFGSurfaceControl);
    });
    {
        mCapture = screenshot();
        // Top left of background must now be visible
        mCapture->expectBGColor(0, 0);
        // Top left of foreground must now be visible
        mCapture->expectBGColor(31, 31);
        // Foreground Surface bounds must be color layer
        mCapture->expectColor(Rect(32, 32, 96, 96), Color::BLACK);
        // Color layer should not extend past foreground bounds
        mCapture->expectBGColor(97, 97);
    }
}

class ScreenCaptureTest : public LayerUpdateTest {
protected:
    std::unique_ptr<ScreenCapture> mCapture;
};

TEST_F(ScreenCaptureTest, CaptureSingleLayer) {
    auto bgHandle = mBGSurfaceControl->getHandle();
    ScreenCapture::captureLayers(&mCapture, bgHandle);
    mCapture->expectBGColor(0, 0);
    // Doesn't capture FG layer which is at 64, 64
    mCapture->expectBGColor(64, 64);
}

TEST_F(ScreenCaptureTest, CaptureLayerWithChild) {
    auto fgHandle = mFGSurfaceControl->getHandle();

    sp<SurfaceControl> child =
            mClient->createSurface(String8("Child surface"), 10, 10, PIXEL_FORMAT_RGBA_8888,
                                           0, mFGSurfaceControl.get());
    fillSurfaceRGBA8(child, 200, 200, 200);

    SurfaceComposerClient::Transaction().show(child).apply(true);

    // Captures mFGSurfaceControl layer and its child.
    ScreenCapture::captureLayers(&mCapture, fgHandle);
    mCapture->expectFGColor(10, 10);
    mCapture->expectChildColor(0, 0);
}

TEST_F(ScreenCaptureTest, CaptureLayerChildOnly) {
    auto fgHandle = mFGSurfaceControl->getHandle();

    sp<SurfaceControl> child =
            mClient->createSurface(String8("Child surface"), 10, 10, PIXEL_FORMAT_RGBA_8888,
                                           0, mFGSurfaceControl.get());
    fillSurfaceRGBA8(child, 200, 200, 200);

    SurfaceComposerClient::Transaction().show(child).apply(true);

    // Captures mFGSurfaceControl's child
    ScreenCapture::captureChildLayers(&mCapture, fgHandle);
    mCapture->checkPixel(10, 10, 0, 0, 0);
    mCapture->expectChildColor(0, 0);
}

TEST_F(ScreenCaptureTest, CaptureTransparent) {
    sp<SurfaceControl> child =
            mClient->createSurface(String8("Child surface"), 10, 10, PIXEL_FORMAT_RGBA_8888,
                                           0, mFGSurfaceControl.get());

    fillSurfaceRGBA8(child, 200, 200, 200);

    SurfaceComposerClient::Transaction().show(child).apply(true);

    auto childHandle = child->getHandle();

    // Captures child
    ScreenCapture::captureLayers(&mCapture, childHandle, {0, 0, 10, 20});
    mCapture->expectColor(Rect(0, 0, 9, 9), {200, 200, 200, 255});
    // Area outside of child's bounds is transparent.
    mCapture->expectColor(Rect(0, 10, 9, 19), {0, 0, 0, 0});
}

TEST_F(ScreenCaptureTest, DontCaptureRelativeOutsideTree) {
    auto fgHandle = mFGSurfaceControl->getHandle();

    sp<SurfaceControl> child =
            mClient->createSurface(String8("Child surface"), 10, 10, PIXEL_FORMAT_RGBA_8888,
                                           0, mFGSurfaceControl.get());
    sp<SurfaceControl> relative = createLayer(String8("Relative surface"), 10, 10, 0);
    fillSurfaceRGBA8(child, 200, 200, 200);
    fillSurfaceRGBA8(relative, 100, 100, 100);

    SurfaceComposerClient::Transaction()
            .show(child)
            // Set relative layer above fg layer so should be shown above when computing all layers.
            .setRelativeLayer(relative, fgHandle, 1)
            .show(relative)
            .apply(true);

    // Captures mFGSurfaceControl layer and its child. Relative layer shouldn't be captured.
    ScreenCapture::captureLayers(&mCapture, fgHandle);
    mCapture->expectFGColor(10, 10);
    mCapture->expectChildColor(0, 0);
}

TEST_F(ScreenCaptureTest, CaptureRelativeInTree) {
    auto fgHandle = mFGSurfaceControl->getHandle();

    sp<SurfaceControl> child =
            mClient->createSurface(String8("Child surface"), 10, 10, PIXEL_FORMAT_RGBA_8888,
                                           0, mFGSurfaceControl.get());
    sp<SurfaceControl> relative =
            mClient->createSurface(String8("Relative surface"), 10, 10,
                                           PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
    fillSurfaceRGBA8(child, 200, 200, 200);
    fillSurfaceRGBA8(relative, 100, 100, 100);

    SurfaceComposerClient::Transaction()
            .show(child)
            // Set relative layer below fg layer but relative to child layer so it should be shown
            // above child layer.
            .setLayer(relative, -1)
            .setRelativeLayer(relative, child->getHandle(), 1)
            .show(relative)
            .apply(true);

    // Captures mFGSurfaceControl layer and its children. Relative layer is a child of fg so its
    // relative value should be taken into account, placing it above child layer.
    ScreenCapture::captureLayers(&mCapture, fgHandle);
    mCapture->expectFGColor(10, 10);
    // Relative layer is showing on top of child layer
    mCapture->expectColor(Rect(0, 0, 9, 9), {100, 100, 100, 255});
}

// In the following tests we verify successful skipping of a parent layer,
// so we use the same verification logic and only change how we mutate
// the parent layer to verify that various properties are ignored.
class ScreenCaptureChildOnlyTest : public LayerUpdateTest {
public:
    void SetUp() override {
        LayerUpdateTest::SetUp();

        mChild =
            mClient->createSurface(String8("Child surface"), 10, 10, PIXEL_FORMAT_RGBA_8888,
                    0, mFGSurfaceControl.get());
        fillSurfaceRGBA8(mChild, 200, 200, 200);

        SurfaceComposerClient::Transaction().show(mChild).apply(true);
    }

    void verify() {
        auto fgHandle = mFGSurfaceControl->getHandle();
        ScreenCapture::captureChildLayers(&mCapture, fgHandle);
        mCapture->checkPixel(10, 10, 0, 0, 0);
        mCapture->expectChildColor(0, 0);
    }

    std::unique_ptr<ScreenCapture> mCapture;
    sp<SurfaceControl> mChild;
};

TEST_F(ScreenCaptureChildOnlyTest, CaptureLayerIgnoresParentVisibility) {

    SurfaceComposerClient::Transaction().hide(mFGSurfaceControl).apply(true);

    // Even though the parent is hidden we should still capture the child.
    verify();
}

TEST_F(ScreenCaptureChildOnlyTest, CaptureLayerIgnoresParentCrop) {
    SurfaceComposerClient::Transaction()
            .setCrop_legacy(mFGSurfaceControl, Rect(0, 0, 1, 1))
            .apply(true);

    // Even though the parent is cropped out we should still capture the child.
    verify();
}

TEST_F(ScreenCaptureChildOnlyTest, CaptureLayerIgnoresTransform) {

    SurfaceComposerClient::Transaction().setMatrix(mFGSurfaceControl, 2, 0, 0, 2);

    // We should not inherit the parent scaling.
    verify();
}

TEST_F(ScreenCaptureChildOnlyTest, RegressionTest76099859) {
    SurfaceComposerClient::Transaction().hide(mFGSurfaceControl).apply(true);

    // Even though the parent is hidden we should still capture the child.
    verify();

    // Verify everything was properly hidden when rendering the full-screen.
    screenshot()->expectBGColor(0,0);
}


TEST_F(ScreenCaptureTest, CaptureLayerWithGrandchild) {
    auto fgHandle = mFGSurfaceControl->getHandle();

    sp<SurfaceControl> child =
            mClient->createSurface(String8("Child surface"), 10, 10, PIXEL_FORMAT_RGBA_8888,
                                           0, mFGSurfaceControl.get());
    fillSurfaceRGBA8(child, 200, 200, 200);

    sp<SurfaceControl> grandchild =
            mClient->createSurface(String8("Grandchild surface"), 5, 5,
                                           PIXEL_FORMAT_RGBA_8888, 0, child.get());

    fillSurfaceRGBA8(grandchild, 50, 50, 50);
    SurfaceComposerClient::Transaction()
            .show(child)
            .setPosition(grandchild, 5, 5)
            .show(grandchild)
            .apply(true);

    // Captures mFGSurfaceControl, its child, and the grandchild.
    ScreenCapture::captureLayers(&mCapture, fgHandle);
    mCapture->expectFGColor(10, 10);
    mCapture->expectChildColor(0, 0);
    mCapture->checkPixel(5, 5, 50, 50, 50);
}

TEST_F(ScreenCaptureTest, CaptureChildOnly) {
    sp<SurfaceControl> child =
            mClient->createSurface(String8("Child surface"), 10, 10, PIXEL_FORMAT_RGBA_8888,
                                           0, mFGSurfaceControl.get());
    fillSurfaceRGBA8(child, 200, 200, 200);
    auto childHandle = child->getHandle();

    SurfaceComposerClient::Transaction().setPosition(child, 5, 5).show(child).apply(true);

    // Captures only the child layer, and not the parent.
    ScreenCapture::captureLayers(&mCapture, childHandle);
    mCapture->expectChildColor(0, 0);
    mCapture->expectChildColor(9, 9);
}

TEST_F(ScreenCaptureTest, CaptureGrandchildOnly) {
    sp<SurfaceControl> child =
            mClient->createSurface(String8("Child surface"), 10, 10, PIXEL_FORMAT_RGBA_8888,
                                           0, mFGSurfaceControl.get());
    fillSurfaceRGBA8(child, 200, 200, 200);
    auto childHandle = child->getHandle();

    sp<SurfaceControl> grandchild =
            mClient->createSurface(String8("Grandchild surface"), 5, 5,
                                           PIXEL_FORMAT_RGBA_8888, 0, child.get());
    fillSurfaceRGBA8(grandchild, 50, 50, 50);

    SurfaceComposerClient::Transaction()
            .show(child)
            .setPosition(grandchild, 5, 5)
            .show(grandchild)
            .apply(true);

    auto grandchildHandle = grandchild->getHandle();

    // Captures only the grandchild.
    ScreenCapture::captureLayers(&mCapture, grandchildHandle);
    mCapture->checkPixel(0, 0, 50, 50, 50);
    mCapture->checkPixel(4, 4, 50, 50, 50);
}

TEST_F(ScreenCaptureTest, CaptureCrop) {
    sp<SurfaceControl> redLayer = createLayer(String8("Red surface"), 60, 60, 0);
    sp<SurfaceControl> blueLayer =
            mClient->createSurface(String8("Blue surface"), 30, 30, PIXEL_FORMAT_RGBA_8888,
                                           0, redLayer.get());

    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(redLayer, Color::RED, 60, 60));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(blueLayer, Color::BLUE, 30, 30));

    SurfaceComposerClient::Transaction()
            .setLayer(redLayer, INT32_MAX - 1)
            .show(redLayer)
            .show(blueLayer)
            .apply(true);

    auto redLayerHandle = redLayer->getHandle();

    // Capturing full screen should have both red and blue are visible.
    ScreenCapture::captureLayers(&mCapture, redLayerHandle);
    mCapture->expectColor(Rect(0, 0, 29, 29), Color::BLUE);
    // red area below the blue area
    mCapture->expectColor(Rect(0, 30, 59, 59), Color::RED);
    // red area to the right of the blue area
    mCapture->expectColor(Rect(30, 0, 59, 59), Color::RED);

    Rect crop = Rect(0, 0, 30, 30);
    ScreenCapture::captureLayers(&mCapture, redLayerHandle, crop);
    // Capturing the cropped screen, cropping out the shown red area, should leave only the blue
    // area visible.
    mCapture->expectColor(Rect(0, 0, 29, 29), Color::BLUE);
    mCapture->checkPixel(30, 30, 0, 0, 0);
}

TEST_F(ScreenCaptureTest, CaptureSize) {
    sp<SurfaceControl> redLayer = createLayer(String8("Red surface"), 60, 60, 0);
    sp<SurfaceControl> blueLayer =
            mClient->createSurface(String8("Blue surface"), 30, 30, PIXEL_FORMAT_RGBA_8888,
                                           0, redLayer.get());

    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(redLayer, Color::RED, 60, 60));
    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(blueLayer, Color::BLUE, 30, 30));

    SurfaceComposerClient::Transaction()
            .setLayer(redLayer, INT32_MAX - 1)
            .show(redLayer)
            .show(blueLayer)
            .apply(true);

    auto redLayerHandle = redLayer->getHandle();

    // Capturing full screen should have both red and blue are visible.
    ScreenCapture::captureLayers(&mCapture, redLayerHandle);
    mCapture->expectColor(Rect(0, 0, 29, 29), Color::BLUE);
    // red area below the blue area
    mCapture->expectColor(Rect(0, 30, 59, 59), Color::RED);
    // red area to the right of the blue area
    mCapture->expectColor(Rect(30, 0, 59, 59), Color::RED);

    ScreenCapture::captureLayers(&mCapture, redLayerHandle, Rect::EMPTY_RECT, 0.5);
    // Capturing the downsized area (30x30) should leave both red and blue but in a smaller area.
    mCapture->expectColor(Rect(0, 0, 14, 14), Color::BLUE);
    // red area below the blue area
    mCapture->expectColor(Rect(0, 15, 29, 29), Color::RED);
    // red area to the right of the blue area
    mCapture->expectColor(Rect(15, 0, 29, 29), Color::RED);
    mCapture->checkPixel(30, 30, 0, 0, 0);
}

TEST_F(ScreenCaptureTest, CaptureInvalidLayer) {
    sp<SurfaceControl> redLayer = createLayer(String8("Red surface"), 60, 60, 0);

    ASSERT_NO_FATAL_FAILURE(fillBufferQueueLayerColor(redLayer, Color::RED, 60, 60));

    auto redLayerHandle = redLayer->getHandle();
    mClient->destroySurface(redLayerHandle);
    SurfaceComposerClient::Transaction().apply(true);

    sp<GraphicBuffer> outBuffer;

    // Layer was deleted so captureLayers should fail with NAME_NOT_FOUND
    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    ASSERT_EQ(NAME_NOT_FOUND, sf->captureLayers(redLayerHandle, &outBuffer, Rect::EMPTY_RECT, 1.0));
}


class DereferenceSurfaceControlTest : public LayerTransactionTest {
protected:
    void SetUp() override {
        LayerTransactionTest::SetUp();
        bgLayer = createLayer("BG layer", 20, 20);
        fillBufferQueueLayerColor(bgLayer, Color::RED, 20, 20);
        fgLayer = createLayer("FG layer", 20, 20);
        fillBufferQueueLayerColor(fgLayer, Color::BLUE, 20, 20);
        Transaction().setLayer(fgLayer, mLayerZBase + 1).apply();
        {
            SCOPED_TRACE("before anything");
            auto shot = screenshot();
            shot->expectColor(Rect(0, 0, 20, 20), Color::BLUE);
        }
    }
    void TearDown() override {
        LayerTransactionTest::TearDown();
        bgLayer = 0;
        fgLayer = 0;
    }

    sp<SurfaceControl> bgLayer;
    sp<SurfaceControl> fgLayer;
};

TEST_F(DereferenceSurfaceControlTest, LayerNotInTransaction) {
    fgLayer = nullptr;
    {
        SCOPED_TRACE("after setting null");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 20, 20), Color::RED);
    }
}

TEST_F(DereferenceSurfaceControlTest, LayerInTransaction) {
    auto transaction = Transaction().show(fgLayer);
    fgLayer = nullptr;
    {
        SCOPED_TRACE("after setting null");
        auto shot = screenshot();
        shot->expectColor(Rect(0, 0, 20, 20), Color::BLUE);
    }
}

} // namespace android
