/*
 * Copyright 2019 The Android Open Source Project
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

#include <cstdarg>
#include <cstdint>

#include <compositionengine/RenderSurfaceCreationArgs.h>
#include <compositionengine/impl/RenderSurface.h>
#include <compositionengine/mock/CompositionEngine.h>
#include <compositionengine/mock/Display.h>
#include <compositionengine/mock/DisplaySurface.h>
#include <compositionengine/mock/OutputLayer.h>
#include <gtest/gtest.h>
#include <renderengine/mock/RenderEngine.h>
#include <system/window.h>
#include <ui/ANativeObjectBase.h>

#include "MockHWComposer.h"

namespace android::compositionengine {
namespace {

/* ------------------------------------------------------------------------
 * MockNativeWindow
 *
 * An intentionally simplified Mock which implements a minimal subset of the full
 * ANativeWindow interface.
 */

class MockNativeWindow : public ANativeObjectBase<ANativeWindow, MockNativeWindow, RefBase> {
public:
    MockNativeWindow() {
        ANativeWindow::setSwapInterval = &forwardSetSwapInterval;
        ANativeWindow::dequeueBuffer = &forwardDequeueBuffer;
        ANativeWindow::cancelBuffer = &forwardCancelBuffer;
        ANativeWindow::queueBuffer = &forwardQueueBuffer;
        ANativeWindow::query = &forwardQuery;
        ANativeWindow::perform = &forwardPerform;

        ANativeWindow::dequeueBuffer_DEPRECATED = &forwardDequeueBufferDeprecated;
        ANativeWindow::cancelBuffer_DEPRECATED = &forwardCancelBufferDeprecated;
        ANativeWindow::lockBuffer_DEPRECATED = &forwardLockBufferDeprecated;
        ANativeWindow::queueBuffer_DEPRECATED = &forwardQueueBufferDeprecated;
    }

    MOCK_METHOD1(setSwapInterval, int(int));
    MOCK_METHOD2(dequeueBuffer, int(struct ANativeWindowBuffer**, int*));
    MOCK_METHOD2(cancelBuffer, int(struct ANativeWindowBuffer*, int));
    MOCK_METHOD2(queueBuffer, int(struct ANativeWindowBuffer*, int));
    MOCK_CONST_METHOD2(query, int(int, int*));
    MOCK_METHOD1(connect, int(int));
    MOCK_METHOD1(lockBuffer_DEPRECATED, int(struct ANativeWindowBuffer*));
    MOCK_METHOD1(setBuffersFormat, int(PixelFormat));
    MOCK_METHOD1(setBuffersDataSpace, int(ui::Dataspace));
    MOCK_METHOD1(setUsage, int(uint64_t));

    static void unexpectedCall(...) { LOG_ALWAYS_FATAL("Unexpected ANativeWindow API call"); }

    static int forwardSetSwapInterval(ANativeWindow* window, int interval) {
        return getSelf(window)->setSwapInterval(interval);
    }

    static int forwardDequeueBuffer(ANativeWindow* window, ANativeWindowBuffer** buffer,
                                    int* fenceFd) {
        return getSelf(window)->dequeueBuffer(buffer, fenceFd);
    }

    static int forwardCancelBuffer(ANativeWindow* window, ANativeWindowBuffer* buffer,
                                   int fenceFd) {
        return getSelf(window)->cancelBuffer(buffer, fenceFd);
    }

    static int forwardQueueBuffer(ANativeWindow* window, ANativeWindowBuffer* buffer, int fenceFd) {
        return getSelf(window)->queueBuffer(buffer, fenceFd);
    }

    static int forwardQuery(const ANativeWindow* window, int what, int* value) {
        return getSelf(window)->query(what, value);
    }

    static int forwardPerform(ANativeWindow* window, int operation, ...) {
        va_list args;
        va_start(args, operation);
        int result = NO_ERROR;
        switch (operation) {
            case NATIVE_WINDOW_API_CONNECT: {
                int api = va_arg(args, int);
                result = getSelf(window)->connect(api);
                break;
            }
            case NATIVE_WINDOW_SET_BUFFERS_FORMAT: {
                PixelFormat format = va_arg(args, PixelFormat);
                result = getSelf(window)->setBuffersFormat(format);
                break;
            }
            case NATIVE_WINDOW_SET_BUFFERS_DATASPACE: {
                ui::Dataspace dataspace = static_cast<ui::Dataspace>(va_arg(args, int));
                result = getSelf(window)->setBuffersDataSpace(dataspace);
                break;
            }
            case NATIVE_WINDOW_SET_USAGE: {
                // Note: Intentionally widens usage from 32 to 64 bits so we
                // just have one implementation.
                uint64_t usage = va_arg(args, uint32_t);
                result = getSelf(window)->setUsage(usage);
                break;
            }
            case NATIVE_WINDOW_SET_USAGE64: {
                uint64_t usage = va_arg(args, uint64_t);
                result = getSelf(window)->setUsage(usage);
                break;
            }
            default:
                LOG_ALWAYS_FATAL("Unexpected operation %d", operation);
                break;
        }

        va_end(args);
        return result;
    }

    static int forwardDequeueBufferDeprecated(ANativeWindow* window, ANativeWindowBuffer** buffer) {
        int ignoredFenceFd = -1;
        return getSelf(window)->dequeueBuffer(buffer, &ignoredFenceFd);
    }

    static int forwardCancelBufferDeprecated(ANativeWindow* window, ANativeWindowBuffer* buffer) {
        return getSelf(window)->cancelBuffer(buffer, -1);
    }

    static int forwardLockBufferDeprecated(ANativeWindow* window, ANativeWindowBuffer* buffer) {
        return getSelf(window)->lockBuffer_DEPRECATED(buffer);
    }

    static int forwardQueueBufferDeprecated(ANativeWindow* window, ANativeWindowBuffer* buffer) {
        return getSelf(window)->queueBuffer(buffer, -1);
    }
};

/* ------------------------------------------------------------------------
 * RenderSurfaceTest
 */

constexpr int32_t DEFAULT_DISPLAY_WIDTH = 1920;
constexpr int32_t DEFAULT_DISPLAY_HEIGHT = 1080;
constexpr std::optional<DisplayId> DEFAULT_DISPLAY_ID = std::make_optional(DisplayId{123u});
const std::string DEFAULT_DISPLAY_NAME = "Mock Display";

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Ref;
using testing::Return;
using testing::ReturnRef;
using testing::SetArgPointee;
using testing::StrictMock;

class RenderSurfaceTest : public testing::Test {
public:
    RenderSurfaceTest() {
        EXPECT_CALL(mDisplay, getId()).WillRepeatedly(ReturnRef(DEFAULT_DISPLAY_ID));
        EXPECT_CALL(mDisplay, getName()).WillRepeatedly(ReturnRef(DEFAULT_DISPLAY_NAME));
        EXPECT_CALL(mCompositionEngine, getHwComposer).WillRepeatedly(ReturnRef(mHwComposer));
        EXPECT_CALL(mCompositionEngine, getRenderEngine).WillRepeatedly(ReturnRef(mRenderEngine));
    }
    ~RenderSurfaceTest() override = default;

    StrictMock<android::mock::HWComposer> mHwComposer;
    StrictMock<renderengine::mock::RenderEngine> mRenderEngine;
    StrictMock<mock::CompositionEngine> mCompositionEngine;
    StrictMock<mock::Display> mDisplay;
    sp<MockNativeWindow> mNativeWindow = new StrictMock<MockNativeWindow>();
    sp<mock::DisplaySurface> mDisplaySurface = new StrictMock<mock::DisplaySurface>();
    impl::RenderSurface mSurface{mCompositionEngine, mDisplay,
                                 RenderSurfaceCreationArgs{DEFAULT_DISPLAY_WIDTH,
                                                           DEFAULT_DISPLAY_HEIGHT, mNativeWindow,
                                                           mDisplaySurface}};
};

/* ------------------------------------------------------------------------
 * Basic construction
 */

TEST_F(RenderSurfaceTest, canInstantiate) {
    EXPECT_TRUE(mSurface.isValid());
}

/* ------------------------------------------------------------------------
 * RenderSurface::initialize()
 */

TEST_F(RenderSurfaceTest, initializeConfiguresNativeWindow) {
    EXPECT_CALL(*mNativeWindow, connect(NATIVE_WINDOW_API_EGL)).WillOnce(Return(NO_ERROR));
    EXPECT_CALL(*mNativeWindow, setBuffersFormat(HAL_PIXEL_FORMAT_RGBA_8888))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(*mNativeWindow, setUsage(GRALLOC_USAGE_HW_RENDER)).WillOnce(Return(NO_ERROR));

    mSurface.initialize();
}

/* ------------------------------------------------------------------------
 * RenderSurface::getSize()
 */

TEST_F(RenderSurfaceTest, sizeReturnsConstructedSize) {
    const ui::Size expected{DEFAULT_DISPLAY_WIDTH, DEFAULT_DISPLAY_HEIGHT};

    EXPECT_EQ(expected, mSurface.getSize());
}

/* ------------------------------------------------------------------------
 * RenderSurface::getClientTargetAcquireFence()
 */

TEST_F(RenderSurfaceTest, getClientTargetAcquireFenceForwardsCall) {
    sp<Fence> fence = new Fence();

    EXPECT_CALL(*mDisplaySurface, getClientTargetAcquireFence()).WillOnce(ReturnRef(fence));

    EXPECT_EQ(fence.get(), mSurface.getClientTargetAcquireFence().get());
}

/* ------------------------------------------------------------------------
 * RenderSurface::setDisplaySize()
 */

TEST_F(RenderSurfaceTest, setDisplaySizeAppliesChange) {
    EXPECT_CALL(*mDisplaySurface, resizeBuffers(640, 480)).Times(1);

    mSurface.setDisplaySize(ui::Size(640, 480));
}

/* ------------------------------------------------------------------------
 * RenderSurface::setBufferDataspace()
 */

TEST_F(RenderSurfaceTest, setBufferDataspaceAppliesChange) {
    EXPECT_CALL(*mNativeWindow, setBuffersDataSpace(ui::Dataspace::DISPLAY_P3))
            .WillOnce(Return(NO_ERROR));

    mSurface.setBufferDataspace(ui::Dataspace::DISPLAY_P3);
}

/* ------------------------------------------------------------------------
 * RenderSurface::setProtected()
 */

TEST_F(RenderSurfaceTest, setProtectedTrueEnablesProtection) {
    EXPECT_CALL(*mNativeWindow, setUsage(GRALLOC_USAGE_HW_RENDER | GRALLOC_USAGE_PROTECTED))
            .WillOnce(Return(NO_ERROR));

    mSurface.setProtected(true);
}

TEST_F(RenderSurfaceTest, setProtectedFalseDisablesProtection) {
    EXPECT_CALL(*mNativeWindow, setUsage(GRALLOC_USAGE_HW_RENDER)).WillOnce(Return(NO_ERROR));

    mSurface.setProtected(false);
}

/* ------------------------------------------------------------------------
 * RenderSurface::beginFrame()
 */

TEST_F(RenderSurfaceTest, beginFrameAppliesChange) {
    EXPECT_CALL(*mDisplaySurface, beginFrame(true)).WillOnce(Return(NO_ERROR));

    EXPECT_EQ(NO_ERROR, mSurface.beginFrame(true));
}

/* ------------------------------------------------------------------------
 * RenderSurface::prepareFrame()
 */

TEST_F(RenderSurfaceTest, prepareFramePassesOutputLayersToHwc) {
    EXPECT_CALL(mHwComposer, prepare(*DEFAULT_DISPLAY_ID, Ref(mDisplay)))
            .WillOnce(Return(INVALID_OPERATION));

    EXPECT_EQ(INVALID_OPERATION, mSurface.prepareFrame());
}

TEST_F(RenderSurfaceTest, prepareFrameTakesEarlyOutOnHwcError) {
    EXPECT_CALL(mHwComposer, prepare(*DEFAULT_DISPLAY_ID, Ref(mDisplay)))
            .WillOnce(Return(INVALID_OPERATION));

    EXPECT_EQ(INVALID_OPERATION, mSurface.prepareFrame());
}

TEST_F(RenderSurfaceTest, prepareFrameHandlesMixedComposition) {
    EXPECT_CALL(mHwComposer, prepare(*DEFAULT_DISPLAY_ID, Ref(mDisplay)))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(mHwComposer, hasClientComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(true));
    EXPECT_CALL(mHwComposer, hasDeviceComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(true));

    EXPECT_CALL(*mDisplaySurface, prepareFrame(DisplaySurface::COMPOSITION_MIXED))
            .WillOnce(Return(INVALID_OPERATION));

    EXPECT_EQ(INVALID_OPERATION, mSurface.prepareFrame());
}

TEST_F(RenderSurfaceTest, prepareFrameHandlesOnlyGlesComposition) {
    EXPECT_CALL(mHwComposer, prepare(*DEFAULT_DISPLAY_ID, Ref(mDisplay)))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(mHwComposer, hasClientComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(true));
    EXPECT_CALL(mHwComposer, hasDeviceComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(false));

    EXPECT_CALL(*mDisplaySurface, prepareFrame(DisplaySurface::COMPOSITION_GLES))
            .WillOnce(Return(NO_ERROR));

    EXPECT_EQ(NO_ERROR, mSurface.prepareFrame());
}

TEST_F(RenderSurfaceTest, prepareFrameHandlesOnlyHwcComposition) {
    EXPECT_CALL(mHwComposer, prepare(*DEFAULT_DISPLAY_ID, Ref(mDisplay)))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(mHwComposer, hasClientComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(false));
    EXPECT_CALL(mHwComposer, hasDeviceComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(true));

    EXPECT_CALL(*mDisplaySurface, prepareFrame(DisplaySurface::COMPOSITION_HWC))
            .WillOnce(Return(NO_ERROR));

    EXPECT_EQ(NO_ERROR, mSurface.prepareFrame());
}

TEST_F(RenderSurfaceTest, prepareFrameHandlesNoComposition) {
    EXPECT_CALL(mHwComposer, prepare(*DEFAULT_DISPLAY_ID, Ref(mDisplay)))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(mHwComposer, hasClientComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(false));
    EXPECT_CALL(mHwComposer, hasDeviceComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(false));

    EXPECT_CALL(*mDisplaySurface, prepareFrame(DisplaySurface::COMPOSITION_HWC))
            .WillOnce(Return(NO_ERROR));

    EXPECT_EQ(NO_ERROR, mSurface.prepareFrame());
}

/* ------------------------------------------------------------------------
 * RenderSurface::dequeueBuffer()
 */

TEST_F(RenderSurfaceTest, dequeueBufferObtainsABuffer) {
    sp<GraphicBuffer> buffer = new GraphicBuffer();

    EXPECT_CALL(*mNativeWindow, dequeueBuffer(_, _))
            .WillOnce(
                    DoAll(SetArgPointee<0>(buffer.get()), SetArgPointee<1>(-1), Return(NO_ERROR)));

    base::unique_fd fence;
    EXPECT_EQ(buffer.get(), mSurface.dequeueBuffer(&fence).get());

    EXPECT_EQ(buffer.get(), mSurface.mutableGraphicBufferForTest().get());
}

/* ------------------------------------------------------------------------
 * RenderSurface::queueBuffer()
 */

TEST_F(RenderSurfaceTest, queueBufferHandlesNoClientComposition) {
    sp<GraphicBuffer> buffer = new GraphicBuffer();
    mSurface.mutableGraphicBufferForTest() = buffer;

    EXPECT_CALL(mHwComposer, hasClientComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(false));
    EXPECT_CALL(mHwComposer, hasFlipClientTargetRequest(DEFAULT_DISPLAY_ID))
            .WillOnce(Return(false));
    EXPECT_CALL(*mDisplaySurface, advanceFrame()).Times(1);

    mSurface.queueBuffer(base::unique_fd());

    EXPECT_EQ(buffer.get(), mSurface.mutableGraphicBufferForTest().get());
}

TEST_F(RenderSurfaceTest, queueBufferHandlesClientComposition) {
    sp<GraphicBuffer> buffer = new GraphicBuffer();
    mSurface.mutableGraphicBufferForTest() = buffer;

    EXPECT_CALL(mHwComposer, hasClientComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(true));
    EXPECT_CALL(*mNativeWindow, queueBuffer(buffer->getNativeBuffer(), -1))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(*mDisplaySurface, advanceFrame()).Times(1);

    mSurface.queueBuffer(base::unique_fd());

    EXPECT_EQ(nullptr, mSurface.mutableGraphicBufferForTest().get());
}

TEST_F(RenderSurfaceTest, queueBufferHandlesFlipClientTargetRequest) {
    sp<GraphicBuffer> buffer = new GraphicBuffer();
    mSurface.mutableGraphicBufferForTest() = buffer;

    EXPECT_CALL(mHwComposer, hasClientComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(false));
    EXPECT_CALL(mHwComposer, hasFlipClientTargetRequest(DEFAULT_DISPLAY_ID)).WillOnce(Return(true));
    EXPECT_CALL(*mNativeWindow, queueBuffer(buffer->getNativeBuffer(), -1))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(*mDisplaySurface, advanceFrame()).Times(1);

    mSurface.queueBuffer(base::unique_fd());

    EXPECT_EQ(nullptr, mSurface.mutableGraphicBufferForTest().get());
}

TEST_F(RenderSurfaceTest, queueBufferHandlesFlipClientTargetRequestWithNoBufferYetDequeued) {
    sp<GraphicBuffer> buffer = new GraphicBuffer();

    EXPECT_CALL(mHwComposer, hasClientComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(false));
    EXPECT_CALL(mHwComposer, hasFlipClientTargetRequest(DEFAULT_DISPLAY_ID)).WillOnce(Return(true));
    EXPECT_CALL(*mNativeWindow, dequeueBuffer(_, _))
            .WillOnce(
                    DoAll(SetArgPointee<0>(buffer.get()), SetArgPointee<1>(-1), Return(NO_ERROR)));
    EXPECT_CALL(*mNativeWindow, queueBuffer(buffer->getNativeBuffer(), -1))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(*mDisplaySurface, advanceFrame()).Times(1);

    mSurface.queueBuffer(base::unique_fd());

    EXPECT_EQ(nullptr, mSurface.mutableGraphicBufferForTest().get());
}

TEST_F(RenderSurfaceTest, queueBufferHandlesNativeWindowQueueBufferFailureOnVirtualDisplay) {
    sp<GraphicBuffer> buffer = new GraphicBuffer();
    mSurface.mutableGraphicBufferForTest() = buffer;

    EXPECT_CALL(mHwComposer, hasClientComposition(DEFAULT_DISPLAY_ID)).WillOnce(Return(true));
    EXPECT_CALL(*mNativeWindow, queueBuffer(buffer->getNativeBuffer(), -1))
            .WillOnce(Return(INVALID_OPERATION));
    EXPECT_CALL(mDisplay, isVirtual()).WillOnce(Return(true));
    EXPECT_CALL(*mNativeWindow, cancelBuffer(buffer->getNativeBuffer(), -1))
            .WillOnce(Return(NO_ERROR));
    EXPECT_CALL(*mDisplaySurface, advanceFrame()).Times(1);

    mSurface.queueBuffer(base::unique_fd());

    EXPECT_EQ(nullptr, mSurface.mutableGraphicBufferForTest().get());
}

/* ------------------------------------------------------------------------
 * RenderSurface::onPresentDisplayCompleted()
 */

TEST_F(RenderSurfaceTest, onPresentDisplayCompletedForwardsSignal) {
    EXPECT_CALL(*mDisplaySurface, onFrameCommitted()).Times(1);

    mSurface.onPresentDisplayCompleted();
}

/* ------------------------------------------------------------------------
 * RenderSurface::setViewportAndProjection()
 */

TEST_F(RenderSurfaceTest, setViewportAndProjectionAppliesChang) {
    mSurface.setSizeForTest(ui::Size(100, 200));

    EXPECT_CALL(mRenderEngine,
                setViewportAndProjection(100, 200, Rect(100, 200), ui::Transform::ROT_0))
            .Times(1);

    mSurface.setViewportAndProjection();
}

/* ------------------------------------------------------------------------
 * RenderSurface::flip()
 */

TEST_F(RenderSurfaceTest, flipForwardsSignal) {
    mSurface.setPageFlipCountForTest(500);

    mSurface.flip();

    EXPECT_EQ(501, mSurface.getPageFlipCount());
}

} // namespace
} // namespace android::compositionengine
