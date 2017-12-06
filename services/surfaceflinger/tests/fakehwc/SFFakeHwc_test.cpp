/*
 * Copyright (C) 2017 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "FakeHwcTest"

#include "FakeComposerClient.h"
#include "FakeComposerService.h"
#include "FakeComposerUtils.h"

#include <gui/ISurfaceComposer.h>
#include <gui/LayerDebugInfo.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>

#include <private/gui/ComposerService.h>
#include <private/gui/LayerState.h>

#include <ui/DisplayInfo.h>

#include <android/native_window.h>

#include <android/hidl/manager/1.0/IServiceManager.h>

#include <hwbinder/ProcessState.h>

#include <binder/ProcessState.h>

#include <log/log.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <limits>

using namespace std::chrono_literals;

using namespace android;
using namespace android::hardware;

using namespace sftest;

namespace {

// Mock test helpers
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::_;

///////////////////////////////////////////////

struct TestColor {
public:
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
};

constexpr static TestColor RED = {195, 63, 63, 255};
constexpr static TestColor LIGHT_RED = {255, 177, 177, 255};
constexpr static TestColor GREEN = {63, 195, 63, 255};
constexpr static TestColor BLUE = {63, 63, 195, 255};
constexpr static TestColor DARK_GRAY = {63, 63, 63, 255};
constexpr static TestColor LIGHT_GRAY = {200, 200, 200, 255};

// Fill an RGBA_8888 formatted surface with a single color.
static void fillSurfaceRGBA8(const sp<SurfaceControl>& sc, const TestColor& color,
                             bool unlock = true) {
    ANativeWindow_Buffer outBuffer;
    sp<Surface> s = sc->getSurface();
    ASSERT_TRUE(s != nullptr);
    ASSERT_EQ(NO_ERROR, s->lock(&outBuffer, nullptr));
    uint8_t* img = reinterpret_cast<uint8_t*>(outBuffer.bits);
    for (int y = 0; y < outBuffer.height; y++) {
        for (int x = 0; x < outBuffer.width; x++) {
            uint8_t* pixel = img + (4 * (y * outBuffer.stride + x));
            pixel[0] = color.r;
            pixel[1] = color.g;
            pixel[2] = color.b;
            pixel[3] = color.a;
        }
    }
    if (unlock) {
        ASSERT_EQ(NO_ERROR, s->unlockAndPost());
    }
}

inline RenderState makeSimpleRect(int left, int top, int right, int bottom) {
    RenderState res;
    res.mDisplayFrame = hwc_rect_t{left, top, right, bottom};
    res.mPlaneAlpha = 1.0f;
    res.mSwapCount = 0;
    res.mSourceCrop = hwc_frect_t{0.f, 0.f, static_cast<float>(right - left),
                                  static_cast<float>(bottom - top)};
    return res;
}

inline RenderState makeSimpleRect(unsigned int left, unsigned int top, unsigned int right,
                                  unsigned int bottom) {
    EXPECT_LE(left, static_cast<unsigned int>(INT_MAX));
    EXPECT_LE(top, static_cast<unsigned int>(INT_MAX));
    EXPECT_LE(right, static_cast<unsigned int>(INT_MAX));
    EXPECT_LE(bottom, static_cast<unsigned int>(INT_MAX));
    return makeSimpleRect(static_cast<int>(left), static_cast<int>(top), static_cast<int>(right),
                          static_cast<int>(bottom));
}

////////////////////////////////////////////////

class DisplayTest : public ::testing::Test {
public:
    class MockComposerClient : public FakeComposerClient {
    public:
        MOCK_METHOD2(getDisplayType, Error(Display display, ComposerClient::DisplayType* outType));
        MOCK_METHOD4(getDisplayAttribute,
                     Error(Display display, Config config, IComposerClient::Attribute attribute,
                           int32_t* outValue));

        // Re-routing to basic fake implementation
        Error getDisplayAttributeFake(Display display, Config config,
                                      IComposerClient::Attribute attribute, int32_t* outValue) {
            return FakeComposerClient::getDisplayAttribute(display, config, attribute, outValue);
        }
    };

protected:
    void SetUp() override;
    void TearDown() override;

    sp<IComposer> mFakeService;
    sp<SurfaceComposerClient> mComposerClient;

    MockComposerClient* mMockComposer;
};

void DisplayTest::SetUp() {
    // TODO: The mMockComposer should be a unique_ptr, but it needs to
    // outlive the test class.  Currently ComposerClient only dies
    // when the service is replaced. The Mock deletes itself when
    // removeClient is called on it, which is ugly.  This can be
    // changed if HIDL ServiceManager allows removing services or
    // ComposerClient starts taking the ownership of the contained
    // implementation class. Moving the fake class to the HWC2
    // interface instead of the current Composer interface might also
    // change the situation.
    mMockComposer = new MockComposerClient;
    sp<ComposerClient> client = new ComposerClient(*mMockComposer);
    mMockComposer->setClient(client.get());
    mFakeService = new FakeComposerService(client);
    (void)mFakeService->registerAsService("mock");

    android::hardware::ProcessState::self()->startThreadPool();
    android::ProcessState::self()->startThreadPool();

    EXPECT_CALL(*mMockComposer, getDisplayType(1, _))
            .WillOnce(DoAll(SetArgPointee<1>(IComposerClient::DisplayType::PHYSICAL),
                            Return(Error::NONE)));
    // Seems to be doubled right now, once for display ID 1 and once for 0. This sounds fishy
    // but encoding that here exactly.
    EXPECT_CALL(*mMockComposer, getDisplayAttribute(1, 1, _, _))
            .Times(5)
            .WillRepeatedly(Invoke(mMockComposer, &MockComposerClient::getDisplayAttributeFake));
    // TODO: Find out what code is generating the ID 0.
    EXPECT_CALL(*mMockComposer, getDisplayAttribute(0, 1, _, _))
            .Times(5)
            .WillRepeatedly(Invoke(mMockComposer, &MockComposerClient::getDisplayAttributeFake));

    startSurfaceFlinger();

    // Fake composer wants to enable VSync injection
    mMockComposer->onSurfaceFlingerStart();

    mComposerClient = new SurfaceComposerClient;
    ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());
}

void DisplayTest::TearDown() {
    mComposerClient->dispose();
    mComposerClient = nullptr;

    // Fake composer needs to release SurfaceComposerClient before the stop.
    mMockComposer->onSurfaceFlingerStop();
    stopSurfaceFlinger();

    mFakeService = nullptr;
    // TODO: Currently deleted in FakeComposerClient::removeClient(). Devise better lifetime
    // management.
    mMockComposer = nullptr;
}

TEST_F(DisplayTest, Hotplug) {
    ALOGD("DisplayTest::Hotplug");

    EXPECT_CALL(*mMockComposer, getDisplayType(2, _))
            .Times(2)
            .WillRepeatedly(DoAll(SetArgPointee<1>(IComposerClient::DisplayType::PHYSICAL),
                                  Return(Error::NONE)));
    // The attribute queries will get done twice. This is for defaults
    EXPECT_CALL(*mMockComposer, getDisplayAttribute(2, 1, _, _))
            .Times(2 * 3)
            .WillRepeatedly(Invoke(mMockComposer, &MockComposerClient::getDisplayAttributeFake));
    // ... and then special handling for dimensions. Specifying this
    // rules later means that gmock will try them first, i.e.,
    // ordering of width/height vs. the default implementation for
    // other queries is significant.
    EXPECT_CALL(*mMockComposer, getDisplayAttribute(2, 1, IComposerClient::Attribute::WIDTH, _))
            .Times(2)
            .WillRepeatedly(DoAll(SetArgPointee<3>(400), Return(Error::NONE)));

    EXPECT_CALL(*mMockComposer, getDisplayAttribute(2, 1, IComposerClient::Attribute::HEIGHT, _))
            .Times(2)
            .WillRepeatedly(DoAll(SetArgPointee<3>(200), Return(Error::NONE)));

    // TODO: Width and height queries are not actually called. Display
    // info returns dimensions 0x0 in display info. Why?

    mMockComposer->hotplugDisplay(static_cast<Display>(2),
                                  IComposerCallback::Connection::CONNECTED);

    {
        sp<android::IBinder> display(
                SurfaceComposerClient::getBuiltInDisplay(ISurfaceComposer::eDisplayIdHdmi));
        DisplayInfo info;
        SurfaceComposerClient::getDisplayInfo(display, &info);
        ASSERT_EQ(400u, info.w);
        ASSERT_EQ(200u, info.h);

        auto surfaceControl =
                mComposerClient->createSurface(String8("Display Test Surface Foo"), info.w, info.h,
                                               PIXEL_FORMAT_RGBA_8888, 0);
        ASSERT_TRUE(surfaceControl != nullptr);
        ASSERT_TRUE(surfaceControl->isValid());
        fillSurfaceRGBA8(surfaceControl, BLUE);

        {
            GlobalTransactionScope gts(*mMockComposer);
            mComposerClient->setDisplayLayerStack(display, 0);

            ASSERT_EQ(NO_ERROR, surfaceControl->setLayer(INT32_MAX - 2));
            ASSERT_EQ(NO_ERROR, surfaceControl->show());
        }
    }

    mMockComposer->hotplugDisplay(static_cast<Display>(2),
                                  IComposerCallback::Connection::DISCONNECTED);

    mMockComposer->clearFrames();

    mMockComposer->hotplugDisplay(static_cast<Display>(2),
                                  IComposerCallback::Connection::CONNECTED);

    {
        sp<android::IBinder> display(
                SurfaceComposerClient::getBuiltInDisplay(ISurfaceComposer::eDisplayIdHdmi));
        DisplayInfo info;
        SurfaceComposerClient::getDisplayInfo(display, &info);
        ASSERT_EQ(400u, info.w);
        ASSERT_EQ(200u, info.h);

        auto surfaceControl =
                mComposerClient->createSurface(String8("Display Test Surface Bar"), info.w, info.h,
                                               PIXEL_FORMAT_RGBA_8888, 0);
        ASSERT_TRUE(surfaceControl != nullptr);
        ASSERT_TRUE(surfaceControl->isValid());
        fillSurfaceRGBA8(surfaceControl, BLUE);

        {
            GlobalTransactionScope gts(*mMockComposer);
            mComposerClient->setDisplayLayerStack(display, 0);

            ASSERT_EQ(NO_ERROR, surfaceControl->setLayer(INT32_MAX - 2));
            ASSERT_EQ(NO_ERROR, surfaceControl->show());
        }
    }
    mMockComposer->hotplugDisplay(static_cast<Display>(2),
                                  IComposerCallback::Connection::DISCONNECTED);
}

////////////////////////////////////////////////

class TransactionTest : public ::testing::Test {
protected:
    // Layer array indexing constants.
    constexpr static int BG_LAYER = 0;
    constexpr static int FG_LAYER = 1;

    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;

    sp<SurfaceComposerClient> mComposerClient;
    sp<SurfaceControl> mBGSurfaceControl;
    sp<SurfaceControl> mFGSurfaceControl;
    std::vector<RenderState> mBaseFrame;
    uint32_t mDisplayWidth;
    uint32_t mDisplayHeight;

    static FakeComposerClient* sFakeComposer;
};

FakeComposerClient* TransactionTest::sFakeComposer;

void TransactionTest::SetUpTestCase() {
    // TODO: See TODO comment at DisplayTest::SetUp for background on
    // the lifetime of the FakeComposerClient.
    sFakeComposer = new FakeComposerClient;
    sp<ComposerClient> client = new ComposerClient(*sFakeComposer);
    sFakeComposer->setClient(client.get());
    sp<IComposer> fakeService = new FakeComposerService(client);
    (void)fakeService->registerAsService("mock");

    android::hardware::ProcessState::self()->startThreadPool();
    android::ProcessState::self()->startThreadPool();

    startSurfaceFlinger();

    // Fake composer wants to enable VSync injection
    sFakeComposer->onSurfaceFlingerStart();
}

void TransactionTest::TearDownTestCase() {
    // Fake composer needs to release SurfaceComposerClient before the stop.
    sFakeComposer->onSurfaceFlingerStop();
    stopSurfaceFlinger();
    // TODO: This is deleted when the ComposerClient calls
    // removeClient. Devise better lifetime control.
    sFakeComposer = nullptr;
}

void TransactionTest::SetUp() {
    ALOGI("TransactionTest::SetUp");
    mComposerClient = new SurfaceComposerClient;
    ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());

    ALOGI("TransactionTest::SetUp - display");
    sp<android::IBinder> display(
            SurfaceComposerClient::getBuiltInDisplay(ISurfaceComposer::eDisplayIdMain));
    DisplayInfo info;
    SurfaceComposerClient::getDisplayInfo(display, &info);

    mDisplayWidth = info.w;
    mDisplayHeight = info.h;

    // Background surface
    mBGSurfaceControl = mComposerClient->createSurface(String8("BG Test Surface"), mDisplayWidth,
                                                       mDisplayHeight, PIXEL_FORMAT_RGBA_8888, 0);
    ASSERT_TRUE(mBGSurfaceControl != nullptr);
    ASSERT_TRUE(mBGSurfaceControl->isValid());
    fillSurfaceRGBA8(mBGSurfaceControl, BLUE);

    // Foreground surface
    mFGSurfaceControl = mComposerClient->createSurface(String8("FG Test Surface"), 64, 64,
                                                       PIXEL_FORMAT_RGBA_8888, 0);
    ASSERT_TRUE(mFGSurfaceControl != nullptr);
    ASSERT_TRUE(mFGSurfaceControl->isValid());

    fillSurfaceRGBA8(mFGSurfaceControl, RED);

    SurfaceComposerClient::openGlobalTransaction();

    mComposerClient->setDisplayLayerStack(display, 0);

    ASSERT_EQ(NO_ERROR, mBGSurfaceControl->setLayer(INT32_MAX - 2));
    ASSERT_EQ(NO_ERROR, mBGSurfaceControl->show());

    ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setLayer(INT32_MAX - 1));
    ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setPosition(64, 64));
    ASSERT_EQ(NO_ERROR, mFGSurfaceControl->show());

    // Synchronous transaction will stop this thread, so we set up a
    // delayed, off-thread vsync request before closing the
    // transaction. In the test code this is usually done with
    // GlobalTransactionScope. Leaving here in the 'vanilla' form for
    // reference.
    ASSERT_EQ(0, sFakeComposer->getFrameCount());
    sFakeComposer->runVSyncAfter(1ms);
    SurfaceComposerClient::closeGlobalTransaction(true);
    sFakeComposer->waitUntilFrame(1);

    // Reference data. This is what the HWC should see.
    static_assert(BG_LAYER == 0 && FG_LAYER == 1, "Unexpected enum values for array indexing");
    mBaseFrame.push_back(makeSimpleRect(0u, 0u, mDisplayWidth, mDisplayHeight));
    mBaseFrame[BG_LAYER].mSwapCount = 1;
    mBaseFrame.push_back(makeSimpleRect(64, 64, 64 + 64, 64 + 64));
    mBaseFrame[FG_LAYER].mSwapCount = 1;

    auto frame = sFakeComposer->getFrameRects(0);
    ASSERT_TRUE(framesAreSame(mBaseFrame, frame));
}

void TransactionTest::TearDown() {
    ALOGD("TransactionTest::TearDown");

    mComposerClient->dispose();
    mBGSurfaceControl = 0;
    mFGSurfaceControl = 0;
    mComposerClient = 0;

    sFakeComposer->runVSyncAndWait();
    mBaseFrame.clear();
    sFakeComposer->clearFrames();
    ASSERT_EQ(0, sFakeComposer->getFrameCount());

    sp<ISurfaceComposer> sf(ComposerService::getComposerService());
    std::vector<LayerDebugInfo> layers;
    status_t result = sf->getLayerDebugInfo(&layers);
    if (result != NO_ERROR) {
        ALOGE("Failed to get layers %s %d", strerror(-result), result);
    } else {
        // If this fails, the test being torn down leaked layers.
        EXPECT_EQ(0u, layers.size());
        if (layers.size() > 0) {
            for (auto layer = layers.begin(); layer != layers.end(); ++layer) {
                std::cout << to_string(*layer).c_str();
            }
            // To ensure the next test has clean slate, will run the class
            // tear down and setup here.
            TearDownTestCase();
            SetUpTestCase();
        }
    }
    ALOGD("TransactionTest::TearDown - complete");
}

TEST_F(TransactionTest, LayerMove) {
    ALOGD("TransactionTest::LayerMove");

    // The scope opens and closes a global transaction and, at the
    // same time, makes sure the SurfaceFlinger progresses one frame
    // after the transaction closes. The results of the transaction
    // should be available in the latest frame stored by the fake
    // composer.
    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setPosition(128, 128));
        // NOTE: No changes yet, so vsync will do nothing, HWC does not get any calls.
        // (How to verify that? Throw in vsync and wait a 2x frame time? Separate test?)
        //
        // sFakeComposer->runVSyncAndWait();
    }

    fillSurfaceRGBA8(mFGSurfaceControl, GREEN);
    sFakeComposer->runVSyncAndWait();

    ASSERT_EQ(3, sFakeComposer->getFrameCount()); // Make sure the waits didn't time out and there's
                                                  // no extra frames.

    // NOTE: Frame 0 is produced in the SetUp.
    auto frame1Ref = mBaseFrame;
    frame1Ref[FG_LAYER].mDisplayFrame =
            hwc_rect_t{128, 128, 128 + 64, 128 + 64}; // Top-most layer moves.
    EXPECT_TRUE(framesAreSame(frame1Ref, sFakeComposer->getFrameRects(1)));

    auto frame2Ref = frame1Ref;
    frame2Ref[FG_LAYER].mSwapCount++;
    EXPECT_TRUE(framesAreSame(frame2Ref, sFakeComposer->getFrameRects(2)));
}

TEST_F(TransactionTest, LayerResize) {
    ALOGD("TransactionTest::LayerResize");
    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setSize(128, 128));
    }

    fillSurfaceRGBA8(mFGSurfaceControl, GREEN);
    sFakeComposer->runVSyncAndWait();

    ASSERT_EQ(3, sFakeComposer->getFrameCount()); // Make sure the waits didn't time out and there's
                                                  // no extra frames.

    auto frame1Ref = mBaseFrame;
    // NOTE: The resize should not be visible for frame 1 as there's no buffer with new size posted.
    EXPECT_TRUE(framesAreSame(frame1Ref, sFakeComposer->getFrameRects(1)));

    auto frame2Ref = frame1Ref;
    frame2Ref[FG_LAYER].mSwapCount++;
    frame2Ref[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 128, 64 + 128};
    frame2Ref[FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 128.f, 128.f};
    EXPECT_TRUE(framesAreSame(frame2Ref, sFakeComposer->getFrameRects(2)));
}

TEST_F(TransactionTest, LayerCrop) {
    // TODO: Add scaling to confirm that crop happens in buffer space?
    {
        GlobalTransactionScope gts(*sFakeComposer);
        Rect cropRect(16, 16, 32, 32);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setCrop(cropRect));
    }
    ASSERT_EQ(2, sFakeComposer->getFrameCount());

    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mSourceCrop = hwc_frect_t{16.f, 16.f, 32.f, 32.f};
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{64 + 16, 64 + 16, 64 + 32, 64 + 32};
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(TransactionTest, LayerFinalCrop) {
    // TODO: Add scaling to confirm that crop happens in display space?
    {
        GlobalTransactionScope gts(*sFakeComposer);
        Rect cropRect(32, 32, 32 + 64, 32 + 64);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setFinalCrop(cropRect));
    }
    ASSERT_EQ(2, sFakeComposer->getFrameCount());

    // In display space we are cropping with [32, 32, 96, 96] against display rect
    // [64, 64, 128, 128]. Should yield display rect [64, 64, 96, 96]
    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 32.f, 32.f};
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 32, 64 + 32};

    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(TransactionTest, LayerFinalCropEmpty) {
    // TODO: Add scaling to confirm that crop happens in display space?
    {
        GlobalTransactionScope gts(*sFakeComposer);
        Rect cropRect(16, 16, 32, 32);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setFinalCrop(cropRect));
    }
    ASSERT_EQ(2, sFakeComposer->getFrameCount());

    // In display space we are cropping with [16, 16, 32, 32] against display rect
    // [64, 64, 128, 128]. The intersection is empty and only the background layer is composited.
    std::vector<RenderState> referenceFrame(1);
    referenceFrame[BG_LAYER] = mBaseFrame[BG_LAYER];
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(TransactionTest, LayerSetLayer) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setLayer(INT_MAX - 3));
    }
    ASSERT_EQ(2, sFakeComposer->getFrameCount());

    // The layers will switch order, but both are rendered because the background layer is
    // transparent (RGBA8888).
    std::vector<RenderState> referenceFrame(2);
    referenceFrame[0] = mBaseFrame[FG_LAYER];
    referenceFrame[1] = mBaseFrame[BG_LAYER];
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(TransactionTest, LayerSetLayerOpaque) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setLayer(INT_MAX - 3));
        ASSERT_EQ(NO_ERROR,
                  mBGSurfaceControl->setFlags(layer_state_t::eLayerOpaque,
                                              layer_state_t::eLayerOpaque));
    }
    ASSERT_EQ(2, sFakeComposer->getFrameCount());

    // The former foreground layer is now covered with opaque layer - it should have disappeared
    std::vector<RenderState> referenceFrame(1);
    referenceFrame[BG_LAYER] = mBaseFrame[BG_LAYER];
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(TransactionTest, SetLayerStack) {
    ALOGD("TransactionTest::SetLayerStack");
    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setLayerStack(1));
    }

    // Foreground layer should have disappeared.
    ASSERT_EQ(2, sFakeComposer->getFrameCount());
    std::vector<RenderState> refFrame(1);
    refFrame[BG_LAYER] = mBaseFrame[BG_LAYER];
    EXPECT_TRUE(framesAreSame(refFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(TransactionTest, LayerShowHide) {
    ALOGD("TransactionTest::LayerShowHide");
    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->hide());
    }

    // Foreground layer should have disappeared.
    ASSERT_EQ(2, sFakeComposer->getFrameCount());
    std::vector<RenderState> refFrame(1);
    refFrame[BG_LAYER] = mBaseFrame[BG_LAYER];
    EXPECT_TRUE(framesAreSame(refFrame, sFakeComposer->getLatestFrame()));

    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->show());
    }

    // Foreground layer should be back
    ASSERT_EQ(3, sFakeComposer->getFrameCount());
    EXPECT_TRUE(framesAreSame(mBaseFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(TransactionTest, LayerSetAlpha) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setAlpha(0.75f));
    }

    ASSERT_EQ(2, sFakeComposer->getFrameCount());
    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mPlaneAlpha = 0.75f;
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(TransactionTest, LayerSetFlags) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR,
                  mFGSurfaceControl->setFlags(layer_state_t::eLayerHidden,
                                              layer_state_t::eLayerHidden));
    }

    // Foreground layer should have disappeared.
    ASSERT_EQ(2, sFakeComposer->getFrameCount());
    std::vector<RenderState> refFrame(1);
    refFrame[BG_LAYER] = mBaseFrame[BG_LAYER];
    EXPECT_TRUE(framesAreSame(refFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(TransactionTest, LayerSetMatrix) {
    struct matrixTestData {
        float matrix[4];
        hwc_transform_t expectedTransform;
        hwc_rect_t expectedDisplayFrame;
    };

    // The matrix operates on the display frame and is applied before
    // the position is added. So, the foreground layer rect is (0, 0,
    // 64, 64) is first transformed, potentially yielding negative
    // coordinates and then the position (64, 64) is added yielding
    // the final on-screen rectangles given.

    const matrixTestData MATRIX_TESTS[7] = // clang-format off
            {{{-1.f, 0.f, 0.f, 1.f},    HWC_TRANSFORM_FLIP_H,           {0, 64, 64, 128}},
             {{1.f, 0.f, 0.f, -1.f},    HWC_TRANSFORM_FLIP_V,           {64, 0, 128, 64}},
             {{0.f, 1.f, -1.f, 0.f},    HWC_TRANSFORM_ROT_90,           {0, 64, 64, 128}},
             {{-1.f, 0.f, 0.f, -1.f},   HWC_TRANSFORM_ROT_180,          {0, 0, 64, 64}},
             {{0.f, -1.f, 1.f, 0.f},    HWC_TRANSFORM_ROT_270,          {64, 0, 128, 64}},
             {{0.f, 1.f, 1.f, 0.f},     HWC_TRANSFORM_FLIP_H_ROT_90,    {64, 64, 128, 128}},
             {{0.f, 1.f, 1.f, 0.f},     HWC_TRANSFORM_FLIP_V_ROT_90,    {64, 64, 128, 128}}};
    // clang-format on
    constexpr int TEST_COUNT = sizeof(MATRIX_TESTS)/sizeof(matrixTestData);

    for (int i = 0; i < TEST_COUNT; i++) {
        // TODO: How to leverage the HWC2 stringifiers?
        const matrixTestData& xform = MATRIX_TESTS[i];
        SCOPED_TRACE(i);
        {
            GlobalTransactionScope gts(*sFakeComposer);
            ASSERT_EQ(NO_ERROR,
                      mFGSurfaceControl->setMatrix(xform.matrix[0], xform.matrix[1],
                                                   xform.matrix[2], xform.matrix[3]));
        }

        auto referenceFrame = mBaseFrame;
        referenceFrame[FG_LAYER].mTransform = xform.expectedTransform;
        referenceFrame[FG_LAYER].mDisplayFrame = xform.expectedDisplayFrame;

        EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
    }
}

#if 0
TEST_F(TransactionTest, LayerSetMatrix2) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        // TODO: PLEASE SPEC THE FUNCTION!
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setMatrix(0.11f, 0.123f,
                                                         -2.33f, 0.22f));
    }
    auto referenceFrame = mBaseFrame;
    // TODO: Is this correct for sure?
    //referenceFrame[FG_LAYER].mTransform = HWC_TRANSFORM_FLIP_V & HWC_TRANSFORM_ROT_90;

    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}
#endif

TEST_F(TransactionTest, DeferredTransaction) {
    // Synchronization surface
    constexpr static int SYNC_LAYER = 2;
    auto syncSurfaceControl = mComposerClient->createSurface(String8("Sync Test Surface"), 1, 1,
                                                             PIXEL_FORMAT_RGBA_8888, 0);
    ASSERT_TRUE(syncSurfaceControl != nullptr);
    ASSERT_TRUE(syncSurfaceControl->isValid());

    fillSurfaceRGBA8(syncSurfaceControl, DARK_GRAY);

    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, syncSurfaceControl->setLayer(INT32_MAX - 1));
        ASSERT_EQ(NO_ERROR, syncSurfaceControl->setPosition(mDisplayWidth - 2, mDisplayHeight - 2));
        ASSERT_EQ(NO_ERROR, syncSurfaceControl->show());
    }
    auto referenceFrame = mBaseFrame;
    referenceFrame.push_back(makeSimpleRect(mDisplayWidth - 2, mDisplayHeight - 2,
                                            mDisplayWidth - 1, mDisplayHeight - 1));
    referenceFrame[SYNC_LAYER].mSwapCount = 1;
    EXPECT_EQ(2, sFakeComposer->getFrameCount());
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    // set up two deferred transactions on different frames - these should not yield composited
    // frames
    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setAlpha(0.75));
        mFGSurfaceControl
                ->deferTransactionUntil(syncSurfaceControl->getHandle(),
                                        syncSurfaceControl->getSurface()->getNextFrameNumber());
    }
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setPosition(128, 128));
        mFGSurfaceControl
                ->deferTransactionUntil(syncSurfaceControl->getHandle(),
                                        syncSurfaceControl->getSurface()->getNextFrameNumber() + 1);
    }
    EXPECT_EQ(4, sFakeComposer->getFrameCount());
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    // should trigger the first deferred transaction, but not the second one
    fillSurfaceRGBA8(syncSurfaceControl, DARK_GRAY);
    sFakeComposer->runVSyncAndWait();
    EXPECT_EQ(5, sFakeComposer->getFrameCount());

    referenceFrame[FG_LAYER].mPlaneAlpha = 0.75f;
    referenceFrame[SYNC_LAYER].mSwapCount++;
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    // should show up immediately since it's not deferred
    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setAlpha(1.0));
    }
    referenceFrame[FG_LAYER].mPlaneAlpha = 1.f;
    EXPECT_EQ(6, sFakeComposer->getFrameCount());
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    // trigger the second deferred transaction
    fillSurfaceRGBA8(syncSurfaceControl, DARK_GRAY);
    sFakeComposer->runVSyncAndWait();
    // TODO: Compute from layer size?
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{128, 128, 128 + 64, 128 + 64};
    referenceFrame[SYNC_LAYER].mSwapCount++;
    EXPECT_EQ(7, sFakeComposer->getFrameCount());
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(TransactionTest, SetRelativeLayer) {
    constexpr int RELATIVE_LAYER = 2;
    auto relativeSurfaceControl = mComposerClient->createSurface(String8("Test Surface"), 64, 64,
                                                                 PIXEL_FORMAT_RGBA_8888, 0);
    fillSurfaceRGBA8(relativeSurfaceControl, LIGHT_RED);

    // Now we stack the surface above the foreground surface and make sure it is visible.
    {
        GlobalTransactionScope gts(*sFakeComposer);
        relativeSurfaceControl->setPosition(64, 64);
        relativeSurfaceControl->show();
        relativeSurfaceControl->setRelativeLayer(mFGSurfaceControl->getHandle(), 1);
    }
    auto referenceFrame = mBaseFrame;
    // NOTE: All three layers will be visible as the surfaces are
    // transparent because of the RGBA format.
    referenceFrame.push_back(makeSimpleRect(64, 64, 64 + 64, 64 + 64));
    referenceFrame[RELATIVE_LAYER].mSwapCount = 1;
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    // A call to setLayer will override a call to setRelativeLayer
    {
        GlobalTransactionScope gts(*sFakeComposer);
        relativeSurfaceControl->setLayer(0);
    }

    // Previous top layer will now appear at the bottom.
    auto referenceFrame2 = mBaseFrame;
    referenceFrame2.insert(referenceFrame2.begin(), referenceFrame[RELATIVE_LAYER]);
    EXPECT_EQ(3, sFakeComposer->getFrameCount());
    EXPECT_TRUE(framesAreSame(referenceFrame2, sFakeComposer->getLatestFrame()));
}

class ChildLayerTest : public TransactionTest {
protected:
    constexpr static int CHILD_LAYER = 2;

    void SetUp() override {
        TransactionTest::SetUp();
        mChild = mComposerClient->createSurface(String8("Child surface"), 10, 10,
                                                PIXEL_FORMAT_RGBA_8888, 0, mFGSurfaceControl.get());
        fillSurfaceRGBA8(mChild, LIGHT_GRAY);

        sFakeComposer->runVSyncAndWait();
        mBaseFrame.push_back(makeSimpleRect(64, 64, 64 + 10, 64 + 10));
        mBaseFrame[CHILD_LAYER].mSwapCount = 1;
        ASSERT_EQ(2, sFakeComposer->getFrameCount());
        ASSERT_TRUE(framesAreSame(mBaseFrame, sFakeComposer->getLatestFrame()));
    }
    void TearDown() override {
        mChild = 0;
        TransactionTest::TearDown();
    }

    sp<SurfaceControl> mChild;
};

TEST_F(ChildLayerTest, Positioning) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->show();
        mChild->setPosition(10, 10);
        // Move to the same position as in the original setup.
        mFGSurfaceControl->setPosition(64, 64);
    }

    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 64, 64 + 64};
    referenceFrame[CHILD_LAYER].mDisplayFrame =
            hwc_rect_t{64 + 10, 64 + 10, 64 + 10 + 10, 64 + 10 + 10};
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setPosition(0, 0));
    }

    auto referenceFrame2 = mBaseFrame;
    referenceFrame2[FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 0 + 64, 0 + 64};
    referenceFrame2[CHILD_LAYER].mDisplayFrame =
            hwc_rect_t{0 + 10, 0 + 10, 0 + 10 + 10, 0 + 10 + 10};
    EXPECT_TRUE(framesAreSame(referenceFrame2, sFakeComposer->getLatestFrame()));
}

TEST_F(ChildLayerTest, Cropping) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->show();
        mChild->setPosition(0, 0);
        mFGSurfaceControl->setPosition(0, 0);
        mFGSurfaceControl->setCrop(Rect(0, 0, 5, 5));
    }
    // NOTE: The foreground surface would be occluded by the child
    // now, but is included in the stack because the child is
    // transparent.
    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 0 + 5, 0 + 5};
    referenceFrame[FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 5.f, 5.f};
    referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 0 + 5, 0 + 5};
    referenceFrame[CHILD_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 5.f, 5.f};
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(ChildLayerTest, FinalCropping) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->show();
        mChild->setPosition(0, 0);
        mFGSurfaceControl->setPosition(0, 0);
        mFGSurfaceControl->setFinalCrop(Rect(0, 0, 5, 5));
    }
    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 0 + 5, 0 + 5};
    referenceFrame[FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 5.f, 5.f};
    referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 0 + 5, 0 + 5};
    referenceFrame[CHILD_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 5.f, 5.f};
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(ChildLayerTest, Constraints) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->show();
        mFGSurfaceControl->setPosition(0, 0);
        mChild->setPosition(63, 63);
    }
    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 64, 64};
    referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{63, 63, 64, 64};
    referenceFrame[CHILD_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 1.f, 1.f};
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(ChildLayerTest, Scaling) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setPosition(0, 0);
    }
    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 64, 64};
    referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 10, 10};
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setMatrix(2.0, 0, 0, 2.0);
    }

    auto referenceFrame2 = mBaseFrame;
    referenceFrame2[FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 128, 128};
    referenceFrame2[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 20, 20};
    EXPECT_TRUE(framesAreSame(referenceFrame2, sFakeComposer->getLatestFrame()));
}

TEST_F(ChildLayerTest, LayerAlpha) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->show();
        mChild->setPosition(0, 0);
        mFGSurfaceControl->setPosition(0, 0);
        ASSERT_EQ(NO_ERROR, mChild->setAlpha(0.5));
    }

    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 64, 64};
    referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 10, 10};
    referenceFrame[CHILD_LAYER].mPlaneAlpha = 0.5f;
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    {
        GlobalTransactionScope gts(*sFakeComposer);
        ASSERT_EQ(NO_ERROR, mFGSurfaceControl->setAlpha(0.5));
    }

    auto referenceFrame2 = referenceFrame;
    referenceFrame2[FG_LAYER].mPlaneAlpha = 0.5f;
    referenceFrame2[CHILD_LAYER].mPlaneAlpha = 0.25f;
    EXPECT_TRUE(framesAreSame(referenceFrame2, sFakeComposer->getLatestFrame()));
}

TEST_F(ChildLayerTest, ReparentChildren) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->show();
        mChild->setPosition(10, 10);
        mFGSurfaceControl->setPosition(64, 64);
    }
    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 64, 64 + 64};
    referenceFrame[CHILD_LAYER].mDisplayFrame =
            hwc_rect_t{64 + 10, 64 + 10, 64 + 10 + 10, 64 + 10 + 10};
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->reparentChildren(mBGSurfaceControl->getHandle());
    }

    auto referenceFrame2 = referenceFrame;
    referenceFrame2[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 64, 64 + 64};
    referenceFrame2[CHILD_LAYER].mDisplayFrame = hwc_rect_t{10, 10, 10 + 10, 10 + 10};
    EXPECT_TRUE(framesAreSame(referenceFrame2, sFakeComposer->getLatestFrame()));
}

TEST_F(ChildLayerTest, DetachChildren) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->show();
        mChild->setPosition(10, 10);
        mFGSurfaceControl->setPosition(64, 64);
    }

    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 64, 64 + 64};
    referenceFrame[CHILD_LAYER].mDisplayFrame =
            hwc_rect_t{64 + 10, 64 + 10, 64 + 10 + 10, 64 + 10 + 10};
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->detachChildren();
    }

    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->hide();
    }

    // Nothing should have changed. The child control becomes a no-op
    // zombie on detach. See comments for detachChildren in the
    // SurfaceControl.h file.
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(ChildLayerTest, InheritNonTransformScalingFromParent) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->show();
        mChild->setPosition(0, 0);
        mFGSurfaceControl->setPosition(0, 0);
    }

    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setOverrideScalingMode(NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW);
        // We cause scaling by 2.
        mFGSurfaceControl->setSize(128, 128);
    }

    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 128, 128};
    referenceFrame[FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 64.f, 64.f};
    referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 20, 20};
    referenceFrame[CHILD_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 10.f, 10.f};
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

// Regression test for b/37673612
TEST_F(ChildLayerTest, ChildrenWithParentBufferTransform) {
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->show();
        mChild->setPosition(0, 0);
        mFGSurfaceControl->setPosition(0, 0);
    }

    // We set things up as in b/37673612 so that there is a mismatch between the buffer size and
    // the WM specified state size.
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setSize(128, 64);
    }

    sp<Surface> s = mFGSurfaceControl->getSurface();
    auto anw = static_cast<ANativeWindow*>(s.get());
    native_window_set_buffers_transform(anw, NATIVE_WINDOW_TRANSFORM_ROT_90);
    native_window_set_buffers_dimensions(anw, 64, 128);
    fillSurfaceRGBA8(mFGSurfaceControl, RED);
    sFakeComposer->runVSyncAndWait();

    // The child should still be in the same place and not have any strange scaling as in
    // b/37673612.
    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 128, 64};
    referenceFrame[FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 64.f, 128.f};
    referenceFrame[FG_LAYER].mSwapCount++;
    referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 10, 10};
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

TEST_F(ChildLayerTest, Bug36858924) {
    // Destroy the child layer
    mChild.clear();

    // Now recreate it as hidden
    mChild = mComposerClient->createSurface(String8("Child surface"), 10, 10,
                                            PIXEL_FORMAT_RGBA_8888, ISurfaceComposerClient::eHidden,
                                            mFGSurfaceControl.get());

    // Show the child layer in a deferred transaction
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mChild->deferTransactionUntil(mFGSurfaceControl->getHandle(),
                                      mFGSurfaceControl->getSurface()->getNextFrameNumber());
        mChild->show();
    }

    // Render the foreground surface a few times
    //
    // Prior to the bugfix for b/36858924, this would usually hang while trying to fill the third
    // frame because SurfaceFlinger would never process the deferred transaction and would therefore
    // never acquire/release the first buffer
    ALOGI("Filling 1");
    fillSurfaceRGBA8(mFGSurfaceControl, GREEN);
    sFakeComposer->runVSyncAndWait();
    ALOGI("Filling 2");
    fillSurfaceRGBA8(mFGSurfaceControl, BLUE);
    sFakeComposer->runVSyncAndWait();
    ALOGI("Filling 3");
    fillSurfaceRGBA8(mFGSurfaceControl, RED);
    sFakeComposer->runVSyncAndWait();
    ALOGI("Filling 4");
    fillSurfaceRGBA8(mFGSurfaceControl, GREEN);
    sFakeComposer->runVSyncAndWait();
}

class LatchingTest : public TransactionTest {
protected:
    void lockAndFillFGBuffer() { fillSurfaceRGBA8(mFGSurfaceControl, RED, false); }

    void unlockFGBuffer() {
        sp<Surface> s = mFGSurfaceControl->getSurface();
        ASSERT_EQ(NO_ERROR, s->unlockAndPost());
        sFakeComposer->runVSyncAndWait();
    }

    void completeFGResize() {
        fillSurfaceRGBA8(mFGSurfaceControl, RED);
        sFakeComposer->runVSyncAndWait();
    }
    void restoreInitialState() {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setSize(64, 64);
        mFGSurfaceControl->setPosition(64, 64);
        mFGSurfaceControl->setCrop(Rect(0, 0, 64, 64));
        mFGSurfaceControl->setFinalCrop(Rect(0, 0, -1, -1));
    }
};

TEST_F(LatchingTest, SurfacePositionLatching) {
    // By default position can be updated even while
    // a resize is pending.
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setSize(32, 32);
        mFGSurfaceControl->setPosition(100, 100);
    }

    // The size should not have updated as we have not provided a new buffer.
    auto referenceFrame1 = mBaseFrame;
    referenceFrame1[FG_LAYER].mDisplayFrame = hwc_rect_t{100, 100, 100 + 64, 100 + 64};
    EXPECT_TRUE(framesAreSame(referenceFrame1, sFakeComposer->getLatestFrame()));

    restoreInitialState();

    // Now we repeat with setGeometryAppliesWithResize
    // and verify the position DOESN'T latch.
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setGeometryAppliesWithResize();
        mFGSurfaceControl->setSize(32, 32);
        mFGSurfaceControl->setPosition(100, 100);
    }
    EXPECT_TRUE(framesAreSame(mBaseFrame, sFakeComposer->getLatestFrame()));

    completeFGResize();

    auto referenceFrame2 = mBaseFrame;
    referenceFrame2[FG_LAYER].mDisplayFrame = hwc_rect_t{100, 100, 100 + 32, 100 + 32};
    referenceFrame2[FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 32.f, 32.f};
    referenceFrame2[FG_LAYER].mSwapCount++;
    EXPECT_TRUE(framesAreSame(referenceFrame2, sFakeComposer->getLatestFrame()));
}

TEST_F(LatchingTest, CropLatching) {
    // Normally the crop applies immediately even while a resize is pending.
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setSize(128, 128);
        mFGSurfaceControl->setCrop(Rect(0, 0, 63, 63));
    }

    auto referenceFrame1 = mBaseFrame;
    referenceFrame1[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 63, 64 + 63};
    referenceFrame1[FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 63.f, 63.f};
    EXPECT_TRUE(framesAreSame(referenceFrame1, sFakeComposer->getLatestFrame()));

    restoreInitialState();

    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setSize(128, 128);
        mFGSurfaceControl->setGeometryAppliesWithResize();
        mFGSurfaceControl->setCrop(Rect(0, 0, 63, 63));
    }
    EXPECT_TRUE(framesAreSame(mBaseFrame, sFakeComposer->getLatestFrame()));

    completeFGResize();

    auto referenceFrame2 = mBaseFrame;
    referenceFrame2[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 63, 64 + 63};
    referenceFrame2[FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 63.f, 63.f};
    referenceFrame2[FG_LAYER].mSwapCount++;
    EXPECT_TRUE(framesAreSame(referenceFrame2, sFakeComposer->getLatestFrame()));
}

TEST_F(LatchingTest, FinalCropLatching) {
    // Normally the crop applies immediately even while a resize is pending.
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setSize(128, 128);
        mFGSurfaceControl->setFinalCrop(Rect(64, 64, 127, 127));
    }

    auto referenceFrame1 = mBaseFrame;
    referenceFrame1[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 127, 127};
    referenceFrame1[FG_LAYER].mSourceCrop =
            hwc_frect_t{0.f, 0.f, static_cast<float>(127 - 64), static_cast<float>(127 - 64)};
    EXPECT_TRUE(framesAreSame(referenceFrame1, sFakeComposer->getLatestFrame()));

    restoreInitialState();

    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setSize(128, 128);
        mFGSurfaceControl->setGeometryAppliesWithResize();
        mFGSurfaceControl->setFinalCrop(Rect(64, 64, 127, 127));
    }
    EXPECT_TRUE(framesAreSame(mBaseFrame, sFakeComposer->getLatestFrame()));

    completeFGResize();

    auto referenceFrame2 = mBaseFrame;
    referenceFrame2[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 127, 127};
    referenceFrame2[FG_LAYER].mSourceCrop =
            hwc_frect_t{0.f, 0.f, static_cast<float>(127 - 64), static_cast<float>(127 - 64)};
    referenceFrame2[FG_LAYER].mSwapCount++;
    EXPECT_TRUE(framesAreSame(referenceFrame2, sFakeComposer->getLatestFrame()));
}

// In this test we ensure that setGeometryAppliesWithResize actually demands
// a buffer of the new size, and not just any size.
TEST_F(LatchingTest, FinalCropLatchingBufferOldSize) {
    // Normally the crop applies immediately even while a resize is pending.
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setSize(128, 128);
        mFGSurfaceControl->setFinalCrop(Rect(64, 64, 127, 127));
    }

    auto referenceFrame1 = mBaseFrame;
    referenceFrame1[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 127, 127};
    referenceFrame1[FG_LAYER].mSourceCrop =
            hwc_frect_t{0.f, 0.f, static_cast<float>(127 - 64), static_cast<float>(127 - 64)};
    EXPECT_TRUE(framesAreSame(referenceFrame1, sFakeComposer->getLatestFrame()));

    restoreInitialState();

    // In order to prepare to submit a buffer at the wrong size, we acquire it prior to
    // initiating the resize.
    lockAndFillFGBuffer();

    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setSize(128, 128);
        mFGSurfaceControl->setGeometryAppliesWithResize();
        mFGSurfaceControl->setFinalCrop(Rect(64, 64, 127, 127));
    }
    EXPECT_TRUE(framesAreSame(mBaseFrame, sFakeComposer->getLatestFrame()));

    // We now submit our old buffer, at the old size, and ensure it doesn't
    // trigger geometry latching.
    unlockFGBuffer();

    auto referenceFrame2 = mBaseFrame;
    referenceFrame2[FG_LAYER].mSwapCount++;
    EXPECT_TRUE(framesAreSame(referenceFrame2, sFakeComposer->getLatestFrame()));

    completeFGResize();
    auto referenceFrame3 = referenceFrame2;
    referenceFrame3[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 127, 127};
    referenceFrame3[FG_LAYER].mSourceCrop =
            hwc_frect_t{0.f, 0.f, static_cast<float>(127 - 64), static_cast<float>(127 - 64)};
    referenceFrame3[FG_LAYER].mSwapCount++;
    EXPECT_TRUE(framesAreSame(referenceFrame3, sFakeComposer->getLatestFrame()));
}

TEST_F(LatchingTest, FinalCropLatchingRegressionForb37531386) {
    // In this scenario, we attempt to set the final crop a second time while the resize
    // is still pending, and ensure we are successful. Success meaning the second crop
    // is the one which eventually latches and not the first.
    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setSize(128, 128);
        mFGSurfaceControl->setGeometryAppliesWithResize();
        mFGSurfaceControl->setFinalCrop(Rect(64, 64, 127, 127));
    }

    {
        GlobalTransactionScope gts(*sFakeComposer);
        mFGSurfaceControl->setFinalCrop(Rect(0, 0, -1, -1));
    }
    EXPECT_TRUE(framesAreSame(mBaseFrame, sFakeComposer->getLatestFrame()));

    completeFGResize();

    auto referenceFrame = mBaseFrame;
    referenceFrame[FG_LAYER].mSwapCount++;
    EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
}

} // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    sftest::FakeHwcEnvironment* fakeEnvironment = new sftest::FakeHwcEnvironment;
    ::testing::AddGlobalTestEnvironment(fakeEnvironment);
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}
