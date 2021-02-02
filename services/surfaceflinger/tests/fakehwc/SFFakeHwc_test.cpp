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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wextra"

// #define LOG_NDEBUG 0
#undef LOG_TAG
#define LOG_TAG "FakeHwcTest"

#include "FakeComposerClient.h"
#include "FakeComposerService.h"
#include "FakeComposerUtils.h"
#include "MockComposerHal.h"

#include <binder/Parcel.h>
#include <gui/DisplayEventReceiver.h>
#include <gui/ISurfaceComposer.h>
#include <gui/LayerDebugInfo.h>
#include <gui/LayerState.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>

#include <android/hidl/manager/1.0/IServiceManager.h>
#include <android/looper.h>
#include <android/native_window.h>
#include <binder/ProcessState.h>
#include <hwbinder/ProcessState.h>
#include <log/log.h>
#include <private/gui/ComposerService.h>
#include <ui/DisplayConfig.h>
#include <utils/Looper.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <limits>
#include <thread>

using namespace std::chrono_literals;

using namespace android;
using namespace android::hardware;

using namespace sftest;

namespace {

// Mock test helpers
using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;

using Transaction = SurfaceComposerClient::Transaction;
using Attribute = V2_4::IComposerClient::Attribute;
using Display = V2_1::Display;

///////////////////////////////////////////////

constexpr PhysicalDisplayId kPrimaryDisplayId = PhysicalDisplayId::fromPort(PRIMARY_DISPLAY);
constexpr PhysicalDisplayId kExternalDisplayId = PhysicalDisplayId::fromPort(EXTERNAL_DISPLAY);

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

///////////////////////////////////////////////
template <typename FakeComposerService>
class DisplayTest : public ::testing::Test {
protected:
    struct TestConfig {
        int32_t id;
        int32_t w;
        int32_t h;
        int32_t vsyncPeriod;
        int32_t group;
    };

    static int processDisplayEvents(int /*fd*/, int /*events*/, void* data) {
        auto self = static_cast<DisplayTest*>(data);

        ssize_t n;
        DisplayEventReceiver::Event buffer[1];

        while ((n = self->mReceiver->getEvents(buffer, 1)) > 0) {
            for (int i = 0; i < n; i++) {
                self->mReceivedDisplayEvents.push_back(buffer[i]);
            }
        }
        ALOGD_IF(n < 0, "Error reading events (%s)\n", strerror(-n));
        return 1;
    }

    Error getDisplayAttributeNoMock(Display display, Config config,
                                    V2_4::IComposerClient::Attribute attribute, int32_t* outValue) {
        mFakeComposerClient->setMockHal(nullptr);
        auto ret =
                mFakeComposerClient->getDisplayAttribute_2_4(display, config, attribute, outValue);
        mFakeComposerClient->setMockHal(mMockComposer.get());
        return ret;
    }

    void setExpectationsForConfigs(Display display, std::vector<TestConfig> testConfigs,
                                   Config activeConfig, V2_4::VsyncPeriodNanos defaultVsyncPeriod) {
        std::vector<Config> configIds;
        for (int i = 0; i < testConfigs.size(); i++) {
            configIds.push_back(testConfigs[i].id);

            EXPECT_CALL(*mMockComposer,
                        getDisplayAttribute_2_4(display, testConfigs[i].id, Attribute::WIDTH, _))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(testConfigs[i].w), Return(Error::NONE)));
            EXPECT_CALL(*mMockComposer,
                        getDisplayAttribute_2_4(display, testConfigs[i].id, Attribute::HEIGHT, _))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(testConfigs[i].h), Return(Error::NONE)));
            EXPECT_CALL(*mMockComposer,
                        getDisplayAttribute_2_4(display, testConfigs[i].id, Attribute::VSYNC_PERIOD,
                                                _))
                    .WillRepeatedly(DoAll(SetArgPointee<3>(testConfigs[i].vsyncPeriod),
                                          Return(Error::NONE)));
            EXPECT_CALL(*mMockComposer,
                        getDisplayAttribute_2_4(display, testConfigs[i].id, Attribute::CONFIG_GROUP,
                                                _))
                    .WillRepeatedly(
                            DoAll(SetArgPointee<3>(testConfigs[i].group), Return(Error::NONE)));
            EXPECT_CALL(*mMockComposer,
                        getDisplayAttribute_2_4(display, testConfigs[i].id, Attribute::DPI_X, _))
                    .WillRepeatedly(Return(Error::UNSUPPORTED));
            EXPECT_CALL(*mMockComposer,
                        getDisplayAttribute_2_4(display, testConfigs[i].id, Attribute::DPI_Y, _))
                    .WillRepeatedly(Return(Error::UNSUPPORTED));
        }

        EXPECT_CALL(*mMockComposer, getDisplayConfigs(display, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(hidl_vec<Config>(configIds)),
                                      Return(V2_1::Error::NONE)));

        EXPECT_CALL(*mMockComposer, getActiveConfig(display, _))
                .WillRepeatedly(DoAll(SetArgPointee<1>(activeConfig), Return(V2_1::Error::NONE)));

        EXPECT_CALL(*mMockComposer, getDisplayVsyncPeriod(display, _))
                .WillRepeatedly(
                        DoAll(SetArgPointee<1>(defaultVsyncPeriod), Return(V2_4::Error::NONE)));
    }

    void SetUp() override {
        mMockComposer = std::make_unique<MockComposerHal>();
        mFakeComposerClient = new FakeComposerClient();
        mFakeComposerClient->setMockHal(mMockComposer.get());

        sp<V2_4::hal::ComposerClient> client = new V2_4::hal::ComposerClient(mFakeComposerClient);
        mFakeService = new FakeComposerService(client);
        ASSERT_EQ(android::OK, mFakeService->registerAsService("mock"));

        android::hardware::ProcessState::self()->startThreadPool();
        android::ProcessState::self()->startThreadPool();

        setExpectationsForConfigs(PRIMARY_DISPLAY,
                                  {{
                                          .id = 1,
                                          .w = 1920,
                                          .h = 1024,
                                          .vsyncPeriod = 16'666'666,
                                          .group = 0,
                                  }},
                                  1, 16'666'666);

        startSurfaceFlinger();

        // Fake composer wants to enable VSync injection
        mFakeComposerClient->onSurfaceFlingerStart();

        mComposerClient = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());

        mReceiver.reset(
                new DisplayEventReceiver(ISurfaceComposer::eVsyncSourceApp,
                                         ISurfaceComposer::EventRegistration::configChanged));
        mLooper = new Looper(false);
        mLooper->addFd(mReceiver->getFd(), 0, ALOOPER_EVENT_INPUT, processDisplayEvents, this);
    }

    void TearDown() override {
        mLooper = nullptr;
        mReceiver = nullptr;

        mComposerClient->dispose();
        mComposerClient = nullptr;

        // Fake composer needs to release SurfaceComposerClient before the stop.
        mFakeComposerClient->onSurfaceFlingerStop();
        stopSurfaceFlinger();

        mFakeComposerClient->setMockHal(nullptr);

        mFakeService = nullptr;
        // TODO: Currently deleted in FakeComposerClient::removeClient(). Devise better lifetime
        // management.
        mMockComposer = nullptr;
    }

    void waitForDisplayTransaction() {
        // Both a refresh and a vsync event are needed to apply pending display
        // transactions.
        mFakeComposerClient->refreshDisplay(EXTERNAL_DISPLAY);
        mFakeComposerClient->runVSyncAndWait();

        // Extra vsync and wait to avoid a 10% flake due to a race.
        mFakeComposerClient->runVSyncAndWait();
    }

    bool waitForHotplugEvent(Display displayId, bool connected) {
        return waitForHotplugEvent(PhysicalDisplayId(displayId), connected);
    }

    bool waitForHotplugEvent(PhysicalDisplayId displayId, bool connected) {
        int waitCount = 20;
        while (waitCount--) {
            while (!mReceivedDisplayEvents.empty()) {
                auto event = mReceivedDisplayEvents.front();
                mReceivedDisplayEvents.pop_front();

                ALOGV_IF(event.header.type == DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG,
                         "event hotplug: displayId %s, connected %d\t",
                         to_string(event.header.displayId).c_str(), event.hotplug.connected);

                if (event.header.type == DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG &&
                    event.header.displayId == displayId && event.hotplug.connected == connected) {
                    return true;
                }
            }

            mLooper->pollOnce(1);
        }
        return false;
    }

    bool waitForConfigChangedEvent(Display display, int32_t configId) {
        PhysicalDisplayId displayId(display);
        int waitCount = 20;
        while (waitCount--) {
            while (!mReceivedDisplayEvents.empty()) {
                auto event = mReceivedDisplayEvents.front();
                mReceivedDisplayEvents.pop_front();

                ALOGV_IF(event.header.type == DisplayEventReceiver::DISPLAY_EVENT_CONFIG_CHANGED,
                         "event config: displayId %s, configId %d\t",
                         to_string(event.header.displayId).c_str(), event.config.configId);

                if (event.header.type == DisplayEventReceiver::DISPLAY_EVENT_CONFIG_CHANGED &&
                    event.header.displayId == displayId && event.config.configId == configId) {
                    return true;
                }
            }

            mLooper->pollOnce(1);
        }
        return false;
    }

    void Test_HotplugOneConfig() {
        ALOGD("DisplayTest::Test_Hotplug_oneConfig");

        setExpectationsForConfigs(EXTERNAL_DISPLAY,
                                  {{.id = 1,
                                    .w = 200,
                                    .h = 400,
                                    .vsyncPeriod = 16'666'666,
                                    .group = 0}},
                                  1, 16'666'666);

        mFakeComposerClient->hotplugDisplay(EXTERNAL_DISPLAY,
                                            V2_1::IComposerCallback::Connection::CONNECTED);
        waitForDisplayTransaction();
        EXPECT_TRUE(waitForHotplugEvent(EXTERNAL_DISPLAY, true));

        {
            const auto display = SurfaceComposerClient::getPhysicalDisplayToken(kExternalDisplayId);
            EXPECT_FALSE(display == nullptr);

            DisplayConfig config;
            EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));
            const ui::Size& resolution = config.resolution;
            EXPECT_EQ(ui::Size(200, 400), resolution);
            EXPECT_EQ(1e9f / 16'666'666, config.refreshRate);

            auto surfaceControl =
                    mComposerClient->createSurface(String8("Display Test Surface Foo"),
                                                   resolution.getWidth(), resolution.getHeight(),
                                                   PIXEL_FORMAT_RGBA_8888, 0);
            EXPECT_TRUE(surfaceControl != nullptr);
            EXPECT_TRUE(surfaceControl->isValid());
            fillSurfaceRGBA8(surfaceControl, BLUE);

            {
                TransactionScope ts(*mFakeComposerClient);
                ts.setDisplayLayerStack(display, 0);

                ts.setLayer(surfaceControl, INT32_MAX - 2).show(surfaceControl);
            }
        }

        mFakeComposerClient->hotplugDisplay(EXTERNAL_DISPLAY,
                                            V2_1::IComposerCallback::Connection::DISCONNECTED);
        waitForDisplayTransaction();
        mFakeComposerClient->clearFrames();
        EXPECT_TRUE(waitForHotplugEvent(EXTERNAL_DISPLAY, false));

        {
            const auto display = SurfaceComposerClient::getPhysicalDisplayToken(kExternalDisplayId);
            EXPECT_TRUE(display == nullptr);

            DisplayConfig config;
            EXPECT_NE(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));
        }
    }

    void Test_HotplugTwoSeparateConfigs() {
        ALOGD("DisplayTest::Test_HotplugTwoSeparateConfigs");

        setExpectationsForConfigs(EXTERNAL_DISPLAY,
                                  {{.id = 1,
                                    .w = 200,
                                    .h = 400,
                                    .vsyncPeriod = 16'666'666,
                                    .group = 0},
                                   {.id = 2,
                                    .w = 800,
                                    .h = 1600,
                                    .vsyncPeriod = 11'111'111,
                                    .group = 1}},
                                  1, 16'666'666);

        mFakeComposerClient->hotplugDisplay(EXTERNAL_DISPLAY,
                                            V2_1::IComposerCallback::Connection::CONNECTED);
        waitForDisplayTransaction();
        EXPECT_TRUE(waitForHotplugEvent(EXTERNAL_DISPLAY, true));

        const auto display = SurfaceComposerClient::getPhysicalDisplayToken(kExternalDisplayId);
        EXPECT_FALSE(display == nullptr);

        DisplayConfig config;
        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));
        EXPECT_EQ(ui::Size(200, 400), config.resolution);
        EXPECT_EQ(1e9f / 16'666'666, config.refreshRate);

        mFakeComposerClient->clearFrames();
        {
            const ui::Size& resolution = config.resolution;
            auto surfaceControl =
                    mComposerClient->createSurface(String8("Display Test Surface Foo"),
                                                   resolution.getWidth(), resolution.getHeight(),
                                                   PIXEL_FORMAT_RGBA_8888, 0);
            EXPECT_TRUE(surfaceControl != nullptr);
            EXPECT_TRUE(surfaceControl->isValid());
            fillSurfaceRGBA8(surfaceControl, BLUE);

            {
                TransactionScope ts(*mFakeComposerClient);
                ts.setDisplayLayerStack(display, 0);

                ts.setLayer(surfaceControl, INT32_MAX - 2).show(surfaceControl);
            }
        }

        Vector<DisplayConfig> configs;
        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getDisplayConfigs(display, &configs));
        EXPECT_EQ(configs.size(), 2);

        // change active config

        if (mIs2_4Client) {
            EXPECT_CALL(*mMockComposer, setActiveConfigWithConstraints(EXTERNAL_DISPLAY, 2, _, _))
                    .WillOnce(Return(V2_4::Error::NONE));
        } else {
            EXPECT_CALL(*mMockComposer, setActiveConfig(EXTERNAL_DISPLAY, 2))
                    .WillOnce(Return(V2_1::Error::NONE));
        }

        for (int i = 0; i < configs.size(); i++) {
            const auto& config = configs[i];
            if (config.resolution.getWidth() == 800) {
                EXPECT_EQ(NO_ERROR,
                          SurfaceComposerClient::setDesiredDisplayConfigSpecs(display, i, false,
                                                                              config.refreshRate,
                                                                              config.refreshRate,
                                                                              config.refreshRate,
                                                                              config.refreshRate));
                waitForDisplayTransaction();
                EXPECT_TRUE(waitForConfigChangedEvent(EXTERNAL_DISPLAY, i));
                break;
            }
        }

        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));
        EXPECT_EQ(ui::Size(800, 1600), config.resolution);
        EXPECT_EQ(1e9f / 11'111'111, config.refreshRate);

        mFakeComposerClient->clearFrames();
        {
            const ui::Size& resolution = config.resolution;
            auto surfaceControl =
                    mComposerClient->createSurface(String8("Display Test Surface Foo"),
                                                   resolution.getWidth(), resolution.getHeight(),
                                                   PIXEL_FORMAT_RGBA_8888, 0);
            EXPECT_TRUE(surfaceControl != nullptr);
            EXPECT_TRUE(surfaceControl->isValid());
            fillSurfaceRGBA8(surfaceControl, BLUE);

            {
                TransactionScope ts(*mFakeComposerClient);
                ts.setDisplayLayerStack(display, 0);

                ts.setLayer(surfaceControl, INT32_MAX - 2).show(surfaceControl);
            }
        }

        mFakeComposerClient->hotplugDisplay(EXTERNAL_DISPLAY,
                                            V2_1::IComposerCallback::Connection::DISCONNECTED);
        waitForDisplayTransaction();
        mFakeComposerClient->clearFrames();
        EXPECT_TRUE(waitForHotplugEvent(EXTERNAL_DISPLAY, false));
    }

    void Test_HotplugTwoConfigsSameGroup() {
        ALOGD("DisplayTest::Test_HotplugTwoConfigsSameGroup");

        setExpectationsForConfigs(EXTERNAL_DISPLAY,
                                  {{.id = 2,
                                    .w = 800,
                                    .h = 1600,
                                    .vsyncPeriod = 16'666'666,
                                    .group = 31},
                                   {.id = 3,
                                    .w = 800,
                                    .h = 1600,
                                    .vsyncPeriod = 11'111'111,
                                    .group = 31}},
                                  2, 16'666'666);

        mFakeComposerClient->hotplugDisplay(EXTERNAL_DISPLAY,
                                            V2_1::IComposerCallback::Connection::CONNECTED);
        waitForDisplayTransaction();
        EXPECT_TRUE(waitForHotplugEvent(EXTERNAL_DISPLAY, true));

        const auto display = SurfaceComposerClient::getPhysicalDisplayToken(kExternalDisplayId);
        EXPECT_FALSE(display == nullptr);

        DisplayConfig config;
        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));
        EXPECT_EQ(ui::Size(800, 1600), config.resolution);
        EXPECT_EQ(1e9f / 16'666'666, config.refreshRate);

        mFakeComposerClient->clearFrames();
        {
            const ui::Size& resolution = config.resolution;
            auto surfaceControl =
                    mComposerClient->createSurface(String8("Display Test Surface Foo"),
                                                   resolution.getWidth(), resolution.getHeight(),
                                                   PIXEL_FORMAT_RGBA_8888, 0);
            EXPECT_TRUE(surfaceControl != nullptr);
            EXPECT_TRUE(surfaceControl->isValid());
            fillSurfaceRGBA8(surfaceControl, BLUE);

            {
                TransactionScope ts(*mFakeComposerClient);
                ts.setDisplayLayerStack(display, 0);

                ts.setLayer(surfaceControl, INT32_MAX - 2).show(surfaceControl);
            }
        }

        Vector<DisplayConfig> configs;
        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getDisplayConfigs(display, &configs));
        EXPECT_EQ(configs.size(), 2);

        // change active config
        if (mIs2_4Client) {
            EXPECT_CALL(*mMockComposer, setActiveConfigWithConstraints(EXTERNAL_DISPLAY, 3, _, _))
                    .WillOnce(Return(V2_4::Error::NONE));
        } else {
            EXPECT_CALL(*mMockComposer, setActiveConfig(EXTERNAL_DISPLAY, 3))
                    .WillOnce(Return(V2_1::Error::NONE));
        }

        for (int i = 0; i < configs.size(); i++) {
            const auto& config = configs[i];
            if (config.refreshRate == 1e9f / 11'111'111) {
                EXPECT_EQ(NO_ERROR,
                          SurfaceComposerClient::setDesiredDisplayConfigSpecs(display, i, false,
                                                                              config.refreshRate,
                                                                              config.refreshRate,
                                                                              config.refreshRate,
                                                                              config.refreshRate));
                waitForDisplayTransaction();
                EXPECT_TRUE(waitForConfigChangedEvent(EXTERNAL_DISPLAY, i));
                break;
            }
        }

        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));
        EXPECT_EQ(ui::Size(800, 1600), config.resolution);
        EXPECT_EQ(1e9f / 11'111'111, config.refreshRate);

        mFakeComposerClient->clearFrames();
        {
            const ui::Size& resolution = config.resolution;
            auto surfaceControl =
                    mComposerClient->createSurface(String8("Display Test Surface Foo"),
                                                   resolution.getWidth(), resolution.getHeight(),
                                                   PIXEL_FORMAT_RGBA_8888, 0);
            EXPECT_TRUE(surfaceControl != nullptr);
            EXPECT_TRUE(surfaceControl->isValid());
            fillSurfaceRGBA8(surfaceControl, BLUE);

            {
                TransactionScope ts(*mFakeComposerClient);
                ts.setDisplayLayerStack(display, 0);

                ts.setLayer(surfaceControl, INT32_MAX - 2).show(surfaceControl);
            }
        }

        mFakeComposerClient->hotplugDisplay(EXTERNAL_DISPLAY,
                                            V2_1::IComposerCallback::Connection::DISCONNECTED);
        waitForDisplayTransaction();
        mFakeComposerClient->clearFrames();
        EXPECT_TRUE(waitForHotplugEvent(EXTERNAL_DISPLAY, false));
    }

    void Test_HotplugThreeConfigsMixedGroups() {
        ALOGD("DisplayTest::Test_HotplugThreeConfigsMixedGroups");

        setExpectationsForConfigs(EXTERNAL_DISPLAY,
                                  {{.id = 2,
                                    .w = 800,
                                    .h = 1600,
                                    .vsyncPeriod = 16'666'666,
                                    .group = 0},
                                   {.id = 3,
                                    .w = 800,
                                    .h = 1600,
                                    .vsyncPeriod = 11'111'111,
                                    .group = 0},
                                   {.id = 4,
                                    .w = 1600,
                                    .h = 3200,
                                    .vsyncPeriod = 8'333'333,
                                    .group = 1},
                                   {.id = 5,
                                    .w = 1600,
                                    .h = 3200,
                                    .vsyncPeriod = 11'111'111,
                                    .group = 1}},
                                  2, 16'666'666);

        mFakeComposerClient->hotplugDisplay(EXTERNAL_DISPLAY,
                                            V2_1::IComposerCallback::Connection::CONNECTED);
        waitForDisplayTransaction();
        EXPECT_TRUE(waitForHotplugEvent(EXTERNAL_DISPLAY, true));

        const auto display = SurfaceComposerClient::getPhysicalDisplayToken(kExternalDisplayId);
        EXPECT_FALSE(display == nullptr);

        DisplayConfig config;
        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));
        EXPECT_EQ(ui::Size(800, 1600), config.resolution);
        EXPECT_EQ(1e9f / 16'666'666, config.refreshRate);

        mFakeComposerClient->clearFrames();
        {
            const ui::Size& resolution = config.resolution;
            auto surfaceControl =
                    mComposerClient->createSurface(String8("Display Test Surface Foo"),
                                                   resolution.getWidth(), resolution.getHeight(),
                                                   PIXEL_FORMAT_RGBA_8888, 0);
            EXPECT_TRUE(surfaceControl != nullptr);
            EXPECT_TRUE(surfaceControl->isValid());
            fillSurfaceRGBA8(surfaceControl, BLUE);

            {
                TransactionScope ts(*mFakeComposerClient);
                ts.setDisplayLayerStack(display, 0);

                ts.setLayer(surfaceControl, INT32_MAX - 2).show(surfaceControl);
            }
        }

        Vector<DisplayConfig> configs;
        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getDisplayConfigs(display, &configs));
        EXPECT_EQ(configs.size(), 4);

        // change active config to 800x1600@90Hz
        if (mIs2_4Client) {
            EXPECT_CALL(*mMockComposer, setActiveConfigWithConstraints(EXTERNAL_DISPLAY, 3, _, _))
                    .WillOnce(Return(V2_4::Error::NONE));
        } else {
            EXPECT_CALL(*mMockComposer, setActiveConfig(EXTERNAL_DISPLAY, 3))
                    .WillOnce(Return(V2_1::Error::NONE));
        }

        for (int i = 0; i < configs.size(); i++) {
            const auto& config = configs[i];
            if (config.resolution.getWidth() == 800 && config.refreshRate == 1e9f / 11'111'111) {
                EXPECT_EQ(NO_ERROR,
                          SurfaceComposerClient::
                                  setDesiredDisplayConfigSpecs(display, i, false,
                                                               configs[i].refreshRate,
                                                               configs[i].refreshRate,
                                                               configs[i].refreshRate,
                                                               configs[i].refreshRate));
                waitForDisplayTransaction();
                EXPECT_TRUE(waitForConfigChangedEvent(EXTERNAL_DISPLAY, i));
                break;
            }
        }

        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));
        EXPECT_EQ(ui::Size(800, 1600), config.resolution);
        EXPECT_EQ(1e9f / 11'111'111, config.refreshRate);

        mFakeComposerClient->clearFrames();
        {
            const ui::Size& resolution = config.resolution;
            auto surfaceControl =
                    mComposerClient->createSurface(String8("Display Test Surface Foo"),
                                                   resolution.getWidth(), resolution.getHeight(),
                                                   PIXEL_FORMAT_RGBA_8888, 0);
            EXPECT_TRUE(surfaceControl != nullptr);
            EXPECT_TRUE(surfaceControl->isValid());
            fillSurfaceRGBA8(surfaceControl, BLUE);

            {
                TransactionScope ts(*mFakeComposerClient);
                ts.setDisplayLayerStack(display, 0);

                ts.setLayer(surfaceControl, INT32_MAX - 2).show(surfaceControl);
            }
        }

        // change active config to 1600x3200@120Hz
        if (mIs2_4Client) {
            EXPECT_CALL(*mMockComposer, setActiveConfigWithConstraints(EXTERNAL_DISPLAY, 4, _, _))
                    .WillOnce(Return(V2_4::Error::NONE));
        } else {
            EXPECT_CALL(*mMockComposer, setActiveConfig(EXTERNAL_DISPLAY, 4))
                    .WillOnce(Return(V2_1::Error::NONE));
        }

        for (int i = 0; i < configs.size(); i++) {
            const auto& config = configs[i];
            if (config.refreshRate == 1e9f / 8'333'333) {
                EXPECT_EQ(NO_ERROR,
                          SurfaceComposerClient::setDesiredDisplayConfigSpecs(display, i, false,
                                                                              config.refreshRate,
                                                                              config.refreshRate,
                                                                              config.refreshRate,
                                                                              config.refreshRate));
                waitForDisplayTransaction();
                EXPECT_TRUE(waitForConfigChangedEvent(EXTERNAL_DISPLAY, i));
                break;
            }
        }

        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));
        EXPECT_EQ(ui::Size(1600, 3200), config.resolution);
        EXPECT_EQ(1e9f / 8'333'333, config.refreshRate);

        mFakeComposerClient->clearFrames();
        {
            const ui::Size& resolution = config.resolution;
            auto surfaceControl =
                    mComposerClient->createSurface(String8("Display Test Surface Foo"),
                                                   resolution.getWidth(), resolution.getHeight(),
                                                   PIXEL_FORMAT_RGBA_8888, 0);
            EXPECT_TRUE(surfaceControl != nullptr);
            EXPECT_TRUE(surfaceControl->isValid());
            fillSurfaceRGBA8(surfaceControl, BLUE);

            {
                TransactionScope ts(*mFakeComposerClient);
                ts.setDisplayLayerStack(display, 0);

                ts.setLayer(surfaceControl, INT32_MAX - 2).show(surfaceControl);
            }
        }

        // change active config to 1600x3200@90Hz
        if (mIs2_4Client) {
            EXPECT_CALL(*mMockComposer, setActiveConfigWithConstraints(EXTERNAL_DISPLAY, 5, _, _))
                    .WillOnce(Return(V2_4::Error::NONE));
        } else {
            EXPECT_CALL(*mMockComposer, setActiveConfig(EXTERNAL_DISPLAY, 5))
                    .WillOnce(Return(V2_1::Error::NONE));
        }

        for (int i = 0; i < configs.size(); i++) {
            const auto& config = configs[i];
            if (config.resolution.getWidth() == 1600 && config.refreshRate == 1e9f / 11'111'111) {
                EXPECT_EQ(NO_ERROR,
                          SurfaceComposerClient::setDesiredDisplayConfigSpecs(display, i, false,
                                                                              config.refreshRate,
                                                                              config.refreshRate,
                                                                              config.refreshRate,
                                                                              config.refreshRate));
                waitForDisplayTransaction();
                EXPECT_TRUE(waitForConfigChangedEvent(EXTERNAL_DISPLAY, i));
                break;
            }
        }

        EXPECT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));
        EXPECT_EQ(ui::Size(1600, 3200), config.resolution);
        EXPECT_EQ(1e9f / 11'111'111, config.refreshRate);

        mFakeComposerClient->clearFrames();
        {
            const ui::Size& resolution = config.resolution;
            auto surfaceControl =
                    mComposerClient->createSurface(String8("Display Test Surface Foo"),
                                                   resolution.getWidth(), resolution.getHeight(),
                                                   PIXEL_FORMAT_RGBA_8888, 0);
            EXPECT_TRUE(surfaceControl != nullptr);
            EXPECT_TRUE(surfaceControl->isValid());
            fillSurfaceRGBA8(surfaceControl, BLUE);

            {
                TransactionScope ts(*mFakeComposerClient);
                ts.setDisplayLayerStack(display, 0);

                ts.setLayer(surfaceControl, INT32_MAX - 2).show(surfaceControl);
            }
        }

        mFakeComposerClient->hotplugDisplay(EXTERNAL_DISPLAY,
                                            V2_1::IComposerCallback::Connection::DISCONNECTED);
        waitForDisplayTransaction();
        mFakeComposerClient->clearFrames();
        EXPECT_TRUE(waitForHotplugEvent(EXTERNAL_DISPLAY, false));
    }

    void Test_HotplugPrimaryDisplay() {
        ALOGD("DisplayTest::HotplugPrimaryDisplay");

        mFakeComposerClient->hotplugDisplay(PRIMARY_DISPLAY,
                                            V2_1::IComposerCallback::Connection::DISCONNECTED);

        waitForDisplayTransaction();

        EXPECT_TRUE(waitForHotplugEvent(PRIMARY_DISPLAY, false));
        {
            const auto display = SurfaceComposerClient::getPhysicalDisplayToken(kPrimaryDisplayId);
            EXPECT_TRUE(display == nullptr);

            DisplayConfig config;
            auto result = SurfaceComposerClient::getActiveDisplayConfig(display, &config);
            EXPECT_NE(NO_ERROR, result);
        }

        mFakeComposerClient->clearFrames();

        setExpectationsForConfigs(PRIMARY_DISPLAY,
                                  {{.id = 1,
                                    .w = 400,
                                    .h = 200,
                                    .vsyncPeriod = 16'666'666,
                                    .group = 0}},
                                  1, 16'666'666);

        mFakeComposerClient->hotplugDisplay(PRIMARY_DISPLAY,
                                            V2_1::IComposerCallback::Connection::CONNECTED);

        waitForDisplayTransaction();

        EXPECT_TRUE(waitForHotplugEvent(PRIMARY_DISPLAY, true));

        {
            const auto display = SurfaceComposerClient::getPhysicalDisplayToken(kPrimaryDisplayId);
            EXPECT_FALSE(display == nullptr);

            DisplayConfig config;
            auto result = SurfaceComposerClient::getActiveDisplayConfig(display, &config);
            EXPECT_EQ(NO_ERROR, result);
            ASSERT_EQ(ui::Size(400, 200), config.resolution);
            EXPECT_EQ(1e9f / 16'666'666, config.refreshRate);
        }
    }

    sp<V2_1::IComposer> mFakeService;
    sp<SurfaceComposerClient> mComposerClient;

    std::unique_ptr<MockComposerHal> mMockComposer;
    FakeComposerClient* mFakeComposerClient;

    std::unique_ptr<DisplayEventReceiver> mReceiver;
    sp<Looper> mLooper;
    std::deque<DisplayEventReceiver::Event> mReceivedDisplayEvents;

    static constexpr bool mIs2_4Client =
            std::is_same<FakeComposerService, FakeComposerService_2_4>::value;
};

using DisplayTest_2_1 = DisplayTest<FakeComposerService_2_1>;

// Tests that VSYNC injection can be safely toggled while invalidating.
TEST_F(DisplayTest_2_1, VsyncInjection) {
    const auto flinger = ComposerService::getComposerService();
    bool enable = true;

    for (int i = 0; i < 100; i++) {
        flinger->enableVSyncInjections(enable);
        enable = !enable;

        constexpr uint32_t kForceInvalidate = 1004;
        android::Parcel data, reply;
        data.writeInterfaceToken(String16("android.ui.ISurfaceComposer"));
        EXPECT_EQ(NO_ERROR,
                  android::IInterface::asBinder(flinger)->transact(kForceInvalidate, data, &reply));

        std::this_thread::sleep_for(5ms);
    }
}

TEST_F(DisplayTest_2_1, HotplugOneConfig) {
    Test_HotplugOneConfig();
}

TEST_F(DisplayTest_2_1, HotplugTwoSeparateConfigs) {
    Test_HotplugTwoSeparateConfigs();
}

TEST_F(DisplayTest_2_1, HotplugTwoConfigsSameGroup) {
    Test_HotplugTwoConfigsSameGroup();
}

TEST_F(DisplayTest_2_1, HotplugThreeConfigsMixedGroups) {
    Test_HotplugThreeConfigsMixedGroups();
}

TEST_F(DisplayTest_2_1, HotplugPrimaryOneConfig) {
    Test_HotplugPrimaryDisplay();
}

using DisplayTest_2_2 = DisplayTest<FakeComposerService_2_2>;

TEST_F(DisplayTest_2_2, HotplugOneConfig) {
    Test_HotplugOneConfig();
}

TEST_F(DisplayTest_2_2, HotplugTwoSeparateConfigs) {
    Test_HotplugTwoSeparateConfigs();
}

TEST_F(DisplayTest_2_2, HotplugTwoConfigsSameGroup) {
    Test_HotplugTwoConfigsSameGroup();
}

TEST_F(DisplayTest_2_2, HotplugThreeConfigsMixedGroups) {
    Test_HotplugThreeConfigsMixedGroups();
}

TEST_F(DisplayTest_2_2, HotplugPrimaryOneConfig) {
    Test_HotplugPrimaryDisplay();
}

using DisplayTest_2_3 = DisplayTest<FakeComposerService_2_3>;

TEST_F(DisplayTest_2_3, HotplugOneConfig) {
    Test_HotplugOneConfig();
}

TEST_F(DisplayTest_2_3, HotplugTwoSeparateConfigs) {
    Test_HotplugTwoSeparateConfigs();
}

TEST_F(DisplayTest_2_3, HotplugTwoConfigsSameGroup) {
    Test_HotplugTwoConfigsSameGroup();
}

TEST_F(DisplayTest_2_3, HotplugThreeConfigsMixedGroups) {
    Test_HotplugThreeConfigsMixedGroups();
}

TEST_F(DisplayTest_2_3, HotplugPrimaryOneConfig) {
    Test_HotplugPrimaryDisplay();
}

using DisplayTest_2_4 = DisplayTest<FakeComposerService_2_4>;

TEST_F(DisplayTest_2_4, HotplugOneConfig) {
    Test_HotplugOneConfig();
}

TEST_F(DisplayTest_2_4, HotplugTwoSeparateConfigs) {
    Test_HotplugTwoSeparateConfigs();
}

TEST_F(DisplayTest_2_4, HotplugTwoConfigsSameGroup) {
    Test_HotplugTwoConfigsSameGroup();
}

TEST_F(DisplayTest_2_4, HotplugThreeConfigsMixedGroups) {
    Test_HotplugThreeConfigsMixedGroups();
}

TEST_F(DisplayTest_2_4, HotplugPrimaryOneConfig) {
    Test_HotplugPrimaryDisplay();
}

////////////////////////////////////////////////

template <typename FakeComposerService>
class TransactionTest : public ::testing::Test {
protected:
    // Layer array indexing constants.
    constexpr static int BG_LAYER = 0;
    constexpr static int FG_LAYER = 1;

    static void SetUpTestCase() {
        // TODO: See TODO comment at DisplayTest::SetUp for background on
        // the lifetime of the FakeComposerClient.
        sFakeComposer = new FakeComposerClient;
        sp<V2_4::hal::ComposerClient> client = new V2_4::hal::ComposerClient(sFakeComposer);
        sp<V2_1::IComposer> fakeService = new FakeComposerService(client);
        (void)fakeService->registerAsService("mock");

        android::hardware::ProcessState::self()->startThreadPool();
        android::ProcessState::self()->startThreadPool();

        startSurfaceFlinger();

        // Fake composer wants to enable VSync injection
        sFakeComposer->onSurfaceFlingerStart();
    }

    static void TearDownTestCase() {
        // Fake composer needs to release SurfaceComposerClient before the stop.
        sFakeComposer->onSurfaceFlingerStop();
        stopSurfaceFlinger();
        // TODO: This is deleted when the ComposerClient calls
        // removeClient. Devise better lifetime control.
        sFakeComposer = nullptr;
    }

    void SetUp() override {
        ALOGI("TransactionTest::SetUp");
        mComposerClient = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mComposerClient->initCheck());

        ALOGI("TransactionTest::SetUp - display");
        const auto display = SurfaceComposerClient::getPhysicalDisplayToken(kPrimaryDisplayId);
        ASSERT_FALSE(display == nullptr);

        DisplayConfig config;
        ASSERT_EQ(NO_ERROR, SurfaceComposerClient::getActiveDisplayConfig(display, &config));

        const ui::Size& resolution = config.resolution;
        mDisplayWidth = resolution.getWidth();
        mDisplayHeight = resolution.getHeight();

        // Background surface
        mBGSurfaceControl =
                mComposerClient->createSurface(String8("BG Test Surface"), mDisplayWidth,
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

        Transaction t;
        t.setDisplayLayerStack(display, 0);

        t.setLayer(mBGSurfaceControl, INT32_MAX - 2);
        t.show(mBGSurfaceControl);

        t.setLayer(mFGSurfaceControl, INT32_MAX - 1);
        t.setPosition(mFGSurfaceControl, 64, 64);
        t.show(mFGSurfaceControl);

        // Synchronous transaction will stop this thread, so we set up a
        // delayed, off-thread vsync request before closing the
        // transaction. In the test code this is usually done with
        // TransactionScope. Leaving here in the 'vanilla' form for
        // reference.
        ASSERT_EQ(0, sFakeComposer->getFrameCount());
        sFakeComposer->runVSyncAfter(1ms);
        t.apply();
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

    void TearDown() override {
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

    void Test_LayerMove() {
        ALOGD("TransactionTest::LayerMove");

        // The scope opens and closes a global transaction and, at the
        // same time, makes sure the SurfaceFlinger progresses one frame
        // after the transaction closes. The results of the transaction
        // should be available in the latest frame stored by the fake
        // composer.
        {
            TransactionScope ts(*sFakeComposer);
            ts.setPosition(mFGSurfaceControl, 128, 128);
            // NOTE: No changes yet, so vsync will do nothing, HWC does not get any calls.
            // (How to verify that? Throw in vsync and wait a 2x frame time? Separate test?)
            //
            // sFakeComposer->runVSyncAndWait();
        }

        fillSurfaceRGBA8(mFGSurfaceControl, GREEN);
        sFakeComposer->runVSyncAndWait();

        ASSERT_EQ(3, sFakeComposer->getFrameCount()); // Make sure the waits didn't time out and
                                                      // there's no extra frames.

        // NOTE: Frame 0 is produced in the SetUp.
        auto frame1Ref = mBaseFrame;
        frame1Ref[FG_LAYER].mDisplayFrame =
                hwc_rect_t{128, 128, 128 + 64, 128 + 64}; // Top-most layer moves.
        EXPECT_TRUE(framesAreSame(frame1Ref, sFakeComposer->getFrameRects(1)));

        auto frame2Ref = frame1Ref;
        frame2Ref[FG_LAYER].mSwapCount++;
        EXPECT_TRUE(framesAreSame(frame2Ref, sFakeComposer->getFrameRects(2)));
    }

    void Test_LayerResize() {
        ALOGD("TransactionTest::LayerResize");
        {
            TransactionScope ts(*sFakeComposer);
            ts.setSize(mFGSurfaceControl, 128, 128);
        }

        fillSurfaceRGBA8(mFGSurfaceControl, GREEN);
        sFakeComposer->runVSyncAndWait();

        ASSERT_EQ(3, sFakeComposer->getFrameCount()); // Make sure the waits didn't time out and
                                                      // there's no extra frames.

        auto frame1Ref = mBaseFrame;
        // NOTE: The resize should not be visible for frame 1 as there's no buffer with new size
        // posted.
        EXPECT_TRUE(framesAreSame(frame1Ref, sFakeComposer->getFrameRects(1)));

        auto frame2Ref = frame1Ref;
        frame2Ref[FG_LAYER].mSwapCount++;
        frame2Ref[FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 128, 64 + 128};
        frame2Ref[FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 128.f, 128.f};
        EXPECT_TRUE(framesAreSame(frame2Ref, sFakeComposer->getFrameRects(2)));
    }

    void Test_LayerCrop() {
        // TODO: Add scaling to confirm that crop happens in buffer space?
        {
            TransactionScope ts(*sFakeComposer);
            Rect cropRect(16, 16, 32, 32);
            ts.setCrop_legacy(mFGSurfaceControl, cropRect);
        }
        ASSERT_EQ(2, sFakeComposer->getFrameCount());

        auto referenceFrame = mBaseFrame;
        referenceFrame[FG_LAYER].mSourceCrop = hwc_frect_t{16.f, 16.f, 32.f, 32.f};
        referenceFrame[FG_LAYER].mDisplayFrame = hwc_rect_t{64 + 16, 64 + 16, 64 + 32, 64 + 32};
        EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
    }

    void Test_LayerSetLayer() {
        {
            TransactionScope ts(*sFakeComposer);
            ts.setLayer(mFGSurfaceControl, INT_MAX - 3);
        }
        ASSERT_EQ(2, sFakeComposer->getFrameCount());

        // The layers will switch order, but both are rendered because the background layer is
        // transparent (RGBA8888).
        std::vector<RenderState> referenceFrame(2);
        referenceFrame[0] = mBaseFrame[FG_LAYER];
        referenceFrame[1] = mBaseFrame[BG_LAYER];
        EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
    }

    void Test_LayerSetLayerOpaque() {
        {
            TransactionScope ts(*sFakeComposer);
            ts.setLayer(mFGSurfaceControl, INT_MAX - 3);
            ts.setFlags(mBGSurfaceControl, layer_state_t::eLayerOpaque,
                        layer_state_t::eLayerOpaque);
        }
        ASSERT_EQ(2, sFakeComposer->getFrameCount());

        // The former foreground layer is now covered with opaque layer - it should have disappeared
        std::vector<RenderState> referenceFrame(1);
        referenceFrame[BG_LAYER] = mBaseFrame[BG_LAYER];
        EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
    }

    void Test_SetLayerStack() {
        ALOGD("TransactionTest::SetLayerStack");
        {
            TransactionScope ts(*sFakeComposer);
            ts.setLayerStack(mFGSurfaceControl, 1);
        }

        // Foreground layer should have disappeared.
        ASSERT_EQ(2, sFakeComposer->getFrameCount());
        std::vector<RenderState> refFrame(1);
        refFrame[BG_LAYER] = mBaseFrame[BG_LAYER];
        EXPECT_TRUE(framesAreSame(refFrame, sFakeComposer->getLatestFrame()));
    }

    void Test_LayerShowHide() {
        ALOGD("TransactionTest::LayerShowHide");
        {
            TransactionScope ts(*sFakeComposer);
            ts.hide(mFGSurfaceControl);
        }

        // Foreground layer should have disappeared.
        ASSERT_EQ(2, sFakeComposer->getFrameCount());
        std::vector<RenderState> refFrame(1);
        refFrame[BG_LAYER] = mBaseFrame[BG_LAYER];
        EXPECT_TRUE(framesAreSame(refFrame, sFakeComposer->getLatestFrame()));

        {
            TransactionScope ts(*sFakeComposer);
            ts.show(mFGSurfaceControl);
        }

        // Foreground layer should be back
        ASSERT_EQ(3, sFakeComposer->getFrameCount());
        EXPECT_TRUE(framesAreSame(mBaseFrame, sFakeComposer->getLatestFrame()));
    }

    void Test_LayerSetAlpha() {
        {
            TransactionScope ts(*sFakeComposer);
            ts.setAlpha(mFGSurfaceControl, 0.75f);
        }

        ASSERT_EQ(2, sFakeComposer->getFrameCount());
        auto referenceFrame = mBaseFrame;
        referenceFrame[FG_LAYER].mPlaneAlpha = 0.75f;
        EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
    }

    void Test_LayerSetFlags() {
        {
            TransactionScope ts(*sFakeComposer);
            ts.setFlags(mFGSurfaceControl, layer_state_t::eLayerHidden,
                        layer_state_t::eLayerHidden);
        }

        // Foreground layer should have disappeared.
        ASSERT_EQ(2, sFakeComposer->getFrameCount());
        std::vector<RenderState> refFrame(1);
        refFrame[BG_LAYER] = mBaseFrame[BG_LAYER];
        EXPECT_TRUE(framesAreSame(refFrame, sFakeComposer->getLatestFrame()));
    }

    void Test_LayerSetMatrix() {
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
        constexpr int TEST_COUNT = sizeof(MATRIX_TESTS) / sizeof(matrixTestData);

        for (int i = 0; i < TEST_COUNT; i++) {
            // TODO: How to leverage the HWC2 stringifiers?
            const matrixTestData& xform = MATRIX_TESTS[i];
            SCOPED_TRACE(i);
            {
                TransactionScope ts(*sFakeComposer);
                ts.setMatrix(mFGSurfaceControl, xform.matrix[0], xform.matrix[1], xform.matrix[2],
                             xform.matrix[3]);
            }

            auto referenceFrame = mBaseFrame;
            referenceFrame[FG_LAYER].mTransform = xform.expectedTransform;
            referenceFrame[FG_LAYER].mDisplayFrame = xform.expectedDisplayFrame;

            EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));
        }
    }

    void Test_DeferredTransaction() {
        // Synchronization surface
        constexpr static int SYNC_LAYER = 2;
        auto syncSurfaceControl = mComposerClient->createSurface(String8("Sync Test Surface"), 1, 1,
                                                                 PIXEL_FORMAT_RGBA_8888, 0);
        ASSERT_TRUE(syncSurfaceControl != nullptr);
        ASSERT_TRUE(syncSurfaceControl->isValid());

        fillSurfaceRGBA8(syncSurfaceControl, DARK_GRAY);

        {
            TransactionScope ts(*sFakeComposer);
            ts.setLayer(syncSurfaceControl, INT32_MAX - 1);
            ts.setPosition(syncSurfaceControl, mDisplayWidth - 2, mDisplayHeight - 2);
            ts.show(syncSurfaceControl);
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
            TransactionScope ts(*sFakeComposer);
            ts.setAlpha(mFGSurfaceControl, 0.75);
            ts.deferTransactionUntil_legacy(mFGSurfaceControl, syncSurfaceControl,
                                            syncSurfaceControl->getSurface()->getNextFrameNumber());
        }
        EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

        {
            TransactionScope ts(*sFakeComposer);
            ts.setPosition(mFGSurfaceControl, 128, 128);
            ts.deferTransactionUntil_legacy(mFGSurfaceControl, syncSurfaceControl,
                                            syncSurfaceControl->getSurface()->getNextFrameNumber() +
                                                    1);
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
            TransactionScope ts(*sFakeComposer);
            ts.setAlpha(mFGSurfaceControl, 1.0);
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

    void Test_SetRelativeLayer() {
        constexpr int RELATIVE_LAYER = 2;
        auto relativeSurfaceControl = mComposerClient->createSurface(String8("Test Surface"), 64,
                                                                     64, PIXEL_FORMAT_RGBA_8888, 0);
        fillSurfaceRGBA8(relativeSurfaceControl, LIGHT_RED);

        // Now we stack the surface above the foreground surface and make sure it is visible.
        {
            TransactionScope ts(*sFakeComposer);
            ts.setPosition(relativeSurfaceControl, 64, 64);
            ts.show(relativeSurfaceControl);
            ts.setRelativeLayer(relativeSurfaceControl, mFGSurfaceControl, 1);
        }
        auto referenceFrame = mBaseFrame;
        // NOTE: All three layers will be visible as the surfaces are
        // transparent because of the RGBA format.
        referenceFrame.push_back(makeSimpleRect(64, 64, 64 + 64, 64 + 64));
        referenceFrame[RELATIVE_LAYER].mSwapCount = 1;
        EXPECT_TRUE(framesAreSame(referenceFrame, sFakeComposer->getLatestFrame()));

        // A call to setLayer will override a call to setRelativeLayer
        {
            TransactionScope ts(*sFakeComposer);
            ts.setLayer(relativeSurfaceControl, 0);
        }

        // Previous top layer will now appear at the bottom.
        auto referenceFrame2 = mBaseFrame;
        referenceFrame2.insert(referenceFrame2.begin(), referenceFrame[RELATIVE_LAYER]);
        EXPECT_EQ(3, sFakeComposer->getFrameCount());
        EXPECT_TRUE(framesAreSame(referenceFrame2, sFakeComposer->getLatestFrame()));
    }

    sp<SurfaceComposerClient> mComposerClient;
    sp<SurfaceControl> mBGSurfaceControl;
    sp<SurfaceControl> mFGSurfaceControl;
    std::vector<RenderState> mBaseFrame;
    uint32_t mDisplayWidth;
    uint32_t mDisplayHeight;

    static inline FakeComposerClient* sFakeComposer;
};

using TransactionTest_2_1 = TransactionTest<FakeComposerService_2_1>;

TEST_F(TransactionTest_2_1, DISABLED_LayerMove) {
    Test_LayerMove();
}

TEST_F(TransactionTest_2_1, DISABLED_LayerResize) {
    Test_LayerResize();
}

TEST_F(TransactionTest_2_1, DISABLED_LayerCrop) {
    Test_LayerCrop();
}

TEST_F(TransactionTest_2_1, DISABLED_LayerSetLayer) {
    Test_LayerSetLayer();
}

TEST_F(TransactionTest_2_1, DISABLED_LayerSetLayerOpaque) {
    Test_LayerSetLayerOpaque();
}

TEST_F(TransactionTest_2_1, DISABLED_SetLayerStack) {
    Test_SetLayerStack();
}

TEST_F(TransactionTest_2_1, DISABLED_LayerShowHide) {
    Test_LayerShowHide();
}

TEST_F(TransactionTest_2_1, DISABLED_LayerSetAlpha) {
    Test_LayerSetAlpha();
}

TEST_F(TransactionTest_2_1, DISABLED_LayerSetFlags) {
    Test_LayerSetFlags();
}

TEST_F(TransactionTest_2_1, DISABLED_LayerSetMatrix) {
    Test_LayerSetMatrix();
}

TEST_F(TransactionTest_2_1, DISABLED_DeferredTransaction) {
    Test_DeferredTransaction();
}

TEST_F(TransactionTest_2_1, DISABLED_SetRelativeLayer) {
    Test_SetRelativeLayer();
}

template <typename FakeComposerService>
class ChildLayerTest : public TransactionTest<FakeComposerService> {
    using Base = TransactionTest<FakeComposerService>;

protected:
    constexpr static int CHILD_LAYER = 2;

    void SetUp() override {
        Base::SetUp();
        mChild = Base::mComposerClient->createSurface(String8("Child surface"), 10, 10,
                                                      PIXEL_FORMAT_RGBA_8888, 0,
                                                      Base::mFGSurfaceControl->getHandle());
        fillSurfaceRGBA8(mChild, LIGHT_GRAY);

        Base::sFakeComposer->runVSyncAndWait();
        Base::mBaseFrame.push_back(makeSimpleRect(64, 64, 64 + 10, 64 + 10));
        Base::mBaseFrame[CHILD_LAYER].mSwapCount = 1;
        ASSERT_EQ(2, Base::sFakeComposer->getFrameCount());
        ASSERT_TRUE(framesAreSame(Base::mBaseFrame, Base::sFakeComposer->getLatestFrame()));
    }

    void TearDown() override {
        mChild = 0;
        Base::TearDown();
    }

    void Test_Positioning() {
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.show(mChild);
            ts.setPosition(mChild, 10, 10);
            // Move to the same position as in the original setup.
            ts.setPosition(Base::mFGSurfaceControl, 64, 64);
        }

        auto referenceFrame = Base::mBaseFrame;
        referenceFrame[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 64, 64 + 64};
        referenceFrame[CHILD_LAYER].mDisplayFrame =
                hwc_rect_t{64 + 10, 64 + 10, 64 + 10 + 10, 64 + 10 + 10};
        EXPECT_TRUE(framesAreSame(referenceFrame, Base::sFakeComposer->getLatestFrame()));

        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.setPosition(Base::mFGSurfaceControl, 0, 0);
        }

        auto referenceFrame2 = Base::mBaseFrame;
        referenceFrame2[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 0 + 64, 0 + 64};
        referenceFrame2[CHILD_LAYER].mDisplayFrame =
                hwc_rect_t{0 + 10, 0 + 10, 0 + 10 + 10, 0 + 10 + 10};
        EXPECT_TRUE(framesAreSame(referenceFrame2, Base::sFakeComposer->getLatestFrame()));
    }

    void Test_Cropping() {
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.show(mChild);
            ts.setPosition(mChild, 0, 0);
            ts.setPosition(Base::mFGSurfaceControl, 0, 0);
            ts.setCrop_legacy(Base::mFGSurfaceControl, Rect(0, 0, 5, 5));
        }
        // NOTE: The foreground surface would be occluded by the child
        // now, but is included in the stack because the child is
        // transparent.
        auto referenceFrame = Base::mBaseFrame;
        referenceFrame[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 0 + 5, 0 + 5};
        referenceFrame[Base::FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 5.f, 5.f};
        referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 0 + 5, 0 + 5};
        referenceFrame[CHILD_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 5.f, 5.f};
        EXPECT_TRUE(framesAreSame(referenceFrame, Base::sFakeComposer->getLatestFrame()));
    }

    void Test_Constraints() {
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.show(mChild);
            ts.setPosition(Base::mFGSurfaceControl, 0, 0);
            ts.setPosition(mChild, 63, 63);
        }
        auto referenceFrame = Base::mBaseFrame;
        referenceFrame[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 64, 64};
        referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{63, 63, 64, 64};
        referenceFrame[CHILD_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 1.f, 1.f};
        EXPECT_TRUE(framesAreSame(referenceFrame, Base::sFakeComposer->getLatestFrame()));
    }

    void Test_Scaling() {
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.setPosition(Base::mFGSurfaceControl, 0, 0);
        }
        auto referenceFrame = Base::mBaseFrame;
        referenceFrame[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 64, 64};
        referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 10, 10};
        EXPECT_TRUE(framesAreSame(referenceFrame, Base::sFakeComposer->getLatestFrame()));

        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.setMatrix(Base::mFGSurfaceControl, 2.0, 0, 0, 2.0);
        }

        auto referenceFrame2 = Base::mBaseFrame;
        referenceFrame2[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 128, 128};
        referenceFrame2[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 20, 20};
        EXPECT_TRUE(framesAreSame(referenceFrame2, Base::sFakeComposer->getLatestFrame()));
    }

    void Test_LayerAlpha() {
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.show(mChild);
            ts.setPosition(mChild, 0, 0);
            ts.setPosition(Base::mFGSurfaceControl, 0, 0);
            ts.setAlpha(mChild, 0.5);
        }

        auto referenceFrame = Base::mBaseFrame;
        referenceFrame[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 64, 64};
        referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 10, 10};
        referenceFrame[CHILD_LAYER].mPlaneAlpha = 0.5f;
        EXPECT_TRUE(framesAreSame(referenceFrame, Base::sFakeComposer->getLatestFrame()));

        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.setAlpha(Base::mFGSurfaceControl, 0.5);
        }

        auto referenceFrame2 = referenceFrame;
        referenceFrame2[Base::FG_LAYER].mPlaneAlpha = 0.5f;
        referenceFrame2[CHILD_LAYER].mPlaneAlpha = 0.25f;
        EXPECT_TRUE(framesAreSame(referenceFrame2, Base::sFakeComposer->getLatestFrame()));
    }

    void Test_ReparentChildren() {
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.show(mChild);
            ts.setPosition(mChild, 10, 10);
            ts.setPosition(Base::mFGSurfaceControl, 64, 64);
        }
        auto referenceFrame = Base::mBaseFrame;
        referenceFrame[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 64, 64 + 64};
        referenceFrame[CHILD_LAYER].mDisplayFrame =
                hwc_rect_t{64 + 10, 64 + 10, 64 + 10 + 10, 64 + 10 + 10};
        EXPECT_TRUE(framesAreSame(referenceFrame, Base::sFakeComposer->getLatestFrame()));

        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.reparentChildren(Base::mFGSurfaceControl, Base::mBGSurfaceControl);
        }

        auto referenceFrame2 = referenceFrame;
        referenceFrame2[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 64, 64 + 64};
        referenceFrame2[CHILD_LAYER].mDisplayFrame = hwc_rect_t{10, 10, 10 + 10, 10 + 10};
        EXPECT_TRUE(framesAreSame(referenceFrame2, Base::sFakeComposer->getLatestFrame()));
    }

    // Regression test for b/37673612
    void Test_ChildrenWithParentBufferTransform() {
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.show(mChild);
            ts.setPosition(mChild, 0, 0);
            ts.setPosition(Base::mFGSurfaceControl, 0, 0);
        }

        // We set things up as in b/37673612 so that there is a mismatch between the buffer size and
        // the WM specified state size.
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.setSize(Base::mFGSurfaceControl, 128, 64);
        }

        sp<Surface> s = Base::mFGSurfaceControl->getSurface();
        auto anw = static_cast<ANativeWindow*>(s.get());
        native_window_set_buffers_transform(anw, NATIVE_WINDOW_TRANSFORM_ROT_90);
        native_window_set_buffers_dimensions(anw, 64, 128);
        fillSurfaceRGBA8(Base::mFGSurfaceControl, RED);
        Base::sFakeComposer->runVSyncAndWait();

        // The child should still be in the same place and not have any strange scaling as in
        // b/37673612.
        auto referenceFrame = Base::mBaseFrame;
        referenceFrame[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 128, 64};
        referenceFrame[Base::FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 64.f, 128.f};
        referenceFrame[Base::FG_LAYER].mSwapCount++;
        referenceFrame[CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 10, 10};
        EXPECT_TRUE(framesAreSame(referenceFrame, Base::sFakeComposer->getLatestFrame()));
    }

    void Test_Bug36858924() {
        // Destroy the child layer
        mChild.clear();

        // Now recreate it as hidden
        mChild = Base::mComposerClient->createSurface(String8("Child surface"), 10, 10,
                                                      PIXEL_FORMAT_RGBA_8888,
                                                      ISurfaceComposerClient::eHidden,
                                                      Base::mFGSurfaceControl->getHandle());

        // Show the child layer in a deferred transaction
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.deferTransactionUntil_legacy(mChild, Base::mFGSurfaceControl,
                                            Base::mFGSurfaceControl->getSurface()
                                                    ->getNextFrameNumber());
            ts.show(mChild);
        }

        // Render the foreground surface a few times
        //
        // Prior to the bugfix for b/36858924, this would usually hang while trying to fill the
        // third frame because SurfaceFlinger would never process the deferred transaction and would
        // therefore never acquire/release the first buffer
        ALOGI("Filling 1");
        fillSurfaceRGBA8(Base::mFGSurfaceControl, GREEN);
        Base::sFakeComposer->runVSyncAndWait();
        ALOGI("Filling 2");
        fillSurfaceRGBA8(Base::mFGSurfaceControl, BLUE);
        Base::sFakeComposer->runVSyncAndWait();
        ALOGI("Filling 3");
        fillSurfaceRGBA8(Base::mFGSurfaceControl, RED);
        Base::sFakeComposer->runVSyncAndWait();
        ALOGI("Filling 4");
        fillSurfaceRGBA8(Base::mFGSurfaceControl, GREEN);
        Base::sFakeComposer->runVSyncAndWait();
    }

    sp<SurfaceControl> mChild;
};

using ChildLayerTest_2_1 = ChildLayerTest<FakeComposerService_2_1>;

TEST_F(ChildLayerTest_2_1, DISABLED_Positioning) {
    Test_Positioning();
}

TEST_F(ChildLayerTest_2_1, DISABLED_Cropping) {
    Test_Cropping();
}

TEST_F(ChildLayerTest_2_1, DISABLED_Constraints) {
    Test_Constraints();
}

TEST_F(ChildLayerTest_2_1, DISABLED_Scaling) {
    Test_Scaling();
}

TEST_F(ChildLayerTest_2_1, DISABLED_LayerAlpha) {
    Test_LayerAlpha();
}

TEST_F(ChildLayerTest_2_1, DISABLED_ReparentChildren) {
    Test_ReparentChildren();
}

// Regression test for b/37673612
TEST_F(ChildLayerTest_2_1, DISABLED_ChildrenWithParentBufferTransform) {
    Test_ChildrenWithParentBufferTransform();
}

TEST_F(ChildLayerTest_2_1, DISABLED_Bug36858924) {
    Test_Bug36858924();
}

template <typename FakeComposerService>
class ChildColorLayerTest : public ChildLayerTest<FakeComposerService> {
    using Base = ChildLayerTest<FakeComposerService>;

protected:
    void SetUp() override {
        Base::SetUp();
        Base::mChild =
                Base::mComposerClient->createSurface(String8("Child surface"), 0, 0,
                                                     PIXEL_FORMAT_RGBA_8888,
                                                     ISurfaceComposerClient::eFXSurfaceEffect,
                                                     Base::mFGSurfaceControl->getHandle());
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.setColor(Base::mChild,
                        {LIGHT_GRAY.r / 255.0f, LIGHT_GRAY.g / 255.0f, LIGHT_GRAY.b / 255.0f});
            ts.setCrop_legacy(Base::mChild, Rect(0, 0, 10, 10));
        }

        Base::sFakeComposer->runVSyncAndWait();
        Base::mBaseFrame.push_back(makeSimpleRect(64, 64, 64 + 10, 64 + 10));
        Base::mBaseFrame[Base::CHILD_LAYER].mSourceCrop = hwc_frect_t{0.0f, 0.0f, 0.0f, 0.0f};
        Base::mBaseFrame[Base::CHILD_LAYER].mSwapCount = 0;
        ASSERT_EQ(2, Base::sFakeComposer->getFrameCount());
        ASSERT_TRUE(framesAreSame(Base::mBaseFrame, Base::sFakeComposer->getLatestFrame()));
    }

    void Test_LayerAlpha() {
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.show(Base::mChild);
            ts.setPosition(Base::mChild, 0, 0);
            ts.setPosition(Base::mFGSurfaceControl, 0, 0);
            ts.setAlpha(Base::mChild, 0.5);
        }

        auto referenceFrame = Base::mBaseFrame;
        referenceFrame[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 64, 64};
        referenceFrame[Base::CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 10, 10};
        referenceFrame[Base::CHILD_LAYER].mPlaneAlpha = 0.5f;
        EXPECT_TRUE(framesAreSame(referenceFrame, Base::sFakeComposer->getLatestFrame()));

        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.setAlpha(Base::mFGSurfaceControl, 0.5);
        }

        auto referenceFrame2 = referenceFrame;
        referenceFrame2[Base::FG_LAYER].mPlaneAlpha = 0.5f;
        referenceFrame2[Base::CHILD_LAYER].mPlaneAlpha = 0.25f;
        EXPECT_TRUE(framesAreSame(referenceFrame2, Base::sFakeComposer->getLatestFrame()));
    }

    void Test_LayerZeroAlpha() {
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.show(Base::mChild);
            ts.setPosition(Base::mChild, 0, 0);
            ts.setPosition(Base::mFGSurfaceControl, 0, 0);
            ts.setAlpha(Base::mChild, 0.5);
        }

        auto referenceFrame = Base::mBaseFrame;
        referenceFrame[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 64, 64};
        referenceFrame[Base::CHILD_LAYER].mDisplayFrame = hwc_rect_t{0, 0, 10, 10};
        referenceFrame[Base::CHILD_LAYER].mPlaneAlpha = 0.5f;
        EXPECT_TRUE(framesAreSame(referenceFrame, Base::sFakeComposer->getLatestFrame()));

        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.setAlpha(Base::mFGSurfaceControl, 0.0f);
        }

        std::vector<RenderState> refFrame(1);
        refFrame[Base::BG_LAYER] = Base::mBaseFrame[Base::BG_LAYER];

        EXPECT_TRUE(framesAreSame(refFrame, Base::sFakeComposer->getLatestFrame()));
    }
};

using ChildColorLayerTest_2_1 = ChildColorLayerTest<FakeComposerService_2_1>;

TEST_F(ChildColorLayerTest_2_1, DISABLED_LayerAlpha) {
    Test_LayerAlpha();
}

TEST_F(ChildColorLayerTest_2_1, DISABLED_LayerZeroAlpha) {
    Test_LayerZeroAlpha();
}

template <typename FakeComposerService>
class LatchingTest : public TransactionTest<FakeComposerService> {
    using Base = TransactionTest<FakeComposerService>;

protected:
    void lockAndFillFGBuffer() { fillSurfaceRGBA8(Base::mFGSurfaceControl, RED, false); }

    void unlockFGBuffer() {
        sp<Surface> s = Base::mFGSurfaceControl->getSurface();
        ASSERT_EQ(NO_ERROR, s->unlockAndPost());
        Base::sFakeComposer->runVSyncAndWait();
    }

    void completeFGResize() {
        fillSurfaceRGBA8(Base::mFGSurfaceControl, RED);
        Base::sFakeComposer->runVSyncAndWait();
    }
    void restoreInitialState() {
        TransactionScope ts(*Base::sFakeComposer);
        ts.setSize(Base::mFGSurfaceControl, 64, 64);
        ts.setPosition(Base::mFGSurfaceControl, 64, 64);
        ts.setCrop_legacy(Base::mFGSurfaceControl, Rect(0, 0, 64, 64));
    }

    void Test_SurfacePositionLatching() {
        // By default position can be updated even while
        // a resize is pending.
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.setSize(Base::mFGSurfaceControl, 32, 32);
            ts.setPosition(Base::mFGSurfaceControl, 100, 100);
        }

        // The size should not have updated as we have not provided a new buffer.
        auto referenceFrame1 = Base::mBaseFrame;
        referenceFrame1[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{100, 100, 100 + 64, 100 + 64};
        EXPECT_TRUE(framesAreSame(referenceFrame1, Base::sFakeComposer->getLatestFrame()));

        restoreInitialState();

        completeFGResize();

        auto referenceFrame2 = Base::mBaseFrame;
        referenceFrame2[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{100, 100, 100 + 32, 100 + 32};
        referenceFrame2[Base::FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 32.f, 32.f};
        referenceFrame2[Base::FG_LAYER].mSwapCount++;
        EXPECT_TRUE(framesAreSame(referenceFrame2, Base::sFakeComposer->getLatestFrame()));
    }

    void Test_CropLatching() {
        // Normally the crop applies immediately even while a resize is pending.
        {
            TransactionScope ts(*Base::sFakeComposer);
            ts.setSize(Base::mFGSurfaceControl, 128, 128);
            ts.setCrop_legacy(Base::mFGSurfaceControl, Rect(0, 0, 63, 63));
        }

        auto referenceFrame1 = Base::mBaseFrame;
        referenceFrame1[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 63, 64 + 63};
        referenceFrame1[Base::FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 63.f, 63.f};
        EXPECT_TRUE(framesAreSame(referenceFrame1, Base::sFakeComposer->getLatestFrame()));

        restoreInitialState();

        completeFGResize();

        auto referenceFrame2 = Base::mBaseFrame;
        referenceFrame2[Base::FG_LAYER].mDisplayFrame = hwc_rect_t{64, 64, 64 + 63, 64 + 63};
        referenceFrame2[Base::FG_LAYER].mSourceCrop = hwc_frect_t{0.f, 0.f, 63.f, 63.f};
        referenceFrame2[Base::FG_LAYER].mSwapCount++;
        EXPECT_TRUE(framesAreSame(referenceFrame2, Base::sFakeComposer->getLatestFrame()));
    }
};

using LatchingTest_2_1 = LatchingTest<FakeComposerService_2_1>;

TEST_F(LatchingTest_2_1, DISABLED_SurfacePositionLatching) {
    Test_SurfacePositionLatching();
}

TEST_F(LatchingTest_2_1, DISABLED_CropLatching) {
    Test_CropLatching();
}

} // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    auto* fakeEnvironment = new sftest::FakeHwcEnvironment;
    ::testing::AddGlobalTestEnvironment(fakeEnvironment);
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion -Wextra"
