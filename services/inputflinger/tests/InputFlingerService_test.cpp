/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <BnInputFlingerQuery.h>
#include <IInputFlingerQuery.h>

#include <android/os/BnInputFlinger.h>
#include <android/os/BnSetInputWindowsListener.h>
#include <android/os/IInputFlinger.h>
#include <android/os/ISetInputWindowsListener.h>

#include <binder/Binder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>

#include <input/Input.h>
#include <input/InputTransport.h>
#include <input/InputWindow.h>

#include <gtest/gtest.h>
#include <inttypes.h>
#include <linux/uinput.h>
#include <log/log.h>
#include <ui/Rect.h>
#include <ui/Region.h>
#include <chrono>
#include <thread>
#include <unordered_map>

#define TAG "InputFlingerServiceTest"

using android::os::BnInputFlinger;
using android::os::BnSetInputWindowsListener;
using android::os::IInputFlinger;
using android::os::ISetInputWindowsListener;

using std::chrono_literals::operator""ms;
using std::chrono_literals::operator""s;

namespace android {

static const sp<IBinder> TestInfoToken = new BBinder();
static const sp<IBinder> FocusedTestInfoToken = new BBinder();
static constexpr int32_t TestInfoId = 1;
static const std::string TestInfoName = "InputFlingerServiceTestInputWindowInfo";
static constexpr Flags<InputWindowInfo::Flag> TestInfoFlags = InputWindowInfo::Flag::NOT_FOCUSABLE;
static constexpr InputWindowInfo::Type TestInfoType = InputWindowInfo::Type::INPUT_METHOD;
static constexpr std::chrono::duration TestInfoDispatchingTimeout = 2532ms;
static constexpr int32_t TestInfoFrameLeft = 93;
static constexpr int32_t TestInfoFrameTop = 34;
static constexpr int32_t TestInfoFrameRight = 16;
static constexpr int32_t TestInfoFrameBottom = 19;
static constexpr int32_t TestInfoSurfaceInset = 17;
static constexpr float TestInfoGlobalScaleFactor = 0.3;
static constexpr float TestInfoWindowXScale = 0.4;
static constexpr float TestInfoWindowYScale = 0.5;
static const Rect TestInfoTouchableRegionRect = {100 /* left */, 150 /* top */, 400 /* right */,
                                                 450 /* bottom */};
static const Region TestInfoTouchableRegion(TestInfoTouchableRegionRect);
static constexpr bool TestInfoVisible = false;
static constexpr bool TestInfoTrustedOverlay = true;
static constexpr bool TestInfoFocusable = false;
static constexpr bool TestInfoHasWallpaper = false;
static constexpr bool TestInfoPaused = false;
static constexpr int32_t TestInfoOwnerPid = 19;
static constexpr int32_t TestInfoOwnerUid = 24;
static constexpr InputWindowInfo::Feature TestInfoInputFeatures =
        InputWindowInfo::Feature::NO_INPUT_CHANNEL;
static constexpr int32_t TestInfoDisplayId = 34;
static constexpr int32_t TestInfoPortalToDisplayId = 2;
static constexpr bool TestInfoReplaceTouchableRegionWithCrop = true;
static const sp<IBinder> TestInfoTouchableRegionCropHandle = new BBinder();

static const std::string TestAppInfoName = "InputFlingerServiceTestInputApplicationInfo";
static const sp<IBinder> TestAppInfoToken = new BBinder();
static constexpr std::chrono::duration TestAppInfoDispatchingTimeout = 12345678ms;

static const String16 kTestServiceName = String16("InputFlingerService");
static const String16 kQueryServiceName = String16("InputFlingerQueryService");

struct SetInputWindowsListener;
// --- InputFlingerServiceTest ---
class InputFlingerServiceTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

protected:
    void InitializeInputFlinger();
    void setInputWindowsByInfos(const std::vector<InputWindowInfo>& infos);
    void setFocusedWindow(const sp<IBinder> token, const sp<IBinder> focusedToken,
                          nsecs_t timestampNanos);

    void setInputWindowsFinished();
    void verifyInputWindowInfo(const InputWindowInfo& info) const;
    InputWindowInfo& getInfo() const { return const_cast<InputWindowInfo&>(mInfo); }

    sp<IInputFlinger> mService;
    sp<IInputFlingerQuery> mQuery;

private:
    sp<SetInputWindowsListener> mSetInputWindowsListener;
    std::unique_ptr<InputChannel> mServerChannel, mClientChannel;
    InputWindowInfo mInfo;
    std::mutex mLock;
    std::condition_variable mSetInputWindowsFinishedCondition;
};

struct SetInputWindowsListener : BnSetInputWindowsListener {
    explicit SetInputWindowsListener(std::function<void()> cbFunc) : mCbFunc(cbFunc) {}

    binder::Status onSetInputWindowsFinished() override;

    std::function<void()> mCbFunc;
};

class TestInputManager : public BnInputFlinger {
protected:
    virtual ~TestInputManager(){};

public:
    TestInputManager(){};

    binder::Status getInputWindows(std::vector<::android::InputWindowInfo>* inputHandles);
    binder::Status getInputChannels(std::vector<::android::InputChannel>* channels);
    binder::Status getLastFocusRequest(FocusRequest*);

    status_t dump(int fd, const Vector<String16>& args) override;

    binder::Status setInputWindows(
            const std::vector<InputWindowInfo>& handles,
            const sp<ISetInputWindowsListener>& setInputWindowsListener) override;

    binder::Status createInputChannel(const std::string& name, InputChannel* outChannel) override;
    binder::Status removeInputChannel(const sp<IBinder>& connectionToken) override;
    binder::Status setFocusedWindow(const FocusRequest&) override;

    void reset();

private:
    mutable Mutex mLock;
    std::unordered_map<int32_t, std::vector<sp<InputWindowHandle>>> mHandlesPerDisplay;
    std::vector<std::shared_ptr<InputChannel>> mInputChannels;
    FocusRequest mFocusRequest;
};

class TestInputQuery : public BnInputFlingerQuery {
public:
    TestInputQuery(sp<android::TestInputManager> manager) : mManager(manager){};
    binder::Status getInputWindows(std::vector<::android::InputWindowInfo>* inputHandles) override;
    binder::Status getInputChannels(std::vector<::android::InputChannel>* channels) override;
    binder::Status getLastFocusRequest(FocusRequest*) override;
    binder::Status resetInputManager() override;

private:
    sp<android::TestInputManager> mManager;
};

binder::Status TestInputQuery::getInputWindows(
        std::vector<::android::InputWindowInfo>* inputHandles) {
    return mManager->getInputWindows(inputHandles);
}

binder::Status TestInputQuery::getInputChannels(std::vector<::android::InputChannel>* channels) {
    return mManager->getInputChannels(channels);
}

binder::Status TestInputQuery::getLastFocusRequest(FocusRequest* request) {
    return mManager->getLastFocusRequest(request);
}

binder::Status TestInputQuery::resetInputManager() {
    mManager->reset();
    return binder::Status::ok();
}

binder::Status SetInputWindowsListener::onSetInputWindowsFinished() {
    if (mCbFunc != nullptr) {
        mCbFunc();
    }
    return binder::Status::ok();
}

binder::Status TestInputManager::setInputWindows(
        const std::vector<InputWindowInfo>& infos,
        const sp<ISetInputWindowsListener>& setInputWindowsListener) {
    AutoMutex _l(mLock);

    for (const auto& info : infos) {
        mHandlesPerDisplay.emplace(info.displayId, std::vector<sp<InputWindowHandle>>());
        mHandlesPerDisplay[info.displayId].push_back(new InputWindowHandle(info));
    }
    if (setInputWindowsListener) {
        setInputWindowsListener->onSetInputWindowsFinished();
    }
    return binder::Status::ok();
}

binder::Status TestInputManager::createInputChannel(const std::string& name,
                                                    InputChannel* outChannel) {
    AutoMutex _l(mLock);
    std::unique_ptr<InputChannel> serverChannel;
    std::unique_ptr<InputChannel> clientChannel;
    InputChannel::openInputChannelPair(name, serverChannel, clientChannel);

    clientChannel->copyTo(*outChannel);

    mInputChannels.emplace_back(std::move(serverChannel));

    return binder::Status::ok();
}

binder::Status TestInputManager::removeInputChannel(const sp<IBinder>& connectionToken) {
    AutoMutex _l(mLock);

    auto it = std::find_if(mInputChannels.begin(), mInputChannels.end(),
                           [&](std::shared_ptr<InputChannel>& c) {
                               return c->getConnectionToken() == connectionToken;
                           });
    if (it != mInputChannels.end()) {
        mInputChannels.erase(it);
    }

    return binder::Status::ok();
}

status_t TestInputManager::dump(int fd, const Vector<String16>& args) {
    std::string dump;

    dump += " InputFlinger dump\n";

    ::write(fd, dump.c_str(), dump.size());
    return NO_ERROR;
}

binder::Status TestInputManager::getInputWindows(
        std::vector<::android::InputWindowInfo>* inputInfos) {
    for (auto& [displayId, inputHandles] : mHandlesPerDisplay) {
        for (auto& inputHandle : inputHandles) {
            inputInfos->push_back(*inputHandle->getInfo());
        }
    }
    return binder::Status::ok();
}

binder::Status TestInputManager::getInputChannels(std::vector<::android::InputChannel>* channels) {
    channels->clear();
    for (std::shared_ptr<InputChannel>& channel : mInputChannels) {
        channels->push_back(*channel);
    }
    return binder::Status::ok();
}

binder::Status TestInputManager::getLastFocusRequest(FocusRequest* request) {
    *request = mFocusRequest;
    return binder::Status::ok();
}

binder::Status TestInputManager::setFocusedWindow(const FocusRequest& request) {
    mFocusRequest = request;
    return binder::Status::ok();
}

void TestInputManager::reset() {
    mHandlesPerDisplay.clear();
    mInputChannels.clear();
    mFocusRequest = FocusRequest();
}

void InputFlingerServiceTest::SetUp() {
    mSetInputWindowsListener = new SetInputWindowsListener([&]() {
        std::unique_lock<std::mutex> lock(mLock);
        mSetInputWindowsFinishedCondition.notify_all();
    });
    InputChannel::openInputChannelPair("testchannels", mServerChannel, mClientChannel);

    mInfo.token = TestInfoToken;
    mInfo.id = TestInfoId;
    mInfo.name = TestInfoName;
    mInfo.flags = TestInfoFlags;
    mInfo.type = TestInfoType;
    mInfo.dispatchingTimeout = TestInfoDispatchingTimeout;
    mInfo.frameLeft = TestInfoFrameLeft;
    mInfo.frameTop = TestInfoFrameTop;
    mInfo.frameRight = TestInfoFrameRight;
    mInfo.frameBottom = TestInfoFrameBottom;
    mInfo.surfaceInset = TestInfoSurfaceInset;
    mInfo.globalScaleFactor = TestInfoGlobalScaleFactor;
    mInfo.transform.set({TestInfoWindowXScale, 0, TestInfoFrameLeft, 0, TestInfoWindowYScale,
                         TestInfoFrameTop, 0, 0, 1});
    mInfo.touchableRegion = TestInfoTouchableRegion;
    mInfo.visible = TestInfoVisible;
    mInfo.trustedOverlay = TestInfoTrustedOverlay;
    mInfo.focusable = TestInfoFocusable;

    mInfo.hasWallpaper = TestInfoHasWallpaper;
    mInfo.paused = TestInfoPaused;
    mInfo.ownerPid = TestInfoOwnerPid;
    mInfo.ownerUid = TestInfoOwnerUid;
    mInfo.inputFeatures = TestInfoInputFeatures;
    mInfo.displayId = TestInfoDisplayId;
    mInfo.portalToDisplayId = TestInfoPortalToDisplayId;
    mInfo.replaceTouchableRegionWithCrop = TestInfoReplaceTouchableRegionWithCrop;
    mInfo.touchableRegionCropHandle = TestInfoTouchableRegionCropHandle;

    mInfo.applicationInfo.name = TestAppInfoName;
    mInfo.applicationInfo.token = TestAppInfoToken;
    mInfo.applicationInfo.dispatchingTimeoutMillis =
            std::chrono::duration_cast<std::chrono::milliseconds>(TestAppInfoDispatchingTimeout)
                    .count();

    InitializeInputFlinger();
}

void InputFlingerServiceTest::TearDown() {
    mQuery->resetInputManager();
}

void InputFlingerServiceTest::verifyInputWindowInfo(const InputWindowInfo& info) const {
    EXPECT_EQ(mInfo, info);
}

void InputFlingerServiceTest::InitializeInputFlinger() {
    sp<IBinder> input(defaultServiceManager()->waitForService(kTestServiceName));
    ASSERT_TRUE(input != nullptr);
    mService = interface_cast<IInputFlinger>(input);

    input = defaultServiceManager()->waitForService(kQueryServiceName);
    ASSERT_TRUE(input != nullptr);
    mQuery = interface_cast<IInputFlingerQuery>(input);
}

void InputFlingerServiceTest::setInputWindowsByInfos(const std::vector<InputWindowInfo>& infos) {
    std::unique_lock<std::mutex> lock(mLock);
    mService->setInputWindows(infos, mSetInputWindowsListener);
    // Verify listener call
    EXPECT_NE(mSetInputWindowsFinishedCondition.wait_for(lock, 1s), std::cv_status::timeout);
}

void InputFlingerServiceTest::setFocusedWindow(const sp<IBinder> token,
                                               const sp<IBinder> focusedToken,
                                               nsecs_t timestampNanos) {
    FocusRequest request;
    request.token = TestInfoToken;
    request.focusedToken = focusedToken;
    request.timestamp = timestampNanos;
    mService->setFocusedWindow(request);
    // call set input windows and wait for the callback to drain the queue.
    setInputWindowsByInfos(std::vector<InputWindowInfo>());
}

/**
 *  Test InputFlinger service interface SetInputWindows
 */
TEST_F(InputFlingerServiceTest, InputWindow_SetInputWindows) {
    std::vector<InputWindowInfo> infos = {getInfo()};
    setInputWindowsByInfos(infos);

    // Verify input windows from service
    std::vector<::android::InputWindowInfo> windowInfos;
    mQuery->getInputWindows(&windowInfos);
    for (const ::android::InputWindowInfo& windowInfo : windowInfos) {
        verifyInputWindowInfo(windowInfo);
    }
}

/**
 *  Test InputFlinger service interface createInputChannel
 */
TEST_F(InputFlingerServiceTest, CreateInputChannelReturnsUnblockedFd) {
    // Test that the unblocked file descriptor flag is kept across processes over binder
    // transactions.

    InputChannel channel;
    ASSERT_TRUE(mService->createInputChannel("testchannels", &channel).isOk());

    const base::unique_fd& fd = channel.getFd();
    ASSERT_TRUE(fd.ok());

    const int result = fcntl(fd, F_GETFL);
    EXPECT_NE(result, -1);
    EXPECT_EQ(result & O_NONBLOCK, O_NONBLOCK);
}

TEST_F(InputFlingerServiceTest, InputWindow_CreateInputChannel) {
    InputChannel channel;
    ASSERT_TRUE(mService->createInputChannel("testchannels", &channel).isOk());

    std::vector<::android::InputChannel> channels;
    mQuery->getInputChannels(&channels);
    ASSERT_EQ(channels.size(), 1UL);
    EXPECT_EQ(channels[0].getConnectionToken(), channel.getConnectionToken());

    mService->removeInputChannel(channel.getConnectionToken());
    mQuery->getInputChannels(&channels);
    EXPECT_EQ(channels.size(), 0UL);
}

TEST_F(InputFlingerServiceTest, InputWindow_setFocusedWindow) {
    nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
    setFocusedWindow(TestInfoToken, nullptr /* focusedToken */, now);

    FocusRequest request;
    mQuery->getLastFocusRequest(&request);

    EXPECT_EQ(request.token, TestInfoToken);
    EXPECT_EQ(request.focusedToken, nullptr);
    EXPECT_EQ(request.timestamp, now);
}

TEST_F(InputFlingerServiceTest, InputWindow_setFocusedWindowWithFocusedToken) {
    nsecs_t now = systemTime(SYSTEM_TIME_MONOTONIC);
    setFocusedWindow(TestInfoToken, FocusedTestInfoToken, now);

    FocusRequest request;
    mQuery->getLastFocusRequest(&request);

    EXPECT_EQ(request.token, TestInfoToken);
    EXPECT_EQ(request.focusedToken, FocusedTestInfoToken);
    EXPECT_EQ(request.timestamp, now);
}

} // namespace android

int main(int argc, char** argv) {
    pid_t forkPid = fork();

    if (forkPid == 0) {
        // Server process
        android::sp<android::TestInputManager> manager = new android::TestInputManager();
        android::sp<android::TestInputQuery> query = new android::TestInputQuery(manager);

        android::defaultServiceManager()->addService(android::kTestServiceName, manager,
                                                     false /*allowIsolated*/);
        android::defaultServiceManager()->addService(android::kQueryServiceName, query,
                                                     false /*allowIsolated*/);
        android::ProcessState::self()->startThreadPool();
        android::IPCThreadState::self()->joinThreadPool();
    } else {
        android::ProcessState::self()->startThreadPool();
        ::testing::InitGoogleTest(&argc, argv);
        int result = RUN_ALL_TESTS();
        kill(forkPid, SIGKILL);
        return result;
    }
    return 0;
}
