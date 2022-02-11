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
#include <android/os/IInputFlinger.h>

#include <binder/Binder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>

#include <input/Input.h>
#include <input/InputTransport.h>

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

using android::gui::FocusRequest;
using android::os::BnInputFlinger;
using android::os::IInputFlinger;

using std::chrono_literals::operator""ms;
using std::chrono_literals::operator""s;

namespace android {

static const String16 kTestServiceName = String16("InputFlingerService");
static const String16 kQueryServiceName = String16("InputFlingerQueryService");

// --- InputFlingerServiceTest ---
class InputFlingerServiceTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

protected:
    void InitializeInputFlinger();

    sp<IInputFlinger> mService;
    sp<IInputFlingerQuery> mQuery;

private:
    std::unique_ptr<InputChannel> mServerChannel, mClientChannel;
    std::mutex mLock;
};


class TestInputManager : public BnInputFlinger {
protected:
    virtual ~TestInputManager(){};

public:
    TestInputManager(){};

    binder::Status getInputChannels(std::vector<::android::InputChannel>* channels);

    status_t dump(int fd, const Vector<String16>& args) override;

    binder::Status createInputChannel(const std::string& name, InputChannel* outChannel) override;
    binder::Status removeInputChannel(const sp<IBinder>& connectionToken) override;
    binder::Status setFocusedWindow(const FocusRequest&) override;

    void reset();

private:
    mutable Mutex mLock;
    std::vector<std::shared_ptr<InputChannel>> mInputChannels;
};

class TestInputQuery : public BnInputFlingerQuery {
public:
    TestInputQuery(sp<android::TestInputManager> manager) : mManager(manager){};
    binder::Status getInputChannels(std::vector<::android::InputChannel>* channels) override;
    binder::Status resetInputManager() override;

private:
    sp<android::TestInputManager> mManager;
};

binder::Status TestInputQuery::getInputChannels(std::vector<::android::InputChannel>* channels) {
    return mManager->getInputChannels(channels);
}

binder::Status TestInputQuery::resetInputManager() {
    mManager->reset();
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

binder::Status TestInputManager::getInputChannels(std::vector<::android::InputChannel>* channels) {
    channels->clear();
    for (std::shared_ptr<InputChannel>& channel : mInputChannels) {
        channels->push_back(*channel);
    }
    return binder::Status::ok();
}

binder::Status TestInputManager::setFocusedWindow(const FocusRequest& request) {
    return binder::Status::ok();
}

void TestInputManager::reset() {
    mInputChannels.clear();
}

void InputFlingerServiceTest::SetUp() {
    InputChannel::openInputChannelPair("testchannels", mServerChannel, mClientChannel);
    InitializeInputFlinger();
}

void InputFlingerServiceTest::TearDown() {
    mQuery->resetInputManager();
}

void InputFlingerServiceTest::InitializeInputFlinger() {
    sp<IBinder> input(defaultServiceManager()->waitForService(kTestServiceName));
    ASSERT_TRUE(input != nullptr);
    mService = interface_cast<IInputFlinger>(input);

    input = defaultServiceManager()->waitForService(kQueryServiceName);
    ASSERT_TRUE(input != nullptr);
    mQuery = interface_cast<IInputFlingerQuery>(input);
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

TEST_F(InputFlingerServiceTest, CreateInputChannel) {
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
