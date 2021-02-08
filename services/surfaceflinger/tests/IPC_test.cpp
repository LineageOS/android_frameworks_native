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

#include <binder/IInterface.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <gtest/gtest.h>
#include <gui/ISurfaceComposer.h>
#include <gui/LayerState.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <ui/DisplayMode.h>
#include <utils/String8.h>

#include <limits>

#include "BufferGenerator.h"
#include "utils/CallbackUtils.h"
#include "utils/ColorUtils.h"
#include "utils/TransactionUtils.h"

namespace android {

namespace test {

using Transaction = SurfaceComposerClient::Transaction;
using CallbackInfo = SurfaceComposerClient::CallbackInfo;
using TCLHash = SurfaceComposerClient::TCLHash;
using android::hardware::graphics::common::V1_1::BufferUsage;

class TransactionHelper : public Transaction {
public:
    size_t getNumListeners() { return mListenerCallbacks.size(); }

    std::unordered_map<sp<ITransactionCompletedListener>, CallbackInfo, TCLHash>
    getListenerCallbacks() {
        return mListenerCallbacks;
    }
};

class IPCTestUtils {
public:
    static void waitForCallback(CallbackHelper& helper, const ExpectedResult& expectedResult,
                                bool finalState = false);
    static status_t getBuffer(sp<GraphicBuffer>* outBuffer, sp<Fence>* outFence);
};

class IIPCTest : public IInterface {
public:
    DECLARE_META_INTERFACE(IPCTest)
    enum class Tag : uint32_t {
        SetDeathToken = IBinder::FIRST_CALL_TRANSACTION,
        InitClient,
        CreateTransaction,
        MergeAndApply,
        VerifyCallbacks,
        CleanUp,
        Last,
    };

    virtual status_t setDeathToken(sp<IBinder>& token) = 0;

    virtual status_t initClient() = 0;

    virtual status_t createTransaction(TransactionHelper* outTransaction, uint32_t width,
                                       uint32_t height) = 0;

    virtual status_t mergeAndApply(TransactionHelper transaction) = 0;

    virtual status_t verifyCallbacks() = 0;

    virtual status_t cleanUp() = 0;
};

class BpIPCTest : public SafeBpInterface<IIPCTest> {
public:
    explicit BpIPCTest(const sp<IBinder>& impl) : SafeBpInterface<IIPCTest>(impl, "BpIPCTest") {}

    status_t setDeathToken(sp<IBinder>& token) {
        return callRemote<decltype(&IIPCTest::setDeathToken)>(Tag::SetDeathToken, token);
    }

    status_t initClient() { return callRemote<decltype(&IIPCTest::initClient)>(Tag::InitClient); }

    status_t createTransaction(TransactionHelper* transaction, uint32_t width, uint32_t height) {
        return callRemote<decltype(&IIPCTest::createTransaction)>(Tag::CreateTransaction,
                                                                  transaction, width, height);
    }

    status_t mergeAndApply(TransactionHelper transaction) {
        return callRemote<decltype(&IIPCTest::mergeAndApply)>(Tag::MergeAndApply, transaction);
    }

    status_t verifyCallbacks() {
        return callRemote<decltype(&IIPCTest::verifyCallbacks)>(Tag::VerifyCallbacks);
    }

    status_t cleanUp() { return callRemote<decltype(&IIPCTest::cleanUp)>(Tag::CleanUp); }
};

IMPLEMENT_META_INTERFACE(IPCTest, "android.gfx.tests.IIPCTest")

class onTestDeath : public IBinder::DeathRecipient {
public:
    void binderDied(const wp<IBinder>& /*who*/) override {
        ALOGE("onTestDeath::binderDied, exiting");
        exit(0);
    }
};

sp<onTestDeath> getDeathToken() {
    static sp<onTestDeath> token = new onTestDeath;
    return token;
}

class BnIPCTest : public SafeBnInterface<IIPCTest> {
public:
    BnIPCTest() : SafeBnInterface("BnIPCTest") {}

    status_t setDeathToken(sp<IBinder>& token) override {
        return token->linkToDeath(getDeathToken());
    }

    status_t initClient() override {
        mClient = new SurfaceComposerClient;
        auto err = mClient->initCheck();
        return err;
    }

    status_t createTransaction(TransactionHelper* transaction, uint32_t width, uint32_t height) {
        if (transaction == nullptr) {
            ALOGE("Error in createTransaction: transaction is nullptr");
            return BAD_VALUE;
        }
        mSurfaceControl = mClient->createSurface(String8("parentProcessSurface"), 0, 0,
                                                 PIXEL_FORMAT_RGBA_8888,
                                                 ISurfaceComposerClient::eFXSurfaceBufferState,
                                                 /*parent*/ nullptr);
        sp<GraphicBuffer> gb;
        sp<Fence> fence;
        int err = IPCTestUtils::getBuffer(&gb, &fence);
        if (err != NO_ERROR) return err;

        TransactionUtils::fillGraphicBufferColor(gb,
                                                 {0, 0, static_cast<int32_t>(width),
                                                  static_cast<int32_t>(height)},
                                                 Color::RED);
        transaction->setLayerStack(mSurfaceControl, 0)
                .setLayer(mSurfaceControl, std::numeric_limits<int32_t>::max())
                .setFrame(mSurfaceControl, Rect(0, 0, width, height))
                .setBuffer(mSurfaceControl, gb)
                .setAcquireFence(mSurfaceControl, fence)
                .show(mSurfaceControl)
                .addTransactionCompletedCallback(mCallbackHelper.function,
                                                 mCallbackHelper.getContext());
        return NO_ERROR;
    }

    status_t mergeAndApply(TransactionHelper /*transaction*/) {
        // transaction.apply();
        return NO_ERROR;
    }

    status_t verifyCallbacks() {
        ExpectedResult expected;
        expected.addSurface(ExpectedResult::Transaction::PRESENTED, mSurfaceControl);
        EXPECT_NO_FATAL_FAILURE(IPCTestUtils::waitForCallback(mCallbackHelper, expected, true));
        return NO_ERROR;
    }

    status_t cleanUp() {
        if (mClient) mClient->dispose();
        mSurfaceControl = nullptr;
        IPCThreadState::self()->stopProcess();
        return NO_ERROR;
    }

    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                        uint32_t /*flags*/) override {
        EXPECT_GE(code, IBinder::FIRST_CALL_TRANSACTION);
        EXPECT_LT(code, static_cast<uint32_t>(IIPCTest::Tag::Last));
        switch (static_cast<IIPCTest::Tag>(code)) {
            case IIPCTest::Tag::SetDeathToken:
                return callLocal(data, reply, &IIPCTest::setDeathToken);
            case IIPCTest::Tag::InitClient:
                return callLocal(data, reply, &IIPCTest::initClient);
            case IIPCTest::Tag::CreateTransaction:
                return callLocal(data, reply, &IIPCTest::createTransaction);
            case IIPCTest::Tag::MergeAndApply:
                return callLocal(data, reply, &IIPCTest::mergeAndApply);
            case IIPCTest::Tag::VerifyCallbacks:
                return callLocal(data, reply, &IIPCTest::verifyCallbacks);
            case IIPCTest::Tag::CleanUp:
                return callLocal(data, reply, &IIPCTest::cleanUp);
            default:
                return UNKNOWN_ERROR;
        }
    }

private:
    sp<SurfaceComposerClient> mClient;
    sp<SurfaceControl> mSurfaceControl;
    CallbackHelper mCallbackHelper;
};

class IPCTest : public ::testing::Test {
public:
    IPCTest() : mDeathRecipient(new BBinder), mRemote(initRemoteService()) {
        ProcessState::self()->startThreadPool();
    }
    void SetUp() {
        mClient = new SurfaceComposerClient;
        ASSERT_EQ(NO_ERROR, mClient->initCheck());

        mPrimaryDisplay = mClient->getInternalDisplayToken();
        ui::DisplayMode mode;
        mClient->getActiveDisplayMode(mPrimaryDisplay, &mode);
        mDisplayWidth = mode.resolution.getWidth();
        mDisplayHeight = mode.resolution.getHeight();

        Transaction setupTransaction;
        setupTransaction.setDisplayLayerStack(mPrimaryDisplay, 0);
        setupTransaction.apply();
    }

protected:
    sp<IIPCTest> initRemoteService();

    sp<IBinder> mDeathRecipient;
    sp<IIPCTest> mRemote;
    sp<SurfaceComposerClient> mClient;
    sp<IBinder> mPrimaryDisplay;
    uint32_t mDisplayWidth;
    uint32_t mDisplayHeight;
    sp<SurfaceControl> sc;
};

status_t IPCTestUtils::getBuffer(sp<GraphicBuffer>* outBuffer, sp<Fence>* outFence) {
    static BufferGenerator bufferGenerator;
    return bufferGenerator.get(outBuffer, outFence);
}

void IPCTestUtils::waitForCallback(CallbackHelper& helper, const ExpectedResult& expectedResult,
                                   bool finalState) {
    CallbackData callbackData;
    ASSERT_NO_FATAL_FAILURE(helper.getCallbackData(&callbackData));
    EXPECT_NO_FATAL_FAILURE(expectedResult.verifyCallbackData(callbackData));

    if (finalState) {
        ASSERT_NO_FATAL_FAILURE(helper.verifyFinalState());
    }
}

sp<IIPCTest> IPCTest::initRemoteService() {
    static std::mutex mMutex;
    static sp<IIPCTest> remote;
    const String16 serviceName("IPCTest");

    std::unique_lock<decltype(mMutex)> lock;
    if (remote == nullptr) {
        pid_t forkPid = fork();
        EXPECT_NE(forkPid, -1);

        if (forkPid == 0) {
            sp<IIPCTest> nativeService = new BnIPCTest;
            if (!nativeService) {
                ALOGE("null service...");
            }
            status_t err = defaultServiceManager()->addService(serviceName,
                                                               IInterface::asBinder(nativeService));
            if (err != NO_ERROR) {
                ALOGE("failed to add service: %d", err);
            }
            ProcessState::self()->startThreadPool();
            IPCThreadState::self()->joinThreadPool();
            [&]() { exit(0); }();
        }
        sp<IBinder> binder = defaultServiceManager()->getService(serviceName);
        remote = interface_cast<IIPCTest>(binder);
        remote->setDeathToken(mDeathRecipient);
    }
    return remote;
}

TEST_F(IPCTest, MergeBasic) {
    CallbackHelper helper1;
    sc = mClient->createSurface(String8("parentProcessSurface"), 0, 0, PIXEL_FORMAT_RGBA_8888,
                                ISurfaceComposerClient::eFXSurfaceBufferState,
                                /*parent*/ nullptr);
    sp<GraphicBuffer> gb;
    sp<Fence> fence;
    int err = IPCTestUtils::getBuffer(&gb, &fence);
    ASSERT_EQ(NO_ERROR, err);
    TransactionUtils::fillGraphicBufferColor(gb,
                                             {0, 0, static_cast<int32_t>(mDisplayWidth),
                                              static_cast<int32_t>(mDisplayHeight)},
                                             Color::RED);

    Transaction transaction;
    transaction.setLayerStack(sc, 0)
            .setLayer(sc, std::numeric_limits<int32_t>::max() - 1)
            .setBuffer(sc, gb)
            .setAcquireFence(sc, fence)
            .show(sc)
            .addTransactionCompletedCallback(helper1.function, helper1.getContext());

    TransactionHelper remote;
    mRemote->initClient();
    mRemote->createTransaction(&remote, mDisplayWidth / 2, mDisplayHeight / 2);
    ASSERT_EQ(1, remote.getNumListeners());
    auto remoteListenerCallbacks = remote.getListenerCallbacks();
    auto remoteCallback = remoteListenerCallbacks.begin();
    auto remoteCallbackInfo = remoteCallback->second;
    auto remoteListenerScs = remoteCallbackInfo.surfaceControls;
    ASSERT_EQ(1, remoteCallbackInfo.callbackIds.size());
    ASSERT_EQ(1, remoteListenerScs.size());

    sp<SurfaceControl> remoteSc = *(remoteListenerScs.begin());
    transaction.merge(std::move(remote));
    transaction.apply();

    sleep(1);
    ExpectedResult expected;
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, sc);
    expected.addSurface(ExpectedResult::Transaction::PRESENTED, remoteSc);
    EXPECT_NO_FATAL_FAILURE(IPCTestUtils::waitForCallback(helper1, expected, true));

    mRemote->verifyCallbacks();
    mRemote->cleanUp();
}

} // namespace test
} // namespace android
