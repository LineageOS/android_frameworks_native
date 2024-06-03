/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <BinderRpcTestClientInfo.h>
#include <BinderRpcTestServerConfig.h>
#include <BinderRpcTestServerInfo.h>
#include <BnBinderRpcCallback.h>
#include <BnBinderRpcSession.h>
#include <BnBinderRpcTest.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <binder/RpcThreads.h>
#include <binder/RpcTransport.h>
#include <binder/RpcTransportRaw.h>
#include <unistd.h>
#include <cinttypes>
#include <string>
#include <vector>

#ifdef __ANDROID__
#include <android-base/properties.h>
#endif

#ifndef __TRUSTY__
#include <android/binder_auto_utils.h>
#include <android/binder_libbinder.h>
#include <binder/ProcessState.h>
#include <binder/RpcTlsTestUtils.h>
#include <binder/RpcTlsUtils.h>
#include <binder/RpcTransportTls.h>

#include <signal.h>

#include "../OS.h"               // for testing UnixBootstrap clients
#include "../RpcSocketAddress.h" // for testing preconnected clients
#include "../vm_sockets.h"       // for VMADDR_*
#endif                           // __TRUSTY__

#include "../BuildFlags.h"
#include "../FdTrigger.h"
#include "../FdUtils.h"
#include "../RpcState.h" // for debugging
#include "FileUtils.h"
#include "utils/Errors.h"

namespace android {

#ifdef BINDER_NO_KERNEL_IPC_TESTING
constexpr bool kEnableKernelIpcTesting = false;
#else
constexpr bool kEnableKernelIpcTesting = true;
#endif

constexpr char kLocalInetAddress[] = "127.0.0.1";

enum class RpcSecurity { RAW, TLS };

static inline std::vector<RpcSecurity> RpcSecurityValues() {
    return {RpcSecurity::RAW, RpcSecurity::TLS};
}

static inline std::vector<bool> noKernelValues() {
    std::vector<bool> values = {true};
    if (kEnableKernelIpcTesting) {
        values.push_back(false);
    }
    return values;
}

static inline bool hasExperimentalRpc() {
#ifdef BINDER_RPC_TO_TRUSTY_TEST
    // Trusty services do not support the experimental version,
    // so that we can update the prebuilts separately.
    // This covers the binderRpcToTrustyTest case on Android.
    return false;
#endif
#ifdef __ANDROID__
    return base::GetProperty("ro.build.version.codename", "") != "REL";
#else
    return false;
#endif
}

static inline std::vector<uint32_t> testVersions() {
    std::vector<uint32_t> versions;
    for (size_t i = 0; i < RPC_WIRE_PROTOCOL_VERSION_NEXT; i++) {
        versions.push_back(i);
    }
    if (hasExperimentalRpc()) {
        versions.push_back(RPC_WIRE_PROTOCOL_VERSION_EXPERIMENTAL);
    }
    return versions;
}

static inline std::string trustyIpcPort(uint32_t serverVersion) {
    return "com.android.trusty.binderRpcTestService.V" + std::to_string(serverVersion);
}

enum class SocketType {
    PRECONNECTED,
    UNIX,
    UNIX_BOOTSTRAP,
    UNIX_RAW,
    VSOCK,
    INET,
    TIPC,
};

static inline std::string PrintToString(SocketType socketType) {
    switch (socketType) {
        case SocketType::PRECONNECTED:
            return "preconnected_uds";
        case SocketType::UNIX:
            return "unix_domain_socket";
        case SocketType::UNIX_BOOTSTRAP:
            return "unix_domain_socket_bootstrap";
        case SocketType::UNIX_RAW:
            return "raw_uds";
        case SocketType::VSOCK:
            return "vm_socket";
        case SocketType::INET:
            return "inet_socket";
        case SocketType::TIPC:
            return "trusty_ipc";
        default:
            LOG_ALWAYS_FATAL("Unknown socket type");
            return "";
    }
}

static inline size_t epochMillis() {
    using std::chrono::duration_cast;
    using std::chrono::milliseconds;
    using std::chrono::seconds;
    using std::chrono::system_clock;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

struct BinderRpcOptions {
    size_t numThreads = 1;
    size_t numSessions = 1;
    // right now, this can be empty, or length numSessions, where each value
    // represents the info for the corresponding session, but we should
    // probably switch this to be a list of sessions options so that other
    // options can all be specified per session
    std::vector<size_t> numIncomingConnectionsBySession = {};
    size_t numOutgoingConnections = SIZE_MAX;
    RpcSession::FileDescriptorTransportMode clientFileDescriptorTransportMode =
            RpcSession::FileDescriptorTransportMode::NONE;
    std::vector<RpcSession::FileDescriptorTransportMode>
            serverSupportedFileDescriptorTransportModes = {
                    RpcSession::FileDescriptorTransportMode::NONE};

    // If true, connection failures will result in `ProcessSession::sessions` being empty
    // instead of a fatal error.
    bool allowConnectFailure = false;
};

#ifndef __TRUSTY__
static inline void writeString(binder::borrowed_fd fd, std::string_view str) {
    uint64_t length = str.length();
    LOG_ALWAYS_FATAL_IF(!android::binder::WriteFully(fd, &length, sizeof(length)));
    LOG_ALWAYS_FATAL_IF(!android::binder::WriteFully(fd, str.data(), str.length()));
}

static inline std::string readString(binder::borrowed_fd fd) {
    uint64_t length;
    LOG_ALWAYS_FATAL_IF(!android::binder::ReadFully(fd, &length, sizeof(length)));
    std::string ret(length, '\0');
    LOG_ALWAYS_FATAL_IF(!android::binder::ReadFully(fd, ret.data(), length));
    return ret;
}

static inline void writeToFd(binder::borrowed_fd fd, const Parcelable& parcelable) {
    Parcel parcel;
    LOG_ALWAYS_FATAL_IF(OK != parcelable.writeToParcel(&parcel));
    writeString(fd, std::string(reinterpret_cast<const char*>(parcel.data()), parcel.dataSize()));
}

template <typename T>
static inline T readFromFd(binder::borrowed_fd fd) {
    std::string data = readString(fd);
    Parcel parcel;
    LOG_ALWAYS_FATAL_IF(OK !=
                        parcel.setData(reinterpret_cast<const uint8_t*>(data.data()), data.size()));
    T object;
    LOG_ALWAYS_FATAL_IF(OK != object.readFromParcel(&parcel));
    return object;
}

static inline std::unique_ptr<RpcTransportCtxFactory> newTlsFactory(
        RpcSecurity rpcSecurity, std::shared_ptr<RpcCertificateVerifier> verifier = nullptr,
        std::unique_ptr<RpcAuth> auth = nullptr) {
    switch (rpcSecurity) {
        case RpcSecurity::RAW:
            return RpcTransportCtxFactoryRaw::make();
        case RpcSecurity::TLS: {
            if (verifier == nullptr) {
                verifier = std::make_shared<RpcCertificateVerifierSimple>();
            }
            if (auth == nullptr) {
                auth = std::make_unique<RpcAuthSelfSigned>();
            }
            return RpcTransportCtxFactoryTls::make(std::move(verifier), std::move(auth));
        }
        default:
            LOG_ALWAYS_FATAL("Unknown RpcSecurity %d", static_cast<int>(rpcSecurity));
    }
}

// Create an FD that returns `contents` when read.
static inline binder::unique_fd mockFileDescriptor(std::string contents) {
    binder::unique_fd readFd, writeFd;
    LOG_ALWAYS_FATAL_IF(!binder::Pipe(&readFd, &writeFd), "%s", strerror(errno));
    RpcMaybeThread([writeFd = std::move(writeFd), contents = std::move(contents)]() {
        signal(SIGPIPE, SIG_IGN); // ignore possible SIGPIPE from the write
        if (!android::binder::WriteStringToFd(contents, writeFd)) {
            int savedErrno = errno;
            LOG_ALWAYS_FATAL_IF(EPIPE != savedErrno, "mockFileDescriptor write failed: %s",
                                strerror(savedErrno));
        }
    }).detach();
    return readFd;
}
#endif // __TRUSTY__

// A threadsafe channel where writes block until the value is read.
template <typename T>
class HandoffChannel {
public:
    void write(T v) {
        {
            RpcMutexUniqueLock lock(mMutex);
            // Wait for space to send.
            mCvEmpty.wait(lock, [&]() { return !mValue.has_value(); });
            mValue.emplace(std::move(v));
        }
        mCvFull.notify_all();
        RpcMutexUniqueLock lock(mMutex);
        // Wait for it to be taken.
        mCvEmpty.wait(lock, [&]() { return !mValue.has_value(); });
    }

    T read() {
        RpcMutexUniqueLock lock(mMutex);
        if (!mValue.has_value()) {
            mCvFull.wait(lock, [&]() { return mValue.has_value(); });
        }
        T v = std::move(mValue.value());
        mValue.reset();
        lock.unlock();
        mCvEmpty.notify_all();
        return v;
    }

private:
    RpcMutex mMutex;
    RpcConditionVariable mCvEmpty;
    RpcConditionVariable mCvFull;
    std::optional<T> mValue;
};

using android::binder::Status;

class MyBinderRpcSession : public BnBinderRpcSession {
public:
    static std::atomic<int32_t> gNum;

    MyBinderRpcSession(const std::string& name) : mName(name) { gNum++; }
    Status getName(std::string* name) override {
        *name = mName;
        return Status::ok();
    }
    ~MyBinderRpcSession() { gNum--; }

private:
    std::string mName;
};

class MyBinderRpcCallback : public BnBinderRpcCallback {
    Status sendCallback(const std::string& value) {
        RpcMutexUniqueLock _l(mMutex);
        mValues.push_back(value);
        _l.unlock();
        mCv.notify_one();
        return Status::ok();
    }
    Status sendOnewayCallback(const std::string& value) { return sendCallback(value); }

public:
    RpcMutex mMutex;
    RpcConditionVariable mCv;
    std::vector<std::string> mValues;
};

// Base class for all concrete implementations of MyBinderRpcTest.
// Sub-classes that want to provide a full implementation should derive
// from this class instead of MyBinderRpcTestDefault below so the compiler
// checks that all methods are implemented.
class MyBinderRpcTestBase : public BnBinderRpcTest {
public:
    int port = 0;

    Status sendString(const std::string& str) override {
        (void)str;
        return Status::ok();
    }
    Status doubleString(const std::string& str, std::string* strstr) override {
        *strstr = str + str;
        return Status::ok();
    }
    Status getClientPort(int* out) override {
        *out = port;
        return Status::ok();
    }
    Status getNullBinder(sp<IBinder>* out) override {
        out->clear();
        return Status::ok();
    }
    Status pingMe(const sp<IBinder>& binder, int32_t* out) override {
        if (binder == nullptr) {
            std::cout << "Received null binder!" << std::endl;
            return Status::fromExceptionCode(Status::EX_NULL_POINTER);
        }
        *out = binder->pingBinder();
        return Status::ok();
    }
    Status repeatBinder(const sp<IBinder>& binder, sp<IBinder>* out) override {
        *out = binder;
        return Status::ok();
    }
    static sp<IBinder> mHeldBinder;
    Status holdBinder(const sp<IBinder>& binder) override {
        mHeldBinder = binder;
        return Status::ok();
    }
    Status getHeldBinder(sp<IBinder>* held) override {
        *held = mHeldBinder;
        return Status::ok();
    }
    Status nestMe(const sp<IBinderRpcTest>& binder, int count) override {
        if (count <= 0) return Status::ok();
        return binder->nestMe(this, count - 1);
    }
    Status alwaysGiveMeTheSameBinder(sp<IBinder>* out) override {
        static sp<IBinder> binder = new BBinder;
        *out = binder;
        return Status::ok();
    }
    Status openSession(const std::string& name, sp<IBinderRpcSession>* out) override {
        *out = new MyBinderRpcSession(name);
        return Status::ok();
    }
    Status getNumOpenSessions(int32_t* out) override {
        *out = MyBinderRpcSession::gNum;
        return Status::ok();
    }

    RpcMutex blockMutex;
    Status lock() override {
        blockMutex.lock();
        return Status::ok();
    }
    Status unlockInMsAsync(int32_t ms) override {
        usleep(ms * 1000);
        blockMutex.unlock();
        return Status::ok();
    }
    Status lockUnlock() override {
        RpcMutexLockGuard _l(blockMutex);
        return Status::ok();
    }

    Status sleepMs(int32_t ms) override {
        usleep(ms * 1000);
        return Status::ok();
    }

    Status sleepMsAsync(int32_t ms) override {
        // In-process binder calls are asynchronous, but the call to this method
        // is synchronous wrt its client. This in/out-process threading model
        // diffentiation is a classic binder leaky abstraction (for better or
        // worse) and is preserved here the way binder sockets plugs itself
        // into BpBinder, as nothing is changed at the higher levels
        // (IInterface) which result in this behavior.
        return sleepMs(ms);
    }

    Status doCallback(const sp<IBinderRpcCallback>& callback, bool oneway, bool delayed,
                      const std::string& value) override {
        if (callback == nullptr) {
            return Status::fromExceptionCode(Status::EX_NULL_POINTER);
        }

        if (delayed) {
            RpcMaybeThread([=, this]() {
                ALOGE("Executing delayed callback: '%s'", value.c_str());
                Status status = doCallback(callback, oneway, false, value);
                ALOGE("Delayed callback status: '%s'", status.toString8().c_str());
            }).detach();
            return Status::ok();
        }

        if (oneway) {
            return callback->sendOnewayCallback(value);
        }

        return callback->sendCallback(value);
    }

    Status doCallbackAsync(const sp<IBinderRpcCallback>& callback, bool oneway, bool delayed,
                           const std::string& value) override {
        return doCallback(callback, oneway, delayed, value);
    }

protected:
    // Generic version of countBinders that works with both
    // RpcServer and RpcServerTrusty
    template <typename T>
    Status countBindersImpl(const wp<T>& server, std::vector<int32_t>* out) {
        sp<T> spServer = server.promote();
        if (spServer == nullptr) {
            return Status::fromExceptionCode(Status::EX_NULL_POINTER);
        }
        out->clear();
        for (auto session : spServer->listSessions()) {
            size_t count = session->state()->countBinders();
            out->push_back(count);
        }
        return Status::ok();
    }
};

// Default implementation of MyBinderRpcTest that can be used as-is
// or derived from by classes that only want to implement a subset of
// the unimplemented methods
class MyBinderRpcTestDefault : public MyBinderRpcTestBase {
public:
    Status countBinders(std::vector<int32_t>* /*out*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }

    Status die(bool /*cleanup*/) override { return Status::fromStatusT(UNKNOWN_TRANSACTION); }

    Status scheduleShutdown() override { return Status::fromStatusT(UNKNOWN_TRANSACTION); }

    Status useKernelBinderCallingId() override { return Status::fromStatusT(UNKNOWN_TRANSACTION); }

    Status echoAsFile(const std::string& /*content*/,
                      android::os::ParcelFileDescriptor* /*out*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }

    Status concatFiles(const std::vector<android::os::ParcelFileDescriptor>& /*files*/,
                       android::os::ParcelFileDescriptor* /*out*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }

    Status blockingSendFdOneway(const android::os::ParcelFileDescriptor& /*fd*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }

    Status blockingRecvFd(android::os::ParcelFileDescriptor* /*fd*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }

    Status blockingSendIntOneway(int /*n*/) override {
        return Status::fromStatusT(UNKNOWN_TRANSACTION);
    }

    Status blockingRecvInt(int* /*n*/) override { return Status::fromStatusT(UNKNOWN_TRANSACTION); }
};

} // namespace android
