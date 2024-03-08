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

#include <gtest/gtest.h>

#include "binderRpcTestCommon.h"

#define EXPECT_OK(status)                        \
    do {                                         \
        android::binder::Status stat = (status); \
        EXPECT_TRUE(stat.isOk()) << stat;        \
    } while (false)

namespace android {

// Abstract base class with a virtual destructor that handles the
// ownership of a process session for BinderRpcTestSession below
class ProcessSession {
public:
    struct SessionInfo {
        sp<RpcSession> session;
        sp<IBinder> root;
    };

    // client session objects associated with other process
    // each one represents a separate session
    std::vector<SessionInfo> sessions;

    virtual ~ProcessSession() = 0;

    // If the process exits with a status, run the given callback on that value.
    virtual void setCustomExitStatusCheck(std::function<void(int wstatus)> f) = 0;

    // Kill the process. Avoid if possible. Shutdown gracefully via an RPC instead.
    virtual void terminate() = 0;
};

// Process session where the process hosts IBinderRpcTest, the server used
// for most testing here
struct BinderRpcTestProcessSession {
    std::unique_ptr<ProcessSession> proc;

    // pre-fetched root object (for first session)
    sp<IBinder> rootBinder;

    // pre-casted root object (for first session)
    sp<IBinderRpcTest> rootIface;

    // whether session should be invalidated by end of run
    bool expectAlreadyShutdown = false;

    // TODO(b/271830568): fix this in binderRpcTest, we always use the first session to cause the
    // remote process to shutdown. Normally, when we shutdown, the default in the destructor is to
    // check that there are no leaks and shutdown. However, when there are incoming threadpools,
    // there will be a few extra binder threads there, so we can't shutdown the server. We should
    // consider an alternative way of doing the test so that we don't need this, some ideas, such as
    // program in understanding of incoming threadpool into the destructor so that (e.g.
    // intelligently wait for sessions to shutdown now that they will do this)
    void forceShutdown() {
        if (auto status = rootIface->scheduleShutdown(); !status.isOk()) {
            EXPECT_EQ(DEAD_OBJECT, status.transactionError()) << status;
        }
        EXPECT_TRUE(proc->sessions.at(0).session->shutdownAndWait(true));
        expectAlreadyShutdown = true;
    }

    BinderRpcTestProcessSession(std::unique_ptr<ProcessSession> proc) : proc(std::move(proc)){};
    BinderRpcTestProcessSession(BinderRpcTestProcessSession&&) = default;
    ~BinderRpcTestProcessSession() {
        if (!expectAlreadyShutdown) {
            EXPECT_NE(nullptr, rootIface);
            if (rootIface == nullptr) return;

            std::vector<int32_t> remoteCounts;
            // calling over any sessions counts across all sessions
            EXPECT_OK(rootIface->countBinders(&remoteCounts));
            EXPECT_EQ(remoteCounts.size(), proc->sessions.size());
            for (auto remoteCount : remoteCounts) {
                EXPECT_EQ(remoteCount, 1);
            }

            // even though it is on another thread, shutdown races with
            // the transaction reply being written
            if (auto status = rootIface->scheduleShutdown(); !status.isOk()) {
                EXPECT_EQ(DEAD_OBJECT, status.transactionError()) << status;
            }
        }

        rootIface = nullptr;
        rootBinder = nullptr;
    }
};

struct BinderRpcParam {
    SocketType type;
    RpcSecurity security;
    uint32_t clientVersion;
    uint32_t serverVersion;
    bool singleThreaded;
    bool noKernel;
};
class BinderRpc : public ::testing::TestWithParam<BinderRpcParam> {
public:
    // TODO: avoid unnecessary layer of indirection
    SocketType socketType() const { return GetParam().type; }
    RpcSecurity rpcSecurity() const { return GetParam().security; }
    uint32_t clientVersion() const { return GetParam().clientVersion; }
    uint32_t serverVersion() const { return GetParam().serverVersion; }
    bool serverSingleThreaded() const { return GetParam().singleThreaded; }
    bool noKernel() const { return GetParam().noKernel; }

    bool clientOrServerSingleThreaded() const {
        return !kEnableRpcThreads || serverSingleThreaded();
    }

    // Whether the test params support sending FDs in parcels.
    bool supportsFdTransport() const {
        if (socketType() == SocketType::TIPC) {
            // Trusty does not support file descriptors yet
            return false;
        }
        return clientVersion() >= 1 && serverVersion() >= 1 && rpcSecurity() != RpcSecurity::TLS &&
                (socketType() == SocketType::PRECONNECTED || socketType() == SocketType::UNIX ||
                 socketType() == SocketType::UNIX_BOOTSTRAP ||
                 socketType() == SocketType::UNIX_RAW);
    }

    void SetUp() override {
        if (socketType() == SocketType::UNIX_BOOTSTRAP && rpcSecurity() == RpcSecurity::TLS) {
            GTEST_SKIP() << "Unix bootstrap not supported over a TLS transport";
        }
    }

    BinderRpcTestProcessSession createRpcTestSocketServerProcess(const BinderRpcOptions& options) {
        BinderRpcTestProcessSession ret(createRpcTestSocketServerProcessEtc(options));

        ret.rootBinder = ret.proc->sessions.empty() ? nullptr : ret.proc->sessions.at(0).root;
        ret.rootIface = interface_cast<IBinderRpcTest>(ret.rootBinder);

        return ret;
    }

    static std::string PrintParamInfo(const testing::TestParamInfo<ParamType>& info) {
        auto ret = PrintToString(info.param.type) + "_" +
                newFactory(info.param.security)->toCString() + "_clientV" +
                std::to_string(info.param.clientVersion) + "_serverV" +
                std::to_string(info.param.serverVersion);
        if (info.param.singleThreaded) {
            ret += "_single_threaded";
        } else {
            ret += "_multi_threaded";
        }
        if (info.param.noKernel) {
            ret += "_no_kernel";
        } else {
            ret += "_with_kernel";
        }
        return ret;
    }

protected:
    static std::unique_ptr<RpcTransportCtxFactory> newFactory(RpcSecurity rpcSecurity);

    std::unique_ptr<ProcessSession> createRpcTestSocketServerProcessEtc(
            const BinderRpcOptions& options);
};

} // namespace android
