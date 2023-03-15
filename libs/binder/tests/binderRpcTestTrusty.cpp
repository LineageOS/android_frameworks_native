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

#define LOG_TAG "binderRpcTest"

#include <android-base/stringprintf.h>
#include <binder/RpcTransportTipcTrusty.h>
#include <trusty-gtest.h>
#include <trusty_ipc.h>

#include "binderRpcTestFixture.h"

namespace android {

// Destructors need to be defined, even if pure virtual
ProcessSession::~ProcessSession() {}

class TrustyProcessSession : public ProcessSession {
public:
    ~TrustyProcessSession() override {}

    void setCustomExitStatusCheck(std::function<void(int wstatus)> /*f*/) override {
        LOG_ALWAYS_FATAL("setCustomExitStatusCheck() not supported");
    }

    void terminate() override { LOG_ALWAYS_FATAL("terminate() not supported"); }
};

std::string BinderRpc::PrintParamInfo(const testing::TestParamInfo<ParamType>& info) {
    auto [type, security, clientVersion, serverVersion, singleThreaded, noKernel] = info.param;
    auto ret = PrintToString(type) + "_clientV" + std::to_string(clientVersion) + "_serverV" +
            std::to_string(serverVersion);
    if (singleThreaded) {
        ret += "_single_threaded";
    } else {
        ret += "_multi_threaded";
    }
    if (noKernel) {
        ret += "_no_kernel";
    } else {
        ret += "_with_kernel";
    }
    return ret;
}

// This creates a new process serving an interface on a certain number of
// threads.
std::unique_ptr<ProcessSession> BinderRpc::createRpcTestSocketServerProcessEtc(
        const BinderRpcOptions& options) {
    LOG_ALWAYS_FATAL_IF(std::any_of(options.numIncomingConnectionsBySession.begin(),
                                    options.numIncomingConnectionsBySession.end(),
                                    [](size_t n) { return n != 0; }),
                        "Non-zero incoming connections on Trusty");

    uint32_t clientVersion = std::get<2>(GetParam());
    uint32_t serverVersion = std::get<3>(GetParam());

    auto ret = std::make_unique<TrustyProcessSession>();

    status_t status;
    for (size_t i = 0; i < options.numSessions; i++) {
        auto factory = android::RpcTransportCtxFactoryTipcTrusty::make();
        auto session = android::RpcSession::make(std::move(factory));

        EXPECT_TRUE(session->setProtocolVersion(clientVersion));
        session->setMaxOutgoingConnections(options.numOutgoingConnections);
        session->setFileDescriptorTransportMode(options.clientFileDescriptorTransportMode);

        status = session->setupPreconnectedClient({}, [&]() {
            auto port = trustyIpcPort(serverVersion);
            int rc = connect(port.c_str(), IPC_CONNECT_WAIT_FOR_PORT);
            LOG_ALWAYS_FATAL_IF(rc < 0, "Failed to connect to service: %d", rc);
            return base::unique_fd(rc);
        });
        if (options.allowConnectFailure && status != OK) {
            ret->sessions.clear();
            break;
        }
        LOG_ALWAYS_FATAL_IF(status != OK, "Failed to connect to service: %s",
                            statusToString(status).c_str());
        ret->sessions.push_back({session, session->getRootObject()});
    }

    return ret;
}

INSTANTIATE_TEST_CASE_P(Trusty, BinderRpc,
                        ::testing::Combine(::testing::Values(SocketType::TIPC),
                                           ::testing::Values(RpcSecurity::RAW),
                                           ::testing::ValuesIn(testVersions()),
                                           ::testing::ValuesIn(testVersions()),
                                           ::testing::Values(false), ::testing::Values(true)),
                        BinderRpc::PrintParamInfo);

} // namespace android

PORT_GTEST(BinderRpcTest, "com.android.trusty.binderRpcTest");
