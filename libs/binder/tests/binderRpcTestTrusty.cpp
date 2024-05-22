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

#include <binder/RpcTransportTipcTrusty.h>
#include <trusty-gtest.h>
#include <trusty_ipc.h>

#include "binderRpcTestFixture.h"

using android::binder::unique_fd;

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

std::unique_ptr<RpcTransportCtxFactory> BinderRpc::newFactory(RpcSecurity rpcSecurity) {
    switch (rpcSecurity) {
        case RpcSecurity::RAW:
            return RpcTransportCtxFactoryTipcTrusty::make();
        default:
            LOG_ALWAYS_FATAL("Unknown RpcSecurity %d", static_cast<int>(rpcSecurity));
    }
}

// This creates a new process serving an interface on a certain number of
// threads.
std::unique_ptr<ProcessSession> BinderRpc::createRpcTestSocketServerProcessEtc(
        const BinderRpcOptions& options) {
    LOG_ALWAYS_FATAL_IF(std::any_of(options.numIncomingConnectionsBySession.begin(),
                                    options.numIncomingConnectionsBySession.end(),
                                    [](size_t n) { return n != 0; }),
                        "Non-zero incoming connections on Trusty");

    RpcSecurity rpcSecurity = GetParam().security;
    uint32_t clientVersion = GetParam().clientVersion;
    uint32_t serverVersion = GetParam().serverVersion;

    auto ret = std::make_unique<TrustyProcessSession>();

    status_t status;
    for (size_t i = 0; i < options.numSessions; i++) {
        auto session = android::RpcSession::make(newFactory(rpcSecurity));

        EXPECT_TRUE(session->setProtocolVersion(clientVersion));
        session->setMaxOutgoingConnections(options.numOutgoingConnections);
        session->setFileDescriptorTransportMode(options.clientFileDescriptorTransportMode);

        status = session->setupPreconnectedClient({}, [&]() {
            auto port = trustyIpcPort(serverVersion);
            int rc = connect(port.c_str(), IPC_CONNECT_WAIT_FOR_PORT);
            LOG_ALWAYS_FATAL_IF(rc < 0, "Failed to connect to service: %d", rc);
            return unique_fd(rc);
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

static std::vector<BinderRpc::ParamType> getTrustyBinderRpcParams() {
    std::vector<BinderRpc::ParamType> ret;

    for (const auto& clientVersion : testVersions()) {
        for (const auto& serverVersion : testVersions()) {
            ret.push_back(BinderRpc::ParamType{
                    .type = SocketType::TIPC,
                    .security = RpcSecurity::RAW,
                    .clientVersion = clientVersion,
                    .serverVersion = serverVersion,
                    // TODO: should we test both versions here?
                    .singleThreaded = false,
                    .noKernel = true,
            });
        }
    }

    return ret;
}

INSTANTIATE_TEST_SUITE_P(Trusty, BinderRpc, ::testing::ValuesIn(getTrustyBinderRpcParams()),
                         BinderRpc::PrintParamInfo);

} // namespace android

PORT_GTEST(BinderRpcTest, "com.android.trusty.binderRpcTest");
