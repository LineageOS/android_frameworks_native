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

#define TLOG_TAG "binderRpcTestService"

#include <binder/RpcServerTrusty.h>
#include <inttypes.h>
#include <lib/tipc/tipc.h>
#include <lk/err_ptr.h>
#include <stdio.h>
#include <trusty_log.h>
#include <vector>

#include "binderRpcTestCommon.h"

using namespace android;
using binder::Status;

static int gConnectionCounter = 0;

class MyBinderRpcTestTrusty : public MyBinderRpcTestDefault {
public:
    wp<RpcServerTrusty> server;

    Status countBinders(std::vector<int32_t>* out) override {
        return countBindersImpl(server, out);
    }

    Status scheduleShutdown() override {
        // TODO: Trusty does not support shutting down the tipc event loop,
        // so we just terminate the service app since it is marked
        // restart_on_exit
        exit(EXIT_SUCCESS);
    }

    // TODO(b/242940548): implement echoAsFile and concatFiles
};

struct ServerInfo {
    std::unique_ptr<std::string> port;
    sp<RpcServerTrusty> server;
};

int main(void) {
    TLOGI("Starting service\n");

    tipc_hset* hset = tipc_hset_create();
    if (IS_ERR(hset)) {
        TLOGE("Failed to create handle set (%d)\n", PTR_ERR(hset));
        return EXIT_FAILURE;
    }

    const auto port_acl = RpcServerTrusty::PortAcl{
            .flags = IPC_PORT_ALLOW_NS_CONNECT | IPC_PORT_ALLOW_TA_CONNECT,
    };

    std::vector<ServerInfo> servers;
    for (auto serverVersion : testVersions()) {
        ServerInfo serverInfo{
                .port = std::make_unique<std::string>(trustyIpcPort(serverVersion)),
        };
        TLOGI("Adding service port '%s'\n", serverInfo.port->c_str());

        // Message size needs to be large enough to cover all messages sent by the
        // tests: SendAndGetResultBackBig sends two large strings.
        constexpr size_t max_msg_size = 4096;
        auto server =
                RpcServerTrusty::make(hset, serverInfo.port->c_str(),
                                      std::shared_ptr<const RpcServerTrusty::PortAcl>(&port_acl),
                                      max_msg_size);
        if (server == nullptr) {
            return EXIT_FAILURE;
        }

        serverInfo.server = server;
        if (!serverInfo.server->setProtocolVersion(serverVersion)) {
            return EXIT_FAILURE;
        }
        serverInfo.server->setPerSessionRootObject(
                [=](wp<RpcSession> /*session*/, const void* /*addrPtr*/, size_t /*len*/) {
                    auto service = sp<MyBinderRpcTestTrusty>::make();
                    // Assign a unique connection identifier to service->port so
                    // getClientPort returns a unique value per connection
                    service->port = ++gConnectionCounter;
                    service->server = server;
                    return service;
                });

        servers.push_back(std::move(serverInfo));
    }

    return tipc_run_event_loop(hset);
}
