/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <android/binder_libbinder.h>
#include <binder/RpcServer.h>
#include <binder/RpcServerTrusty.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportTipcTrusty.h>

using android::RpcServer;
using android::RpcServerTrusty;
using android::RpcSession;
using android::RpcTransportCtxFactoryTipcTrusty;
using android::sp;
using android::wp;

struct ARpcServerTrusty {
    sp<RpcServer> mRpcServer;

    ARpcServerTrusty() = delete;
    ARpcServerTrusty(sp<RpcServer> rpcServer) : mRpcServer(std::move(rpcServer)) {}
};

ARpcServerTrusty* ARpcServerTrusty_newPerSession(AIBinder* (*cb)(const void*, size_t, char*),
                                                 char* cbArg, void (*cbArgDeleter)(char*)) {
    std::shared_ptr<char> cbArgSp(cbArg, cbArgDeleter);

    auto rpcTransportCtxFactory = RpcTransportCtxFactoryTipcTrusty::make();
    if (rpcTransportCtxFactory == nullptr) {
        return nullptr;
    }

    auto ctx = rpcTransportCtxFactory->newServerCtx();
    if (ctx == nullptr) {
        return nullptr;
    }

    auto rpcServer = RpcServerTrusty::makeRpcServer(std::move(ctx));
    if (rpcServer == nullptr) {
        return nullptr;
    }

    rpcServer->setPerSessionRootObject(
            [cb, cbArgSp](wp<RpcSession> /*session*/, const void* addrPtr, size_t len) {
                auto* aib = (*cb)(addrPtr, len, cbArgSp.get());
                auto b = AIBinder_toPlatformBinder(aib);

                // We have a new sp<IBinder> backed by the same binder, so we can
                // finally release the AIBinder* from the callback
                AIBinder_decStrong(aib);

                return b;
            });

    return new (std::nothrow) ARpcServerTrusty(std::move(rpcServer));
}

void ARpcServerTrusty_delete(ARpcServerTrusty* rstr) {
    delete rstr;
}

int ARpcServerTrusty_handleConnect(ARpcServerTrusty* rstr, handle_t chan, const uuid* peer,
                                   void** ctx_p) {
    return RpcServerTrusty::handleConnectInternal(rstr->mRpcServer.get(), chan, peer, ctx_p);
}

int ARpcServerTrusty_handleMessage(void* ctx) {
    return RpcServerTrusty::handleMessageInternal(ctx);
}

void ARpcServerTrusty_handleDisconnect(void* ctx) {
    RpcServerTrusty::handleDisconnectInternal(ctx);
}

void ARpcServerTrusty_handleChannelCleanup(void* ctx) {
    RpcServerTrusty::handleChannelCleanup(ctx);
}
