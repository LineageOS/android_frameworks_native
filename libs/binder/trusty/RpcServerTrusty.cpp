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

#define LOG_TAG "libbinder.RpcServerTrusty"

#include <cinttypes>
#include <cstring>

#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <binder/RpcServerTrusty.h>
#include <binder/RpcThreads.h>
#include <binder/RpcTransportTipcTrusty.h>
#include <lk/macros.h>
#include <log/log.h>

#include <lib/tipc/tipc.h>

#include "../FdTrigger.h"
#include "../RpcState.h"
#include "TrustyStatus.h"

using android::binder::unique_fd;

namespace android {

sp<RpcServerTrusty> RpcServerTrusty::make(
        tipc_hset* handleSet, std::string&& portName, std::shared_ptr<const PortAcl>&& portAcl,
        size_t msgMaxSize, size_t msgQueueLen,
        std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory) {
    // Default is without TLS.
    if (rpcTransportCtxFactory == nullptr)
        rpcTransportCtxFactory = RpcTransportCtxFactoryTipcTrusty::make();
    auto ctx = rpcTransportCtxFactory->newServerCtx();
    if (ctx == nullptr) {
        ALOGE("Failed to create RpcServerTrusty: can't create server context");
        return nullptr;
    }

    auto srv = sp<RpcServerTrusty>::make(std::move(ctx), std::move(portName), std::move(portAcl),
                                         msgMaxSize, msgQueueLen);
    if (srv == nullptr) {
        ALOGE("Failed to create RpcServerTrusty: can't create server object");
        return nullptr;
    }

    int rc =
            tipc_add_service_ports(handleSet, &srv->mTipcPort, 1, 0, &kTipcOps, &srv->mTipcPortCtx);
    if (rc != NO_ERROR) {
        ALOGE("Failed to create RpcServerTrusty: can't add service: %d", rc);
        return nullptr;
    }
    return srv;
}

RpcServerTrusty::~RpcServerTrusty() {
    if (mTipcPortCtx != nullptr) {
        tipc_remove_service(mTipcPortCtx);
    }
}

RpcServerTrusty::RpcServerTrusty(std::unique_ptr<RpcTransportCtx> ctx, std::string&& portName,
                                 std::shared_ptr<const PortAcl>&& portAcl, size_t msgMaxSize,
                                 size_t msgQueueLen)
      : mRpcServer(makeRpcServer(std::move(ctx))),
        mPortName(std::move(portName)),
        mPortAcl(std::move(portAcl)),
        mTipcPortCtx(nullptr) {
    mTipcPort.name = mPortName.c_str();
    mTipcPort.msg_max_size = msgMaxSize;
    mTipcPort.msg_queue_len = msgQueueLen;
    mTipcPort.priv = this;

    if (mPortAcl) {
        // Initialize the array of pointers to uuids.
        // The pointers in mUuidPtrs should stay valid across moves of
        // RpcServerTrusty (the addresses of a std::vector's elements
        // shouldn't change when the vector is moved), but would be invalidated
        // by a copy which is why we disable the copy constructor and assignment
        // operator for RpcServerTrusty.
        auto numUuids = mPortAcl->uuids.size();
        mUuidPtrs.resize(numUuids);
        for (size_t i = 0; i < numUuids; i++) {
            mUuidPtrs[i] = &mPortAcl->uuids[i];
        }

        // Copy the contents of portAcl into the tipc_port_acl structure that we
        // pass to tipc_add_service
        mTipcPortAcl.flags = mPortAcl->flags;
        mTipcPortAcl.uuid_num = numUuids;
        mTipcPortAcl.uuids = mUuidPtrs.data();
        mTipcPortAcl.extra_data = mPortAcl->extraData;

        mTipcPort.acl = &mTipcPortAcl;
    } else {
        mTipcPort.acl = nullptr;
    }
}

void RpcServerTrusty::setPerSessionRootObject(
        std::function<sp<IBinder>(wp<RpcSession> session, const void* peer, size_t peer_len)>&&
                create_session) {
    auto wrap_create_session = [create_session =
                                        std::move(create_session)](wp<RpcSession> session,
                                                                   const trusty_peer_id& peer,
                                                                   size_t peer_len) -> sp<IBinder> {
        if (peer.kind != TRUSTY_PEER_ID_KIND_UUID) {
            ALOGE("Creating binder root object, but peer had "
                  "non-uuid type %" PRIx64 " (expected %" PRIx64 ")",
                  peer.kind, TRUSTY_PEER_ID_KIND_UUID);
            return nullptr;
        }
        if (peer_len != sizeof(trusty_peer_id_uuid)) {
            ALOGE("Creating binder root object, but uuid-type peer had unexpected "
                  "size %zu (expected %zu)",
                  peer_len, sizeof(trusty_peer_id_uuid));
            return nullptr;
        }

        const auto& peer_uuid = reinterpret_cast<const trusty_peer_id_uuid&>(peer);
        return create_session(std::move(session), &peer_uuid.id, sizeof(peer_uuid.id));
    };
    setPerSessionRootObjectInternal(mRpcServer.get(), std::move(wrap_create_session));
}

void RpcServerTrusty::setPerSessionRootObjectInternal(
        RpcServer* server,
        std::function<sp<IBinder>(wp<RpcSession> session, const trusty_peer_id& peer,
                                  size_t peer_len)>&& create_session) {
    auto wrap_create_session =
            [create_session = std::move(create_session)](wp<RpcSession> session, const void* peer,
                                                         size_t peer_len) -> sp<IBinder> {
        if (peer_len > sizeof(trusty_peer_id_storage)) {
            ALOGE("Creating binder root object, but peer ID (%zu bytes) too "
                  "big to fit in trusty_peer_id_storage (%zu bytes)",
                  peer_len, sizeof(trusty_peer_id_storage));
            return nullptr;
        }

        /* memcpy because peer isn't guaranteed to be sufficiently aligned */
        trusty_peer_id_storage peer_obj = TRUSTY_PEER_ID_STORAGE_INITIAL_VALUE();
        std::memcpy(&peer_obj, peer, peer_len);

        return create_session(std::move(session), reinterpret_cast<const trusty_peer_id&>(peer_obj),
                              peer_len);
    };
    server->setPerSessionRootObject(std::move(wrap_create_session));
}

status_t RpcServerTrusty::queueConnect(unique_fd chan, const trusty_peer_id& peer,
                                       size_t peer_len) {
    struct AddConnectionTodo {
        struct tipc_work_todo todo;
        struct tipc_port_ctx* port;
        unique_fd chan;
        struct trusty_peer_id_storage peer;
        size_t peer_len;

        static int DoWork(struct tipc_work_todo* todo) {
            AddConnectionTodo* self = containerof(todo, AddConnectionTodo, todo);
            handle_t chan = self->chan.release();
            int rc = tipc_add_connection(self->port, chan,
                                         &reinterpret_cast<const trusty_peer_id&>(self->peer),
                                         self->peer_len);
            if (rc != NO_ERROR) {
                close(chan);
            }

            delete self;
            return rc;
        }
    };

    if (peer_len > sizeof(trusty_peer_id_storage)) {
        ALOGE("Tried to queue connection, but peer ID (kind %" PRIx64 ", %zu"
              "bytes) is too big to fit in trusty_peer_id_storage (%zu bytes)",
              peer.kind, peer_len, sizeof(trusty_peer_id_storage));
        return BAD_VALUE;
    }

    auto* add_conn = new (std::nothrow) AddConnectionTodo{
            .todo = TIPC_WORK_TODO_INITIAL_VALUE(add_conn->todo, AddConnectionTodo::DoWork),
            .port = mTipcPortCtx,
            .chan = std::move(chan),
            .peer = TRUSTY_PEER_ID_STORAGE_INITIAL_VALUE(),
            .peer_len = peer_len,
    };
    if (add_conn == nullptr) {
        return NO_MEMORY;
    }
    std::memcpy(&add_conn->peer, &peer, peer_len);

    tipc_queue_work(tipc_get_hset(mTipcPortCtx), &add_conn->todo);
    return OK;
}

int RpcServerTrusty::handleConnect(const tipc_port* port, handle_t chan, const trusty_peer_id* peer,
                                   size_t peer_len, void** ctx_p) {
    auto* server = reinterpret_cast<RpcServerTrusty*>(const_cast<void*>(port->priv));
    return handleConnectInternal(server->mRpcServer.get(), chan, *peer, peer_len, ctx_p);
}

int RpcServerTrusty::handleConnectInternal(RpcServer* rpcServer, handle_t chan,
                                           const trusty_peer_id& peer, size_t peer_len,
                                           void** ctx_p) {
    rpcServer->mShutdownTrigger = FdTrigger::make();
    rpcServer->mConnectingThreads[rpc_this_thread::get_id()] = RpcMaybeThread();

    int rc = NO_ERROR;
    auto setupChannelContext = [&](sp<RpcSession>&& session,
                                   RpcSession::PreJoinSetupResult&& result, bool isIncoming) {
        if (result.status != OK) {
            rc = statusToTrusty(result.status);
            return;
        }

        /* Save the session and connection for the other callbacks */
        auto* channelContext = new (std::nothrow) ChannelContext;
        if (channelContext == nullptr) {
            rc = ERR_NO_MEMORY;
            return;
        }

        channelContext->session = std::move(session);
        channelContext->connection = std::move(result.connection);
        channelContext->isIncoming = isIncoming;

        *ctx_p = channelContext;
    };

    auto joinFn = [&](sp<RpcSession>&& session, RpcSession::PreJoinSetupResult&& result) {
        setupChannelContext(std::move(session), std::move(result), true);
    };

    auto incomingSetupFn = [&](sp<RpcSession>&& session, RpcSession::PreJoinSetupResult&& result) {
        setupChannelContext(std::move(session), std::move(result), false);
    };

    // We need to duplicate the channel handle here because the tipc library
    // owns the original handle and closes is automatically on channel cleanup.
    // We use dup() because Trusty does not have fcntl().
    // NOLINTNEXTLINE(android-cloexec-dup)
    handle_t chanDup = dup(chan);
    if (chanDup < 0) {
        return chanDup;
    }
    unique_fd clientFd(chanDup);
    android::RpcTransportFd transportFd(std::move(clientFd));

    std::array<uint8_t, RpcServer::kRpcAddressSize> addr;
    if (peer_len > RpcServer::kRpcAddressSize) {
        return ERR_BAD_LEN;
    }
    memcpy(addr.data(), &peer, peer_len);
    RpcServer::establishConnection(sp<RpcServer>::fromExisting(rpcServer), std::move(transportFd),
                                   addr, peer_len, joinFn, incomingSetupFn);

    return rc;
}

int RpcServerTrusty::handleMessage(const tipc_port* /*port*/, handle_t /*chan*/, void* ctx) {
    return handleMessageInternal(ctx);
}

int RpcServerTrusty::handleMessageInternal(void* ctx) {
    auto* channelContext = reinterpret_cast<ChannelContext*>(ctx);
    if (channelContext == nullptr) {
        LOG_RPC_DETAIL("bad state: message received on uninitialized channel");
        return ERR_BAD_STATE;
    }

    auto& session = channelContext->session;
    auto& connection = channelContext->connection;
    status_t status =
            session->state()->drainCommands(connection, session, RpcState::CommandType::ANY);
    if (status != OK) {
        LOG_RPC_DETAIL("Binder connection thread closing w/ status %s",
                       statusToString(status).c_str());
    }

    return NO_ERROR;
}

void RpcServerTrusty::handleDisconnect(const tipc_port* /*port*/, handle_t /*chan*/, void* ctx) {
    return handleDisconnectInternal(ctx);
}

void RpcServerTrusty::handleDisconnectInternal(void* ctx) {
    auto* channelContext = reinterpret_cast<ChannelContext*>(ctx);
    if (channelContext == nullptr) {
        return;
    }

    auto& session = channelContext->session;
    (void)session->shutdownAndWait(false);
}

void RpcServerTrusty::handleChannelCleanup(void* ctx) {
    auto* channelContext = reinterpret_cast<ChannelContext*>(ctx);
    if (channelContext == nullptr) {
        return;
    }

    if (channelContext->isIncoming) {
        LOG_ALWAYS_FATAL_IF(!channelContext->session->removeIncomingConnection(
                                    channelContext->connection),
                            "bad state: connection object guaranteed to be in list");
    }

    delete channelContext;
}

} // namespace android
