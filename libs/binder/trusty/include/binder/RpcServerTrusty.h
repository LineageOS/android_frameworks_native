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

#include <binder/ARpcServerTrusty.h>
#include <binder/IBinder.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransport.h>
#include <binder/unique_fd.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <map>
#include <vector>

#include <lib/tipc/tipc_srv.h>
#include <uapi/trusty_peer_id.h>

namespace android {

/**
 * This is the Trusty-specific RPC server code.
 */
class RpcServerTrusty final : public virtual RefBase {
public:
    // C++ equivalent to tipc_port_acl that uses safe data structures instead of
    // raw pointers, except for |extraData| which doesn't have a good
    // equivalent.
    struct PortAcl {
        uint32_t flags;
        std::vector<uuid> uuids;
        const void* extraData;
    };

    ~RpcServerTrusty();

    /**
     * Creates an RPC server listening on the given port and adds it to the
     * Trusty handle set at |handleSet|.
     *
     * The caller is responsible for calling tipc_run_event_loop() to start
     * the TIPC event loop after creating one or more services here.
     */
    static sp<RpcServerTrusty> make(
            tipc_hset* handleSet, std::string&& portName, std::shared_ptr<const PortAcl>&& portAcl,
            size_t msgMaxSize,
            size_t msgQueueLen,
            std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory = nullptr);

    [[nodiscard]] bool setProtocolVersion(uint32_t version) {
        return mRpcServer->setProtocolVersion(version);
    }
    void setSupportedFileDescriptorTransportModes(
            const std::vector<RpcSession::FileDescriptorTransportMode>& modes) {
        mRpcServer->setSupportedFileDescriptorTransportModes(modes);
    }
    void setRootObject(const sp<IBinder>& binder) { mRpcServer->setRootObject(binder); }
    void setRootObjectWeak(const wp<IBinder>& binder) { mRpcServer->setRootObjectWeak(binder); }
    /*
     * Assumes the peer (passed via the const void*, size_t pair) is specified
     * by a UUID. Deprecated. Use the version below that takes a trusty_peer_id.
     */
    void setPerSessionRootObject(std::function<sp<IBinder>(wp<RpcSession> session, const void* peer,
                                                           size_t peer_len)>&& create_root);
    void setPerSessionRootObject(
            std::function<sp<IBinder>(wp<RpcSession> session, const trusty_peer_id& peer,
                                      size_t peer_len)>&& create_root) {
        setPerSessionRootObjectInternal(mRpcServer.get(), std::move(create_root));
    }

    sp<IBinder> getRootObject() { return mRpcServer->getRootObject(); }

    status_t queueConnect(binder::unique_fd chan, const trusty_peer_id& peer, size_t peer_len);
    /**
     * For debugging!
     */
    std::vector<sp<RpcSession>> listSessions() { return mRpcServer->listSessions(); }

private:
    // Both this class and RpcServer have multiple non-copyable fields,
    // including mPortAcl below which can't be copied because mUuidPtrs
    // holds pointers into it
    RpcServerTrusty(const RpcServerTrusty&) = delete;
    void operator=(const RpcServerTrusty&) = delete;

    friend sp<RpcServerTrusty>;
    explicit RpcServerTrusty(std::unique_ptr<RpcTransportCtx> ctx, std::string&& portName,
                             std::shared_ptr<const PortAcl>&& portAcl, size_t msgMaxSize,
                             size_t msgQueueLen);

    // Internal helper that creates the RpcServer.
    // This is used both from here and Rust.
    static sp<RpcServer> makeRpcServer(std::unique_ptr<RpcTransportCtx> ctx) {
        auto rpcServer = sp<RpcServer>::make(std::move(ctx));

        // By default we use the latest stable version.
        LOG_ALWAYS_FATAL_IF(!rpcServer->setProtocolVersion(RPC_WIRE_PROTOCOL_VERSION));

        // The default behavior in trusty is to allow handles to be passed with tipc IPC.
        // We add mode NONE so that servers do not reject connections from clients who do
        // not change their default transport mode.
        [[clang::no_destroy]] static const std::vector<RpcSession::FileDescriptorTransportMode>
                TRUSTY_SERVER_SUPPORTED_FD_MODES = {RpcSession::FileDescriptorTransportMode::TRUSTY,
                                                    RpcSession::FileDescriptorTransportMode::NONE};

        rpcServer->setSupportedFileDescriptorTransportModes(TRUSTY_SERVER_SUPPORTED_FD_MODES);

        return rpcServer;
    }

    static void setPerSessionRootObjectInternal(
            RpcServer* server,
            std::function<sp<IBinder>(wp<RpcSession> session, const trusty_peer_id& peer,
                                      size_t peer_len)>&& create_session);

    friend struct ::ARpcServerTrusty;
    friend ::ARpcServerTrusty* ::ARpcServerTrusty_newPerSession(
            ::AIBinder* (*)(const trusty_peer_id*, size_t, void*), void*, void (*)(void*));
    friend void ::ARpcServerTrusty_delete(::ARpcServerTrusty*);
    friend int ::ARpcServerTrusty_handleConnect(::ARpcServerTrusty*, handle_t,
                                                const trusty_peer_id*, size_t, void**);
    friend int ::ARpcServerTrusty_handleMessage(void*);
    friend void ::ARpcServerTrusty_handleDisconnect(void*);
    friend void ::ARpcServerTrusty_handleChannelCleanup(void*);

    // The Rpc-specific context maintained for every open TIPC channel.
    struct ChannelContext {
        sp<RpcSession> session;
        sp<RpcSession::RpcConnection> connection;
        bool isIncoming = true;
    };

    static int handleConnect(const tipc_port* port, handle_t chan, const trusty_peer_id* peer,
                             size_t peer_len, void** ctx_p);
    static int handleMessage(const tipc_port* port, handle_t chan, void* ctx);
    static void handleDisconnect(const tipc_port* port, handle_t chan, void* ctx);
    static void handleChannelCleanup(void* ctx);

    static int handleConnectInternal(RpcServer* rpcServer, handle_t chan,
                                     const trusty_peer_id& peer, size_t peer_len, void** ctx_p);
    static int handleMessageInternal(void* ctx);
    static void handleDisconnectInternal(void* ctx);

    static constexpr tipc_srv_ops kTipcOps = {
            .on_connect_peer_id = &handleConnect,
            .on_message = &handleMessage,
            .on_disconnect = &handleDisconnect,
            .on_channel_cleanup = &handleChannelCleanup,
    };

    sp<RpcServer> mRpcServer;
    std::string mPortName;
    std::shared_ptr<const PortAcl> mPortAcl;
    std::vector<const uuid*> mUuidPtrs;
    tipc_port_acl mTipcPortAcl;
    tipc_port mTipcPort;
    tipc_port_ctx* mTipcPortCtx;
};

} // namespace android
