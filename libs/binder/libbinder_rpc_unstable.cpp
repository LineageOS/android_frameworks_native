/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <binder_rpc_unstable.hpp>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <android/binder_libbinder.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <cutils/sockets.h>
#include <linux/vm_sockets.h>

using android::OK;
using android::RpcServer;
using android::RpcSession;
using android::sp;
using android::status_t;
using android::statusToString;
using android::base::unique_fd;

// Opaque handle for RpcServer.
struct ARpcServer {};

static sp<RpcServer> toRpcServer(ARpcServer* handle) {
    auto ref = reinterpret_cast<RpcServer*>(handle);
    return sp<RpcServer>::fromExisting(ref);
}

static ARpcServer* createRpcServerHandle(sp<RpcServer>& server) {
    auto ref = server.get();
    ref->incStrong(ref);
    return reinterpret_cast<ARpcServer*>(ref);
}

static void freeRpcServerHandle(ARpcServer* handle) {
    auto ref = reinterpret_cast<RpcServer*>(handle);
    ref->decStrong(ref);
}

extern "C" {

ARpcServer* ARpcServer_newVsock(AIBinder* service, unsigned int cid, unsigned int port) {
    auto server = RpcServer::make();

    unsigned int bindCid = VMADDR_CID_ANY; // bind to the remote interface
    if (cid == VMADDR_CID_LOCAL) {
        bindCid = VMADDR_CID_LOCAL; // bind to the local interface
        cid = VMADDR_CID_ANY;       // no need for a connection filter
    }

    if (status_t status = server->setupVsockServer(bindCid, port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock server with port " << port
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    if (cid != VMADDR_CID_ANY) {
        server->setConnectionFilter([=](const void* addr, size_t addrlen) {
            LOG_ALWAYS_FATAL_IF(addrlen < sizeof(sockaddr_vm), "sockaddr is truncated");
            const sockaddr_vm* vaddr = reinterpret_cast<const sockaddr_vm*>(addr);
            LOG_ALWAYS_FATAL_IF(vaddr->svm_family != AF_VSOCK, "address is not a vsock");
            if (cid != vaddr->svm_cid) {
                LOG(ERROR) << "Rejected vsock connection from CID " << vaddr->svm_cid;
                return false;
            }
            return true;
        });
    }
    server->setRootObject(AIBinder_toPlatformBinder(service));
    return createRpcServerHandle(server);
}

ARpcServer* ARpcServer_newInitUnixDomain(AIBinder* service, const char* name) {
    auto server = RpcServer::make();
    auto fd = unique_fd(android_get_control_socket(name));
    if (!fd.ok()) {
        LOG(ERROR) << "Failed to get fd for the socket:" << name;
        return nullptr;
    }
    if (status_t status = server->setupRawSocketServer(std::move(fd)); status != OK) {
        LOG(ERROR) << "Failed to set up Unix Domain RPC server with name " << name
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    server->setRootObject(AIBinder_toPlatformBinder(service));
    return createRpcServerHandle(server);
}

void ARpcServer_start(ARpcServer* handle) {
    toRpcServer(handle)->start();
}

void ARpcServer_join(ARpcServer* handle) {
    toRpcServer(handle)->join();
}

void ARpcServer_shutdown(ARpcServer* handle) {
    toRpcServer(handle)->shutdown();
}

void ARpcServer_free(ARpcServer* handle) {
    freeRpcServerHandle(handle);
}

AIBinder* VsockRpcClient(unsigned int cid, unsigned int port) {
    auto session = RpcSession::make();
    if (status_t status = session->setupVsockClient(cid, port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock client with CID " << cid << " and port " << port
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

AIBinder* UnixDomainRpcClient(const char* name) {
    std::string pathname(name);
    pathname = ANDROID_SOCKET_DIR "/" + pathname;
    auto session = RpcSession::make();
    if (status_t status = session->setupUnixDomainClient(pathname.c_str()); status != OK) {
        LOG(ERROR) << "Failed to set up Unix Domain RPC client with path: " << pathname
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

AIBinder* RpcPreconnectedClient(int (*requestFd)(void* param), void* param) {
    auto session = RpcSession::make();
    auto request = [=] { return unique_fd{requestFd(param)}; };
    if (status_t status = session->setupPreconnectedClient(unique_fd{}, request); status != OK) {
        LOG(ERROR) << "Failed to set up vsock client. error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}
}
