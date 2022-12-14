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

#pragma once

#include <sys/socket.h>
#include <stdint.h>

extern "C" {

struct AIBinder;
struct ARpcServer;

// Starts an RPC server on a given port and a given root IBinder object.
// The server will only accept connections from the given CID.
// Set `cid` to VMADDR_CID_ANY to accept connections from any client.
// Set `cid` to VMADDR_CID_LOCAL to only bind to the local vsock interface.
// Returns an opaque handle to the running server instance, or null if the server
// could not be started.
[[nodiscard]] ARpcServer* ARpcServer_newVsock(AIBinder* service, unsigned int cid,
                                              unsigned int port);

// Starts a Unix domain RPC server with a given init-managed Unix domain `name`
// and a given root IBinder object.
// The socket should be created in init.rc with the same `name`.
// Returns an opaque handle to the running server instance, or null if the server
// could not be started.
[[nodiscard]] ARpcServer* ARpcServer_newInitUnixDomain(AIBinder* service, const char* name);

// Runs ARpcServer_join() in a background thread. Immediately returns.
void ARpcServer_start(ARpcServer* server);

// Joins the thread of a running RpcServer instance. At any given point, there
// can only be one thread calling ARpcServer_join().
// If a client needs to actively terminate join, call ARpcServer_shutdown() in
// a separate thread.
void ARpcServer_join(ARpcServer* server);

// Shuts down any running ARpcServer_join().
void ARpcServer_shutdown(ARpcServer* server);

// Frees the ARpcServer handle and drops the reference count on the underlying
// RpcServer instance. The handle must not be reused afterwards.
// This automatically calls ARpcServer_shutdown().
void ARpcServer_free(ARpcServer* server);

AIBinder* VsockRpcClient(unsigned int cid, unsigned int port);

// Gets the service via the RPC binder with Unix domain socket with the given
// Unix socket `name`.
// The final Unix domain socket path name is /dev/socket/`name`.
AIBinder* UnixDomainRpcClient(const char* name);

// Connect to an RPC server with preconnected file descriptors.
//
// requestFd should connect to the server and return a valid file descriptor, or
// -1 if connection fails.
//
// param will be passed to requestFd. Callers can use param to pass contexts to
// the requestFd function.
AIBinder* RpcPreconnectedClient(int (*requestFd)(void* param), void* param);
}
