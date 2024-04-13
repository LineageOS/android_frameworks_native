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
#pragma once

#include <lib/tipc/tipc_srv.h>

#if defined(__cplusplus)
extern "C" {
#endif

struct AIBinder;
struct ARpcServerTrusty;

struct ARpcServerTrusty* ARpcServerTrusty_newPerSession(struct AIBinder* (*)(const void*, size_t,
                                                                             char*),
                                                        char*, void (*)(char*));
void ARpcServerTrusty_delete(struct ARpcServerTrusty*);
int ARpcServerTrusty_handleConnect(struct ARpcServerTrusty*, handle_t, const struct uuid*, void**);
int ARpcServerTrusty_handleMessage(void*);
void ARpcServerTrusty_handleDisconnect(void*);
void ARpcServerTrusty_handleChannelCleanup(void*);

#if defined(__cplusplus)
}
#endif
