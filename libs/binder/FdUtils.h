/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <binder/unique_fd.h>

#if defined(_WIN32) || defined(__TRUSTY__)
// Pipe and Socketpair are missing there
#elif !defined(BINDER_NO_LIBBASE)

namespace android::binder {
using android::base::Pipe;
using android::base::Socketpair;
} // namespace android::binder

#else // BINDER_NO_LIBBASE

#include <sys/socket.h>

namespace android::binder {

// Inline functions, so that they can be used header-only.

// See pipe(2).
// This helper hides the details of converting to unique_fd, and also hides the
// fact that macOS doesn't support O_CLOEXEC or O_NONBLOCK directly.
inline bool Pipe(unique_fd* read, unique_fd* write, int flags = O_CLOEXEC) {
    int pipefd[2];

#if defined(__APPLE__)
    if (flags & ~(O_CLOEXEC | O_NONBLOCK)) {
        return false;
    }
    if (pipe(pipefd) != 0) {
        return false;
    }

    if (flags & O_CLOEXEC) {
        if (fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) != 0 ||
            fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) != 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            return false;
        }
    }
    if (flags & O_NONBLOCK) {
        if (fcntl(pipefd[0], F_SETFL, O_NONBLOCK) != 0 ||
            fcntl(pipefd[1], F_SETFL, O_NONBLOCK) != 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            return false;
        }
    }
#else
    if (pipe2(pipefd, flags) != 0) {
        return false;
    }
#endif

    read->reset(pipefd[0]);
    write->reset(pipefd[1]);
    return true;
}

// See socketpair(2).
// This helper hides the details of converting to unique_fd.
inline bool Socketpair(int domain, int type, int protocol, unique_fd* left, unique_fd* right) {
    int sockfd[2];
    if (socketpair(domain, type, protocol, sockfd) != 0) {
        return false;
    }
    left->reset(sockfd[0]);
    right->reset(sockfd[1]);
    return true;
}

// See socketpair(2).
// This helper hides the details of converting to unique_fd.
inline bool Socketpair(int type, unique_fd* left, unique_fd* right) {
    return Socketpair(AF_UNIX, type, 0, left, right);
}

} // namespace android::binder

#endif // BINDER_NO_LIBBASE
