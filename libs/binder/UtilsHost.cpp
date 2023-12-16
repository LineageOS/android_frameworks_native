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

#include "UtilsHost.h"

#include <poll.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sstream>

#include <log/log.h>

#include "FdUtils.h"
#include "Utils.h"

namespace android {

using android::binder::unique_fd;

CommandResult::~CommandResult() {
    if (!pid.has_value()) return;
    if (*pid == 0) {
        ALOGW("%s: PID is unexpectedly 0, won't kill it", __PRETTY_FUNCTION__);
        return;
    }

    ALOGE_IF(kill(*pid, SIGKILL) != 0, "kill(%d): %s", *pid, strerror(errno));

    while (pid.has_value()) {
        int status;
        LOG_HOST("%s: Waiting for PID %d to exit.", __PRETTY_FUNCTION__, *pid);
        int waitres = waitpid(*pid, &status, 0);
        if (waitres == -1) {
            ALOGE("%s: waitpid(%d): %s", __PRETTY_FUNCTION__, *pid, strerror(errno));
            break;
        }
        if (WIFEXITED(status)) {
            LOG_HOST("%s: PID %d exited.", __PRETTY_FUNCTION__, *pid);
            pid.reset();
        } else if (WIFSIGNALED(status)) {
            LOG_HOST("%s: PID %d terminated by signal %d.", __PRETTY_FUNCTION__, *pid,
                     WTERMSIG(status));
            pid.reset();
        } else if (WIFSTOPPED(status)) {
            ALOGW("%s: pid %d stopped", __PRETTY_FUNCTION__, *pid);
        } else if (WIFCONTINUED(status)) {
            ALOGW("%s: pid %d continued", __PRETTY_FUNCTION__, *pid);
        }
    }
}

std::ostream& operator<<(std::ostream& os, const CommandResult& res) {
    if (res.exitCode) os << "code=" << *res.exitCode;
    if (res.signal) os << "signal=" << *res.signal;
    if (res.pid) os << ", pid=" << *res.pid;
    return os << ", stdout=" << res.stdoutStr << ", stderr=" << res.stderrStr;
}

std::string CommandResult::toString() const {
    std::stringstream ss;
    ss << (*this);
    return ss.str();
}

std::optional<CommandResult> execute(std::vector<std::string> argStringVec,
                                     const std::function<bool(const CommandResult&)>& end) {
    // turn vector<string> into null-terminated char* vector.
    std::vector<char*> argv;
    argv.reserve(argStringVec.size() + 1);
    for (auto& arg : argStringVec) argv.push_back(arg.data());
    argv.push_back(nullptr);

    CommandResult ret;
    unique_fd outWrite;
    if (!binder::Pipe(&ret.outPipe, &outWrite)) {
        PLOGE("pipe() for outPipe");
        return {};
    }
    unique_fd errWrite;
    if (!binder::Pipe(&ret.errPipe, &errWrite)) {
        PLOGE("pipe() for errPipe");
        return {};
    }

    int pid = fork();
    if (pid == -1) {
        PLOGE("fork()");
        return {};
    }
    if (pid == 0) {
        // child
        ret.outPipe.reset();
        ret.errPipe.reset();

        int res = TEMP_FAILURE_RETRY(dup2(outWrite.get(), STDOUT_FILENO));
        LOG_ALWAYS_FATAL_IF(-1 == res, "dup2(outPipe): %s", strerror(errno));
        outWrite.reset();

        res = TEMP_FAILURE_RETRY(dup2(errWrite.get(), STDERR_FILENO));
        LOG_ALWAYS_FATAL_IF(-1 == res, "dup2(errPipe): %s", strerror(errno));
        errWrite.reset();

        execvp(argv[0], argv.data());
        LOG_ALWAYS_FATAL("execvp() returns");
    }
    // parent
    outWrite.reset();
    errWrite.reset();
    ret.pid = pid;

    auto handlePoll = [](unique_fd* fd, const pollfd* pfd, std::string* s) {
        if (!fd->ok()) return true;
        if (pfd->revents & POLLIN) {
            char buf[1024];
            ssize_t n = TEMP_FAILURE_RETRY(read(fd->get(), buf, sizeof(buf)));
            if (n < 0) return false;
            if (n > 0) *s += std::string_view(buf, n);
        }
        if (pfd->revents & POLLHUP) {
            fd->reset();
        }
        return true;
    };

    // Drain both stdout and stderr. Check end() regularly until both are closed.
    while (ret.outPipe.ok() || ret.errPipe.ok()) {
        pollfd fds[2];
        pollfd *outPollFd = nullptr, *errPollFd = nullptr;
        memset(fds, 0, sizeof(fds));
        nfds_t nfds = 0;
        if (ret.outPipe.ok()) {
            outPollFd = &fds[nfds++];
            *outPollFd = {.fd = ret.outPipe.get(), .events = POLLIN};
        }
        if (ret.errPipe.ok()) {
            errPollFd = &fds[nfds++];
            *errPollFd = {.fd = ret.errPipe.get(), .events = POLLIN};
        }
        int pollRet = poll(fds, nfds, 1000 /* ms timeout */);
        if (pollRet == -1) {
            PLOGE("poll()");
            return {};
        }

        if (!handlePoll(&ret.outPipe, outPollFd, &ret.stdoutStr)) {
            PLOGE("read(stdout)");
            return {};
        }
        if (!handlePoll(&ret.errPipe, errPollFd, &ret.stderrStr)) {
            PLOGE("read(stderr)");
            return {};
        }

        if (end && end(ret)) return ret;
    }

    // If both stdout and stderr are closed by the subprocess, it may or may not be terminated.
    while (ret.pid.has_value()) {
        int status;
        auto exitPid = waitpid(pid, &status, 0);
        if (exitPid == -1) {
            PLOGE("waitpid(%d)", pid);
            return {};
        }
        if (exitPid == pid) {
            if (WIFEXITED(status)) {
                ret.pid = std::nullopt;
                ret.exitCode = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                ret.pid = std::nullopt;
                ret.signal = WTERMSIG(status);
            } else if (WIFSTOPPED(status)) {
                ALOGW("%s: pid %d stopped", __PRETTY_FUNCTION__, *ret.pid);
            } else if (WIFCONTINUED(status)) {
                ALOGW("%s: pid %d continued", __PRETTY_FUNCTION__, *ret.pid);
            }
        }
        // ret is not changed unless the process is terminated (where pid == nullopt). Hence there
        // is no need to check the predicate `end(ret)`.
    }

    return ret;
}
} // namespace android
