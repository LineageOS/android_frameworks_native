/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <fuzzbinder/random_fd.h>

#include <fcntl.h>

#include <android-base/logging.h>
#include <cutils/ashmem.h>

namespace android {

using base::unique_fd;

std::vector<unique_fd> getRandomFds(FuzzedDataProvider* provider) {
    const char* fdType;

    std::vector<unique_fd> fds = provider->PickValueInArray<
            std::function<std::vector<unique_fd>()>>({
            [&]() {
                fdType = "ashmem";
                std::vector<unique_fd> ret;
                ret.push_back(unique_fd(
                        ashmem_create_region("binder test region",
                                             provider->ConsumeIntegralInRange<size_t>(0, 4096))));
                return ret;
            },
            [&]() {
                fdType = "/dev/null";
                std::vector<unique_fd> ret;
                ret.push_back(unique_fd(open("/dev/null", O_RDWR)));
                return ret;
            },
            [&]() {
                fdType = "pipefd";

                int pipefds[2];

                int flags = O_CLOEXEC;
                if (provider->ConsumeBool()) flags |= O_DIRECT;
                if (provider->ConsumeBool()) flags |= O_NONBLOCK;

                CHECK_EQ(0, pipe2(pipefds, flags)) << flags;

                if (provider->ConsumeBool()) std::swap(pipefds[0], pipefds[1]);

                std::vector<unique_fd> ret;
                ret.push_back(unique_fd(pipefds[0]));
                ret.push_back(unique_fd(pipefds[1]));
                return ret;
            },
    })();

    for (const auto& fd : fds) CHECK(fd.ok()) << fd.get() << " " << fdType;

    return fds;
}

} // namespace android
