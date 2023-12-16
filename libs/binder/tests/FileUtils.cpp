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

#include "FileUtils.h"

#ifdef BINDER_NO_LIBBASE

#include <sys/stat.h>
#include <filesystem>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#if defined(_WIN32)
#include <direct.h>
#include <windows.h>
#endif

namespace android::binder {

bool ReadFdToString(borrowed_fd fd, std::string* content) {
    content->clear();

    // Although original we had small files in mind, this code gets used for
    // very large files too, where the std::string growth heuristics might not
    // be suitable. https://code.google.com/p/android/issues/detail?id=258500.
    struct stat sb;
    if (fstat(fd.get(), &sb) != -1 && sb.st_size > 0) {
        content->reserve(sb.st_size);
    }

    char buf[4096] __attribute__((__uninitialized__));
    ssize_t n;
    while ((n = TEMP_FAILURE_RETRY(read(fd.get(), &buf[0], sizeof(buf)))) > 0) {
        content->append(buf, n);
    }
    return (n == 0) ? true : false;
}

bool WriteStringToFd(std::string_view content, borrowed_fd fd) {
    const char* p = content.data();
    size_t left = content.size();
    while (left > 0) {
        ssize_t n = TEMP_FAILURE_RETRY(write(fd.get(), p, left));
        if (n == -1) {
            return false;
        }
        p += n;
        left -= n;
    }
    return true;
}

static std::filesystem::path GetExecutablePath2() {
#if defined(__linux__)
    return std::filesystem::read_symlink("/proc/self/exe");
#elif defined(__APPLE__)
    char path[PATH_MAX + 1];
    uint32_t path_len = sizeof(path);
    int rc = _NSGetExecutablePath(path, &path_len);
    if (rc < 0) {
        std::unique_ptr<char> path_buf(new char[path_len]);
        _NSGetExecutablePath(path_buf.get(), &path_len);
        return path_buf.get();
    }
    return path;
#elif defined(_WIN32)
    char path[PATH_MAX + 1];
    DWORD result = GetModuleFileName(NULL, path, sizeof(path) - 1);
    if (result == 0 || result == sizeof(path) - 1) return "";
    path[PATH_MAX - 1] = 0;
    return path;
#elif defined(__EMSCRIPTEN__)
    abort();
#else
#error unknown OS
#endif
}

std::string GetExecutableDirectory() {
    return GetExecutablePath2().parent_path();
}

} // namespace android::binder

#endif // BINDER_NO_LIBBASE
