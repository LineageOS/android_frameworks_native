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

#include "../file.h"

#ifndef BINDER_NO_LIBBASE

namespace android::binder {
using android::base::GetExecutableDirectory;
using android::base::ReadFdToString;
using android::base::WriteStringToFd;
} // namespace android::binder

#else // BINDER_NO_LIBBASE

#include <binder/unique_fd.h>

#include <string_view>

#if !defined(_WIN32) && !defined(O_BINARY)
/** Windows needs O_BINARY, but Unix never mangles line endings. */
#define O_BINARY 0
#endif

namespace android::binder {

bool ReadFdToString(borrowed_fd fd, std::string* content);
bool WriteStringToFd(std::string_view content, borrowed_fd fd);

std::string GetExecutableDirectory();

} // namespace android::binder

#endif // BINDER_NO_LIBBASE
