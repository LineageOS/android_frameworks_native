/*
 * Copyright 2016 The Android Open Source Project
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

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#include <fmt/format.h>
#include <log/log.h>
#pragma clang diagnostic pop

#include <type_traits>

namespace android {
namespace gfx {

/* SafeLog is a mix-in that can be used to easily add typesafe logging using fmtlib to any class.
 * To use it, inherit from it using CRTP and implement the getLogTag method.
 *
 * For example:
 *
 * class Frobnicator : private SafeLog<Frobnicator> {
 *     friend class SafeLog<Frobnicator>;  // Allows getLogTag to be private
 *
 *   public:
 *     void frobnicate(int32_t i);
 *
 *   private:
 *     // SafeLog does member access on the object calling alog*, so this tag can theoretically vary
 *     // by instance unless getLogTag is made static
 *     const char* getLogTag() { return "Frobnicator"; }
 * };
 *
 * void Frobnicator::frobnicate(int32_t i) {
 *     // Logs something like "04-16 21:35:46.811  3513  3513 I Frobnicator: frobnicating 42"
 *     alogi("frobnicating {}", i);
 * }
 *
 * See http://fmtlib.net for more information on the formatting API.
 */

template <typename T>
class SafeLog {
  protected:
    template <typename... Args>
#if LOG_NDEBUG
    void alogv(Args&&... /*unused*/) const {
    }
#else
    void alogv(Args&&... args) const {
        alog<ANDROID_LOG_VERBOSE>(std::forward<Args>(args)...);
    }
#endif

    template <typename... Args>
    void alogd(Args&&... args) const {
        alog<ANDROID_LOG_DEBUG>(std::forward<Args>(args)...);
    }

    template <typename... Args>
    void alogi(Args&&... args) const {
        alog<ANDROID_LOG_INFO>(std::forward<Args>(args)...);
    }

    template <typename... Args>
    void alogw(Args&&... args) const {
        alog<ANDROID_LOG_WARN>(std::forward<Args>(args)...);
    }

    template <typename... Args>
    void aloge(Args&&... args) const {
        alog<ANDROID_LOG_ERROR>(std::forward<Args>(args)...);
    }

  private:
    // Suppresses clang-tidy check cppcoreguidelines-pro-bounds-array-to-pointer-decay
    template <size_t strlen, typename... Args>
    void write(fmt::MemoryWriter* writer, const char (&str)[strlen], Args&&... args) const {
        writer->write(static_cast<const char*>(str), std::forward<Args>(args)...);
    }

    template <int priority, typename... Args>
    void alog(Args&&... args) const {
        static_assert(std::is_base_of<SafeLog<T>, T>::value, "Can't convert to SafeLog pointer");
        fmt::MemoryWriter writer;
        write(&writer, std::forward<Args>(args)...);
        auto derivedThis = static_cast<const T*>(this);
        android_writeLog(priority, derivedThis->getLogTag(), writer.c_str());
    }
};

}  // namespace gfx
}  // namespace android
