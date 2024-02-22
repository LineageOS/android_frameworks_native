/*
 * Copyright 2023 The Android Open Source Project
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

#include <android-base/expected.h>
#include <utils/Errors.h>

namespace android::ui {

enum class ErrorCode : int32_t {
    /**
     * No error.
     */
    None = 0,
    /**
     * Invalid BufferDescriptor.
     */
    BadDescriptor = 1,
    /**
     * Invalid buffer handle.
     */
    BadBuffer = 2,
    /**
     * Invalid HardwareBufferDescription.
     */
    BadValue = 3,
    /**
     * Resource unavailable.
     */
    NoResources = 5,
    /**
     * Permanent failure.
     */
    Unsupported = 7,
};

class Error {
public:
    Error(ErrorCode err) : mCode(err) {}

    Error(ErrorCode err, std::string&& message) : mCode(err), mMessage(std::move(message)) {}
    Error(ErrorCode err, const std::string_view& message) : mCode(err), mMessage(message) {}

    static constexpr status_t codeToStatus(ErrorCode code) {
        switch (code) {
            case ErrorCode::None:
                return OK;
            case ErrorCode::BadDescriptor:
                return BAD_VALUE;
            case ErrorCode::BadValue:
                return BAD_VALUE;
            case ErrorCode::BadBuffer:
                return BAD_TYPE;
            case ErrorCode::NoResources:
                return NO_MEMORY;
            case ErrorCode::Unsupported:
                return INVALID_OPERATION;
            default:
                return UNKNOWN_ERROR;
        }
    }

    static constexpr ErrorCode statusToCode(status_t status) {
        switch (status) {
            case OK:
                return ErrorCode::None;
            case BAD_VALUE:
                return ErrorCode::BadValue;
            case BAD_TYPE:
                return ErrorCode::BadBuffer;
            case NO_MEMORY:
                return ErrorCode::NoResources;
            case INVALID_OPERATION:
                return ErrorCode::Unsupported;
            default:
                return ErrorCode::Unsupported;
        }
    }

    constexpr status_t asStatus() const { return codeToStatus(mCode); }

    ErrorCode code() const { return mCode; }

    const std::string& message() const { return mMessage; }

    bool operator==(const ErrorCode code) { return mCode == code; }

private:
    ErrorCode mCode;
    std::string mMessage;
};

template <typename T>
class Result : public base::expected<T, Error> {
public:
    using base::expected<T, Error>::expected;

    [[nodiscard]] constexpr status_t asStatus() const {
        return this->has_value() ? OK : this->error().asStatus();
    }

    [[nodiscard]] constexpr ErrorCode errorCode() const {
        return this->has_value() ? ErrorCode::None : this->error().code();
    }
};

} // namespace android::ui
