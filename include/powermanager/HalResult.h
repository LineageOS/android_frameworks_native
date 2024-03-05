/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *                        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <android/binder_auto_utils.h>
#include <android/binder_status.h>
#include <android/hardware/power/1.0/IPower.h>
#include <binder/Status.h>
#include <hidl/HidlSupport.h>
#include <string>

namespace android::power {

static bool checkUnsupported(const ndk::ScopedAStatus& ndkStatus) {
    return ndkStatus.getExceptionCode() == EX_UNSUPPORTED_OPERATION ||
            ndkStatus.getStatus() == STATUS_UNKNOWN_TRANSACTION;
}

static bool checkUnsupported(const binder::Status& status) {
    return status.exceptionCode() == binder::Status::EX_UNSUPPORTED_OPERATION ||
            status.transactionError() == UNKNOWN_TRANSACTION;
}

// Result of a call to the Power HAL wrapper, holding data if successful.
template <typename T>
class HalResult {
public:
    static HalResult<T> ok(T&& value) { return HalResult(std::forward<T>(value)); }
    static HalResult<T> ok(T& value) { return HalResult<T>::ok(T{value}); }
    static HalResult<T> failed(std::string msg) { return HalResult(msg, /* unsupported= */ false); }
    static HalResult<T> unsupported() { return HalResult("", /* unsupported= */ true); }

    static HalResult<T> fromStatus(const binder::Status& status, T&& data) {
        if (checkUnsupported(status)) {
            return HalResult<T>::unsupported();
        }
        if (status.isOk()) {
            return HalResult<T>::ok(std::forward<T>(data));
        }
        return HalResult<T>::failed(std::string(status.toString8().c_str()));
    }

    static HalResult<T> fromStatus(const binder::Status& status, T& data) {
        return HalResult<T>::fromStatus(status, T{data});
    }

    static HalResult<T> fromStatus(const ndk::ScopedAStatus& ndkStatus, T&& data) {
        if (checkUnsupported(ndkStatus)) {
            return HalResult<T>::unsupported();
        }
        if (ndkStatus.isOk()) {
            return HalResult<T>::ok(std::forward<T>(data));
        }
        return HalResult<T>::failed(std::string(ndkStatus.getDescription()));
    }

    static HalResult<T> fromStatus(const ndk::ScopedAStatus& ndkStatus, T& data) {
        return HalResult<T>::fromStatus(ndkStatus, T{data});
    }

    template <typename R>
    static HalResult<T> fromReturn(hardware::Return<R>& ret, T&& data) {
        return ret.isOk() ? HalResult<T>::ok(std::forward<T>(data))
                          : HalResult<T>::failed(ret.description());
    }

    template <typename R>
    static HalResult<T> fromReturn(hardware::Return<R>& ret, T& data) {
        return HalResult<T>::fromReturn(ret, T{data});
    }

    template <typename R>
    static HalResult<T> fromReturn(hardware::Return<R>& ret, hardware::power::V1_0::Status status,
                                   T&& data) {
        return ret.isOk() ? HalResult<T>::fromStatus(status, std::forward<T>(data))
                          : HalResult<T>::failed(ret.description());
    }

    template <typename R>
    static HalResult<T> fromReturn(hardware::Return<R>& ret, hardware::power::V1_0::Status status,
                                   T& data) {
        return HalResult<T>::fromReturn(ret, status, T{data});
    }

    // This will throw std::bad_optional_access if this result is not ok.
    const T& value() const { return mValue.value(); }
    bool isOk() const { return !mUnsupported && mValue.has_value(); }
    bool isFailed() const { return !mUnsupported && !mValue.has_value(); }
    bool isUnsupported() const { return mUnsupported; }
    const char* errorMessage() const { return mErrorMessage.c_str(); }

private:
    std::optional<T> mValue;
    std::string mErrorMessage;
    bool mUnsupported;

    explicit HalResult(T&& value)
          : mValue{std::move(value)}, mErrorMessage(), mUnsupported(false) {}
    explicit HalResult(std::string errorMessage, bool unsupported)
          : mValue(), mErrorMessage(std::move(errorMessage)), mUnsupported(unsupported) {}
};

// Empty result
template <>
class HalResult<void> {
public:
    static HalResult<void> ok() { return HalResult(); }
    static HalResult<void> failed(std::string msg) { return HalResult(std::move(msg)); }
    static HalResult<void> unsupported() { return HalResult(/* unsupported= */ true); }

    static HalResult<void> fromStatus(const binder::Status& status) {
        if (checkUnsupported(status)) {
            return HalResult<void>::unsupported();
        }
        if (status.isOk()) {
            return HalResult<void>::ok();
        }
        return HalResult<void>::failed(std::string(status.toString8().c_str()));
    }

    static HalResult<void> fromStatus(const ndk::ScopedAStatus& ndkStatus) {
        if (ndkStatus.isOk()) {
            return HalResult<void>::ok();
        }
        if (checkUnsupported(ndkStatus)) {
            return HalResult<void>::unsupported();
        }
        return HalResult<void>::failed(ndkStatus.getDescription());
    }

    template <typename R>
    static HalResult<void> fromReturn(hardware::Return<R>& ret) {
        return ret.isOk() ? HalResult<void>::ok() : HalResult<void>::failed(ret.description());
    }

    bool isOk() const { return !mUnsupported && !mFailed; }
    bool isFailed() const { return !mUnsupported && mFailed; }
    bool isUnsupported() const { return mUnsupported; }
    const char* errorMessage() const { return mErrorMessage.c_str(); }

private:
    std::string mErrorMessage;
    bool mFailed;
    bool mUnsupported;

    explicit HalResult(bool unsupported = false)
          : mErrorMessage(), mFailed(false), mUnsupported(unsupported) {}
    explicit HalResult(std::string errorMessage)
          : mErrorMessage(std::move(errorMessage)), mFailed(true), mUnsupported(false) {}
};
} // namespace android::power
