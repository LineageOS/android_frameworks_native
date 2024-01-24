/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *            http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <aidl/android/hardware/power/Boost.h>
#include <aidl/android/hardware/power/ChannelConfig.h>
#include <aidl/android/hardware/power/IPower.h>
#include <aidl/android/hardware/power/IPowerHintSession.h>
#include <aidl/android/hardware/power/Mode.h>
#include <aidl/android/hardware/power/SessionConfig.h>
#include <android-base/thread_annotations.h>
#include <android/hardware/power/1.1/IPower.h>
#include <android/hardware/power/1.2/IPower.h>
#include <android/hardware/power/1.3/IPower.h>
#include <binder/Status.h>

#include <utility>

namespace android {

namespace power {

// State of Power HAL support for individual apis.
enum class HalSupport {
    UNKNOWN = 0,
    ON = 1,
    OFF = 2,
};

// Result of a call to the Power HAL wrapper, holding data if successful.
template <typename T>
class HalResult {
public:
    static HalResult<T> ok(T&& value) { return HalResult(std::forward<T>(value)); }
    static HalResult<T> ok(T& value) { return HalResult<T>::ok(T{value}); }
    static HalResult<T> failed(std::string msg) { return HalResult(msg, /* unsupported= */ false); }
    static HalResult<T> unsupported() { return HalResult("", /* unsupported= */ true); }

    static HalResult<T> fromStatus(const binder::Status& status, T&& data) {
        if (status.exceptionCode() == binder::Status::EX_UNSUPPORTED_OPERATION) {
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

    static HalResult<T> fromStatus(const ndk::ScopedAStatus& status, T&& data) {
        if (status.getExceptionCode() == binder::Status::EX_UNSUPPORTED_OPERATION) {
            return HalResult<T>::unsupported();
        }
        if (status.isOk()) {
            return HalResult<T>::ok(std::forward<T>(data));
        }
        return HalResult<T>::failed(std::string(status.getDescription()));
    }

    static HalResult<T> fromStatus(const ndk::ScopedAStatus& status, T& data) {
        return HalResult<T>::fromStatus(status, T{data});
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

// Empty result of a call to the Power HAL wrapper.
template <>
class HalResult<void> {
public:
    static HalResult<void> ok() { return HalResult(); }
    static HalResult<void> failed(std::string msg) { return HalResult(std::move(msg)); }
    static HalResult<void> unsupported() { return HalResult(/* unsupported= */ true); }

    static HalResult<void> fromStatus(const binder::Status& status) {
        if (status.exceptionCode() == binder::Status::EX_UNSUPPORTED_OPERATION) {
            return HalResult<void>::unsupported();
        }
        if (status.isOk()) {
            return HalResult<void>::ok();
        }
        return HalResult<void>::failed(std::string(status.toString8().c_str()));
    }

    static HalResult<void> fromStatus(const ndk::ScopedAStatus& status) {
        if (status.getExceptionCode() == binder::Status::EX_UNSUPPORTED_OPERATION) {
            return HalResult<void>::unsupported();
        }
        if (status.isOk()) {
            return HalResult<void>::ok();
        }
        return HalResult<void>::failed(std::string(status.getDescription()));
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

// Wrapper for Power HAL handlers.
class HalWrapper {
public:
    virtual ~HalWrapper() = default;

    virtual HalResult<void> setBoost(aidl::android::hardware::power::Boost boost,
                                     int32_t durationMs) = 0;
    virtual HalResult<void> setMode(aidl::android::hardware::power::Mode mode, bool enabled) = 0;
    virtual HalResult<std::shared_ptr<aidl::android::hardware::power::IPowerHintSession>>
    createHintSession(int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
                      int64_t durationNanos) = 0;
    virtual HalResult<std::shared_ptr<aidl::android::hardware::power::IPowerHintSession>>
    createHintSessionWithConfig(int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
                                int64_t durationNanos,
                                aidl::android::hardware::power::SessionTag tag,
                                aidl::android::hardware::power::SessionConfig* config) = 0;
    virtual HalResult<int64_t> getHintSessionPreferredRate() = 0;
    virtual HalResult<aidl::android::hardware::power::ChannelConfig> getSessionChannel(int tgid,
                                                                                       int uid) = 0;
    virtual HalResult<void> closeSessionChannel(int tgid, int uid) = 0;
};

// Empty Power HAL wrapper that ignores all api calls.
class EmptyHalWrapper : public HalWrapper {
public:
    EmptyHalWrapper() = default;
    ~EmptyHalWrapper() override = default;

    HalResult<void> setBoost(aidl::android::hardware::power::Boost boost,
                             int32_t durationMs) override;
    HalResult<void> setMode(aidl::android::hardware::power::Mode mode, bool enabled) override;
    HalResult<std::shared_ptr<aidl::android::hardware::power::IPowerHintSession>> createHintSession(
            int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
            int64_t durationNanos) override;
    HalResult<std::shared_ptr<aidl::android::hardware::power::IPowerHintSession>>
    createHintSessionWithConfig(int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
                                int64_t durationNanos,
                                aidl::android::hardware::power::SessionTag tag,
                                aidl::android::hardware::power::SessionConfig* config) override;
    HalResult<int64_t> getHintSessionPreferredRate() override;
    HalResult<aidl::android::hardware::power::ChannelConfig> getSessionChannel(int tgid,
                                                                               int uid) override;
    HalResult<void> closeSessionChannel(int tgid, int uid) override;

protected:
    virtual const char* getUnsupportedMessage();
};

// Wrapper for the HIDL Power HAL v1.0.
class HidlHalWrapperV1_0 : public EmptyHalWrapper {
public:
    explicit HidlHalWrapperV1_0(sp<hardware::power::V1_0::IPower> handleV1_0)
          : mHandleV1_0(std::move(handleV1_0)) {}
    ~HidlHalWrapperV1_0() override = default;

    HalResult<void> setBoost(aidl::android::hardware::power::Boost boost,
                             int32_t durationMs) override;
    HalResult<void> setMode(aidl::android::hardware::power::Mode mode, bool enabled) override;

protected:
    const sp<hardware::power::V1_0::IPower> mHandleV1_0;
    virtual HalResult<void> sendPowerHint(hardware::power::V1_3::PowerHint hintId, uint32_t data);
    const char* getUnsupportedMessage();

private:
    HalResult<void> setInteractive(bool enabled);
    HalResult<void> setFeature(hardware::power::V1_0::Feature feature, bool enabled);
};

// Wrapper for the HIDL Power HAL v1.1.
class HidlHalWrapperV1_1 : public HidlHalWrapperV1_0 {
public:
    explicit HidlHalWrapperV1_1(sp<hardware::power::V1_1::IPower> handleV1_1)
          : HidlHalWrapperV1_0(std::move(handleV1_1)) {}
    ~HidlHalWrapperV1_1() override = default;

protected:
    HalResult<void> sendPowerHint(hardware::power::V1_3::PowerHint hintId, uint32_t data) override;
};

// Wrapper for the HIDL Power HAL v1.2.
class HidlHalWrapperV1_2 : public HidlHalWrapperV1_1 {
public:
    HalResult<void> setBoost(aidl::android::hardware::power::Boost boost,
                             int32_t durationMs) override;
    HalResult<void> setMode(aidl::android::hardware::power::Mode mode, bool enabled) override;
    explicit HidlHalWrapperV1_2(sp<hardware::power::V1_2::IPower> handleV1_2)
          : HidlHalWrapperV1_1(std::move(handleV1_2)) {}
    ~HidlHalWrapperV1_2() override = default;

protected:
    HalResult<void> sendPowerHint(hardware::power::V1_3::PowerHint hintId, uint32_t data) override;
};

// Wrapper for the HIDL Power HAL v1.3.
class HidlHalWrapperV1_3 : public HidlHalWrapperV1_2 {
public:
    HalResult<void> setMode(aidl::android::hardware::power::Mode mode, bool enabled) override;
    explicit HidlHalWrapperV1_3(sp<hardware::power::V1_3::IPower> handleV1_3)
          : HidlHalWrapperV1_2(std::move(handleV1_3)) {}
    ~HidlHalWrapperV1_3() override = default;

protected:
    HalResult<void> sendPowerHint(hardware::power::V1_3::PowerHint hintId, uint32_t data) override;
};

// Wrapper for the AIDL Power HAL.
class AidlHalWrapper : public EmptyHalWrapper {
public:
    explicit AidlHalWrapper(std::shared_ptr<aidl::android::hardware::power::IPower> handle)
          : mHandle(std::move(handle)) {}
    ~AidlHalWrapper() override = default;

    HalResult<void> setBoost(aidl::android::hardware::power::Boost boost,
                             int32_t durationMs) override;
    HalResult<void> setMode(aidl::android::hardware::power::Mode mode, bool enabled) override;
    HalResult<std::shared_ptr<aidl::android::hardware::power::IPowerHintSession>> createHintSession(
            int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
            int64_t durationNanos) override;
    HalResult<std::shared_ptr<aidl::android::hardware::power::IPowerHintSession>>
    createHintSessionWithConfig(int32_t tgid, int32_t uid, const std::vector<int32_t>& threadIds,
                                int64_t durationNanos,
                                aidl::android::hardware::power::SessionTag tag,
                                aidl::android::hardware::power::SessionConfig* config) override;

    HalResult<int64_t> getHintSessionPreferredRate() override;
    HalResult<aidl::android::hardware::power::ChannelConfig> getSessionChannel(int tgid,
                                                                               int uid) override;
    HalResult<void> closeSessionChannel(int tgid, int uid) override;

protected:
    const char* getUnsupportedMessage() override;

private:
    // Control access to the boost and mode supported arrays.
    std::mutex mBoostMutex;
    std::mutex mModeMutex;
    std::shared_ptr<aidl::android::hardware::power::IPower> mHandle;
    // Android framework only sends boost upto DISPLAY_UPDATE_IMMINENT.
    // Need to increase the array size if more boost supported.
    std::array<
            std::atomic<HalSupport>,
            static_cast<int32_t>(aidl::android::hardware::power::Boost::DISPLAY_UPDATE_IMMINENT) +
                    1>
            mBoostSupportedArray GUARDED_BY(mBoostMutex) = {HalSupport::UNKNOWN};
    std::array<std::atomic<HalSupport>,
               static_cast<int32_t>(
                       *(ndk::enum_range<aidl::android::hardware::power::Mode>().end() - 1)) +
                       1>
            mModeSupportedArray GUARDED_BY(mModeMutex) = {HalSupport::UNKNOWN};
};

}; // namespace power

}; // namespace android
