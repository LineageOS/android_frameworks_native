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
#include <android/binder_libbinder.h>
#include <android/persistable_bundle.h>
#include <binder/PersistableBundle.h>
#include <log/log.h>
#include <persistable_bundle_internal.h>
#include <string.h>

#include <set>

__BEGIN_DECLS

struct APersistableBundle {
    APersistableBundle(const APersistableBundle& pBundle) : mPBundle(pBundle.mPBundle) {}
    APersistableBundle(const android::os::PersistableBundle& pBundle) : mPBundle(pBundle) {}
    APersistableBundle() = default;
    android::os::PersistableBundle mPBundle;
};

APersistableBundle* _Nullable APersistableBundle_new() {
    return new (std::nothrow) APersistableBundle();
}

APersistableBundle* _Nullable APersistableBundle_dup(const APersistableBundle* pBundle) {
    if (pBundle) {
        return new APersistableBundle(*pBundle);
    } else {
        return new APersistableBundle();
    }
}

void APersistableBundle_delete(APersistableBundle* pBundle) {
    free(pBundle);
}

bool APersistableBundle_isEqual(const APersistableBundle* lhs, const APersistableBundle* rhs) {
    if (lhs && rhs) {
        return lhs->mPBundle == rhs->mPBundle;
    } else if (lhs == rhs) {
        return true;
    } else {
        return false;
    }
}

binder_status_t APersistableBundle_readFromParcel(const AParcel* parcel,
                                                  APersistableBundle* _Nullable* outPBundle) {
    if (!parcel || !outPBundle) return STATUS_BAD_VALUE;
    APersistableBundle* newPBundle = APersistableBundle_new();
    if (newPBundle == nullptr) return STATUS_NO_MEMORY;
    binder_status_t status =
            newPBundle->mPBundle.readFromParcel(AParcel_viewPlatformParcel(parcel));
    if (status == STATUS_OK) {
        *outPBundle = newPBundle;
    }
    return status;
}

binder_status_t APersistableBundle_writeToParcel(const APersistableBundle* pBundle,
                                                 AParcel* parcel) {
    if (!parcel || !pBundle) return STATUS_BAD_VALUE;
    return pBundle->mPBundle.writeToParcel(AParcel_viewPlatformParcel(parcel));
}

int32_t APersistableBundle_size(const APersistableBundle* pBundle) {
    size_t size = pBundle->mPBundle.size();
    LOG_ALWAYS_FATAL_IF(size > INT32_MAX,
                        "The APersistableBundle has gotten too large! There will be an overflow in "
                        "the reported size.");
    return pBundle->mPBundle.size();
}
int32_t APersistableBundle_erase(APersistableBundle* pBundle, const char* key) {
    return pBundle->mPBundle.erase(android::String16(key));
}
void APersistableBundle_putBoolean(APersistableBundle* pBundle, const char* key, bool val) {
    pBundle->mPBundle.putBoolean(android::String16(key), val);
}
void APersistableBundle_putInt(APersistableBundle* pBundle, const char* key, int32_t val) {
    pBundle->mPBundle.putInt(android::String16(key), val);
}
void APersistableBundle_putLong(APersistableBundle* pBundle, const char* key, int64_t val) {
    pBundle->mPBundle.putLong(android::String16(key), val);
}
void APersistableBundle_putDouble(APersistableBundle* pBundle, const char* key, double val) {
    pBundle->mPBundle.putDouble(android::String16(key), val);
}
void APersistableBundle_putString(APersistableBundle* pBundle, const char* key, const char* val) {
    pBundle->mPBundle.putString(android::String16(key), android::String16(val));
}
void APersistableBundle_putBooleanVector(APersistableBundle* pBundle, const char* key,
                                         const bool* vec, int32_t num) {
    LOG_ALWAYS_FATAL_IF(num < 0, "Negative number of elements is invalid.");
    std::vector<bool> newVec(num);
    for (int32_t i = 0; i < num; i++) {
        newVec[i] = vec[i];
    }
    pBundle->mPBundle.putBooleanVector(android::String16(key), newVec);
}
void APersistableBundle_putIntVector(APersistableBundle* pBundle, const char* key,
                                     const int32_t* vec, int32_t num) {
    LOG_ALWAYS_FATAL_IF(num < 0, "Negative number of elements is invalid.");
    std::vector<int32_t> newVec(num);
    for (int32_t i = 0; i < num; i++) {
        newVec[i] = vec[i];
    }
    pBundle->mPBundle.putIntVector(android::String16(key), newVec);
}
void APersistableBundle_putLongVector(APersistableBundle* pBundle, const char* key,
                                      const int64_t* vec, int32_t num) {
    LOG_ALWAYS_FATAL_IF(num < 0, "Negative number of elements is invalid.");
    std::vector<int64_t> newVec(num);
    for (int32_t i = 0; i < num; i++) {
        newVec[i] = vec[i];
    }
    pBundle->mPBundle.putLongVector(android::String16(key), newVec);
}
void APersistableBundle_putDoubleVector(APersistableBundle* pBundle, const char* key,
                                        const double* vec, int32_t num) {
    LOG_ALWAYS_FATAL_IF(num < 0, "Negative number of elements is invalid.");
    std::vector<double> newVec(num);
    for (int32_t i = 0; i < num; i++) {
        newVec[i] = vec[i];
    }
    pBundle->mPBundle.putDoubleVector(android::String16(key), newVec);
}
void APersistableBundle_putStringVector(APersistableBundle* pBundle, const char* key,
                                        const char* const* vec, int32_t num) {
    LOG_ALWAYS_FATAL_IF(num < 0, "Negative number of elements is invalid.");
    std::vector<android::String16> newVec(num);
    for (int32_t i = 0; i < num; i++) {
        newVec[i] = android::String16(vec[i]);
    }
    pBundle->mPBundle.putStringVector(android::String16(key), newVec);
}
void APersistableBundle_putPersistableBundle(APersistableBundle* pBundle, const char* key,
                                             const APersistableBundle* val) {
    pBundle->mPBundle.putPersistableBundle(android::String16(key), val->mPBundle);
}
bool APersistableBundle_getBoolean(const APersistableBundle* pBundle, const char* key, bool* val) {
    return pBundle->mPBundle.getBoolean(android::String16(key), val);
}
bool APersistableBundle_getInt(const APersistableBundle* pBundle, const char* key, int32_t* val) {
    return pBundle->mPBundle.getInt(android::String16(key), val);
}
bool APersistableBundle_getLong(const APersistableBundle* pBundle, const char* key, int64_t* val) {
    return pBundle->mPBundle.getLong(android::String16(key), val);
}
bool APersistableBundle_getDouble(const APersistableBundle* pBundle, const char* key, double* val) {
    return pBundle->mPBundle.getDouble(android::String16(key), val);
}
int32_t APersistableBundle_getString(const APersistableBundle* pBundle, const char* key, char** val,
                                     APersistableBundle_stringAllocator stringAllocator,
                                     void* context) {
    android::String16 outVal;
    bool ret = pBundle->mPBundle.getString(android::String16(key), &outVal);
    if (!ret) return APERSISTABLEBUNDLE_KEY_NOT_FOUND;
    android::String8 tmp8(outVal);
    *val = stringAllocator(tmp8.bytes() + 1, context);
    if (*val) {
        strncpy(*val, tmp8.c_str(), tmp8.bytes() + 1);
        return tmp8.bytes();
    } else {
        return APERSISTABLEBUNDLE_ALLOCATOR_FAILED;
    }
}
int32_t APersistableBundle_getBooleanVector(const APersistableBundle* pBundle, const char* key,
                                            bool* buffer, int32_t bufferSizeBytes) {
    std::vector<bool> newVec;
    bool ret = pBundle->mPBundle.getBooleanVector(android::String16(key), &newVec);
    if (!ret) return APERSISTABLEBUNDLE_KEY_NOT_FOUND;
    return getVecInternal<bool>(newVec, buffer, bufferSizeBytes);
}
int32_t APersistableBundle_getIntVector(const APersistableBundle* pBundle, const char* key,
                                        int32_t* buffer, int32_t bufferSizeBytes) {
    std::vector<int32_t> newVec;
    bool ret = pBundle->mPBundle.getIntVector(android::String16(key), &newVec);
    if (!ret) return APERSISTABLEBUNDLE_KEY_NOT_FOUND;
    return getVecInternal<int32_t>(newVec, buffer, bufferSizeBytes);
}
int32_t APersistableBundle_getLongVector(const APersistableBundle* pBundle, const char* key,
                                         int64_t* buffer, int32_t bufferSizeBytes) {
    std::vector<int64_t> newVec;
    bool ret = pBundle->mPBundle.getLongVector(android::String16(key), &newVec);
    if (!ret) return APERSISTABLEBUNDLE_KEY_NOT_FOUND;
    return getVecInternal<int64_t>(newVec, buffer, bufferSizeBytes);
}
int32_t APersistableBundle_getDoubleVector(const APersistableBundle* pBundle, const char* key,
                                           double* buffer, int32_t bufferSizeBytes) {
    std::vector<double> newVec;
    bool ret = pBundle->mPBundle.getDoubleVector(android::String16(key), &newVec);
    if (!ret) return APERSISTABLEBUNDLE_KEY_NOT_FOUND;
    return getVecInternal<double>(newVec, buffer, bufferSizeBytes);
}
int32_t APersistableBundle_getStringVector(const APersistableBundle* pBundle, const char* key,
                                           char** vec, int32_t bufferSizeBytes,
                                           APersistableBundle_stringAllocator stringAllocator,
                                           void* context) {
    std::vector<android::String16> newVec;
    bool ret = pBundle->mPBundle.getStringVector(android::String16(key), &newVec);
    if (!ret) return APERSISTABLEBUNDLE_KEY_NOT_FOUND;
    return getStringsInternal<std::vector<android::String16>>(newVec, vec, bufferSizeBytes,
                                                              stringAllocator, context);
}
bool APersistableBundle_getPersistableBundle(const APersistableBundle* pBundle, const char* key,
                                             APersistableBundle** outBundle) {
    APersistableBundle* bundle = APersistableBundle_new();
    bool ret = pBundle->mPBundle.getPersistableBundle(android::String16(key), &bundle->mPBundle);
    if (ret) {
        *outBundle = bundle;
        return true;
    }
    return false;
}
int32_t APersistableBundle_getBooleanKeys(const APersistableBundle* pBundle, char** outKeys,
                                          int32_t bufferSizeBytes,
                                          APersistableBundle_stringAllocator stringAllocator,
                                          void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getBooleanKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}
int32_t APersistableBundle_getIntKeys(const APersistableBundle* pBundle, char** outKeys,
                                      int32_t bufferSizeBytes,
                                      APersistableBundle_stringAllocator stringAllocator,
                                      void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getIntKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}
int32_t APersistableBundle_getLongKeys(const APersistableBundle* pBundle, char** outKeys,
                                       int32_t bufferSizeBytes,
                                       APersistableBundle_stringAllocator stringAllocator,
                                       void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getLongKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}
int32_t APersistableBundle_getDoubleKeys(const APersistableBundle* pBundle, char** outKeys,
                                         int32_t bufferSizeBytes,
                                         APersistableBundle_stringAllocator stringAllocator,
                                         void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getDoubleKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}
int32_t APersistableBundle_getStringKeys(const APersistableBundle* pBundle, char** outKeys,
                                         int32_t bufferSizeBytes,
                                         APersistableBundle_stringAllocator stringAllocator,
                                         void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getStringKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}
int32_t APersistableBundle_getBooleanVectorKeys(const APersistableBundle* pBundle, char** outKeys,
                                                int32_t bufferSizeBytes,
                                                APersistableBundle_stringAllocator stringAllocator,
                                                void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getBooleanVectorKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}
int32_t APersistableBundle_getIntVectorKeys(const APersistableBundle* pBundle, char** outKeys,
                                            int32_t bufferSizeBytes,
                                            APersistableBundle_stringAllocator stringAllocator,
                                            void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getIntVectorKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}
int32_t APersistableBundle_getLongVectorKeys(const APersistableBundle* pBundle, char** outKeys,
                                             int32_t bufferSizeBytes,
                                             APersistableBundle_stringAllocator stringAllocator,
                                             void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getLongVectorKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}
int32_t APersistableBundle_getDoubleVectorKeys(const APersistableBundle* pBundle, char** outKeys,
                                               int32_t bufferSizeBytes,
                                               APersistableBundle_stringAllocator stringAllocator,
                                               void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getDoubleVectorKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}
int32_t APersistableBundle_getStringVectorKeys(const APersistableBundle* pBundle, char** outKeys,
                                               int32_t bufferSizeBytes,
                                               APersistableBundle_stringAllocator stringAllocator,
                                               void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getStringVectorKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}
int32_t APersistableBundle_getPersistableBundleKeys(
        const APersistableBundle* pBundle, char** outKeys, int32_t bufferSizeBytes,
        APersistableBundle_stringAllocator stringAllocator, void* context) {
    std::set<android::String16> ret = pBundle->mPBundle.getPersistableBundleKeys();
    return getStringsInternal<std::set<android::String16>>(ret, outKeys, bufferSizeBytes,
                                                           stringAllocator, context);
}

__END_DECLS
