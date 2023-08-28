/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <binder/Status.h>

// Extracted from frameworks/av/media/libaudioclient/include/media/AidlConversionUtil.h
namespace android::gui::aidl_utils {

/**
 * Return the equivalent Android status_t from a binder exception code.
 *
 * Generally one should use statusTFromBinderStatus() instead.
 *
 * Exception codes can be generated from a remote Java service exception, translate
 * them for use on the Native side.
 *
 * Note: for EX_TRANSACTION_FAILED and EX_SERVICE_SPECIFIC a more detailed error code
 * can be found from transactionError() or serviceSpecificErrorCode().
 */
static inline status_t statusTFromExceptionCode(int32_t exceptionCode) {
    using namespace ::android::binder;
    switch (exceptionCode) {
        case Status::EX_NONE:
            return OK;
        case Status::EX_SECURITY: // Java SecurityException, rethrows locally in Java
            return PERMISSION_DENIED;
        case Status::EX_BAD_PARCELABLE:   // Java BadParcelableException, rethrows in Java
        case Status::EX_ILLEGAL_ARGUMENT: // Java IllegalArgumentException, rethrows in Java
        case Status::EX_NULL_POINTER:     // Java NullPointerException, rethrows in Java
            return BAD_VALUE;
        case Status::EX_ILLEGAL_STATE:         // Java IllegalStateException, rethrows in Java
        case Status::EX_UNSUPPORTED_OPERATION: // Java UnsupportedOperationException, rethrows
            return INVALID_OPERATION;
        case Status::EX_HAS_REPLY_HEADER: // Native strictmode violation
        case Status::EX_PARCELABLE: // Java bootclass loader (not standard exception), rethrows
        case Status::EX_NETWORK_MAIN_THREAD: // Java NetworkOnMainThreadException, rethrows
        case Status::EX_TRANSACTION_FAILED:  // Native - see error code
        case Status::EX_SERVICE_SPECIFIC:    // Java ServiceSpecificException,
                                             // rethrows in Java with integer error code
            return UNKNOWN_ERROR;
    }
    return UNKNOWN_ERROR;
}

/**
 * Return the equivalent Android status_t from a binder status.
 *
 * Used to handle errors from a AIDL method declaration
 *
 * [oneway] void method(type0 param0, ...)
 *
 * or the following (where return_type is not a status_t)
 *
 * return_type method(type0 param0, ...)
 */
static inline status_t statusTFromBinderStatus(const ::android::binder::Status &status) {
    return status.isOk() ? OK // check OK,
        : status.serviceSpecificErrorCode() // service-side error, not standard Java exception
                                            // (fromServiceSpecificError)
        ?: status.transactionError() // a native binder transaction error (fromStatusT)
        ?: statusTFromExceptionCode(status.exceptionCode()); // a service-side error with a
                                                    // standard Java exception (fromExceptionCode)
}

/**
 * Return a binder::Status from native service status.
 *
 * This is used for methods not returning an explicit status_t,
 * where Java callers expect an exception, not an integer return value.
 */
static inline ::android::binder::Status binderStatusFromStatusT(
        status_t status, const char *optionalMessage = nullptr) {
    const char *const emptyIfNull = optionalMessage == nullptr ? "" : optionalMessage;
    // From binder::Status instructions:
    //  Prefer a generic exception code when possible, then a service specific
    //  code, and finally a status_t for low level failures or legacy support.
    //  Exception codes and service specific errors map to nicer exceptions for
    //  Java clients.

    using namespace ::android::binder;
    switch (status) {
        case OK:
            return Status::ok();
        case PERMISSION_DENIED: // throw SecurityException on Java side
            return Status::fromExceptionCode(Status::EX_SECURITY, emptyIfNull);
        case BAD_VALUE: // throw IllegalArgumentException on Java side
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT, emptyIfNull);
        case INVALID_OPERATION: // throw IllegalStateException on Java side
            return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE, emptyIfNull);
    }

    // A service specific error will not show on status.transactionError() so
    // be sure to use statusTFromBinderStatus() for reliable error handling.

    // throw a ServiceSpecificException.
    return Status::fromServiceSpecificError(status, emptyIfNull);
}

} // namespace android::gui::aidl_utils
