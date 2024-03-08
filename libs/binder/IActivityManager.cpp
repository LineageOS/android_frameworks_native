/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <unistd.h>
#include <fcntl.h>

#include <android/permission_manager.h>
#include <binder/ActivityManager.h>
#include <binder/IActivityManager.h>
#include <binder/Parcel.h>
#include <utils/Errors.h>

namespace android {

// ------------------------------------------------------------------------------------

class BpActivityManager : public BpInterface<IActivityManager>
{
public:
    explicit BpActivityManager(const sp<IBinder>& impl)
        : BpInterface<IActivityManager>(impl)
    {
    }

    virtual int openContentUri(const String16& stringUri)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
        data.writeString16(stringUri);
        status_t ret = remote()->transact(OPEN_CONTENT_URI_TRANSACTION, data, & reply);
        int fd = -1;
        if (ret == NO_ERROR) {
            int32_t exceptionCode = reply.readExceptionCode();
            if (!exceptionCode) {
                // Success is indicated here by a nonzero int followed by the fd;
                // failure by a zero int with no data following.
                if (reply.readInt32() != 0) {
                    fd = fcntl(reply.readParcelFileDescriptor(), F_DUPFD_CLOEXEC, 0);
                }
            } else {
                // An exception was thrown back; fall through to return failure
                ALOGD("openContentUri(%s) caught exception %d\n", String8(stringUri).c_str(),
                      exceptionCode);
            }
        }
        return fd;
    }

    virtual status_t registerUidObserver(const sp<IUidObserver>& observer,
                                     const int32_t event,
                                     const int32_t cutpoint,
                                     const String16& callingPackage)
    {
         Parcel data, reply;
         data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
         data.writeStrongBinder(IInterface::asBinder(observer));
         data.writeInt32(event);
         data.writeInt32(cutpoint);
         data.writeString16(callingPackage);
         status_t err = remote()->transact(REGISTER_UID_OBSERVER_TRANSACTION, data, &reply);
         if (err != NO_ERROR || ((err = reply.readExceptionCode()) != NO_ERROR)) {
             return err;
         }
         return OK;
    }

    virtual status_t registerUidObserverForUids(const sp<IUidObserver>& observer,
                                                const int32_t event, const int32_t cutpoint,
                                                const String16& callingPackage,
                                                const int32_t uids[], size_t nUids,
                                                /*out*/ sp<IBinder>& observerToken) {
         Parcel data, reply;
         data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
         data.writeStrongBinder(IInterface::asBinder(observer));
         data.writeInt32(event);
         data.writeInt32(cutpoint);
         data.writeString16(callingPackage);
         data.writeInt32Array(nUids, uids);
         status_t err =
                 remote()->transact(REGISTER_UID_OBSERVER_FOR_UIDS_TRANSACTION, data, &reply);
         if (err != NO_ERROR || ((err = reply.readExceptionCode()) != NO_ERROR)) {
             return err;
         }
         err = reply.readStrongBinder(&observerToken);
         if (err != NO_ERROR || ((err = reply.readExceptionCode()) != NO_ERROR)) {
             return err;
         }
         return OK;
    }

    virtual status_t unregisterUidObserver(const sp<IUidObserver>& observer)
    {
         Parcel data, reply;
         data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
         data.writeStrongBinder(IInterface::asBinder(observer));
         status_t err = remote()->transact(UNREGISTER_UID_OBSERVER_TRANSACTION, data, &reply);
         if (err != NO_ERROR || ((err = reply.readExceptionCode()) != NO_ERROR)) {
             return err;
         }
         return OK;
    }

    virtual status_t addUidToObserver(const sp<IBinder>& observerToken,
                                      const String16& callingPackage, int32_t uid) {
         Parcel data, reply;
         data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
         data.writeStrongBinder(observerToken);
         data.writeString16(callingPackage);
         data.writeInt32(uid);
         status_t err = remote()->transact(ADD_UID_TO_OBSERVER_TRANSACTION, data, &reply);
         if (err != NO_ERROR || ((err = reply.readExceptionCode()) != NO_ERROR)) {
             return err;
         }
         return OK;
    }

    virtual status_t removeUidFromObserver(const sp<IBinder>& observerToken,
                                           const String16& callingPackage, int32_t uid) {
         Parcel data, reply;
         data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
         data.writeStrongBinder(observerToken);
         data.writeString16(callingPackage);
         data.writeInt32(uid);
         status_t err = remote()->transact(REMOVE_UID_FROM_OBSERVER_TRANSACTION, data, &reply);
         if (err != NO_ERROR || ((err = reply.readExceptionCode()) != NO_ERROR)) {
             return err;
         }
         return OK;
    }

    virtual bool isUidActive(const uid_t uid, const String16& callingPackage)
    {
         Parcel data, reply;
         data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
         data.writeInt32(uid);
         data.writeString16(callingPackage);
         remote()->transact(IS_UID_ACTIVE_TRANSACTION, data, &reply);
         // fail on exception
         if (reply.readExceptionCode() != 0) return false;
         return reply.readInt32() == 1;
    }

    virtual int32_t getUidProcessState(const uid_t uid, const String16& callingPackage)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
        data.writeInt32(uid);
        data.writeString16(callingPackage);
        remote()->transact(GET_UID_PROCESS_STATE_TRANSACTION, data, &reply);
        // fail on exception
        if (reply.readExceptionCode() != 0) {
            return ActivityManager::PROCESS_STATE_UNKNOWN;
        }
        return reply.readInt32();
    }

    virtual status_t checkPermission(const String16& permission,
                                    const pid_t pid,
                                    const uid_t uid,
                                    int32_t* outResult) {
        Parcel data, reply;
        data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
        data.writeString16(permission);
        data.writeInt32(pid);
        data.writeInt32(uid);
        status_t err = remote()->transact(CHECK_PERMISSION_TRANSACTION, data, &reply);
        if (err != NO_ERROR || ((err = reply.readExceptionCode()) != NO_ERROR)) {
            return err;
        }
        *outResult = reply.readInt32();
        return NO_ERROR;
    }

    virtual status_t logFgsApiBegin(int32_t apiType, int32_t appUid, int32_t appPid) {
        Parcel data, reply;
        data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
        data.writeInt32(apiType);
        data.writeInt32(appUid);
        data.writeInt32(appPid);
        status_t err = remote()->transact(LOG_FGS_API_BEGIN_TRANSACTION, data, &reply,
                                          IBinder::FLAG_ONEWAY);
        if (err != NO_ERROR || ((err = reply.readExceptionCode()) != NO_ERROR)) {
            ALOGD("%s: FGS Logger Transaction failed, %d", __func__, err);
            return err;
        }
        return NO_ERROR;
    }

    virtual status_t logFgsApiEnd(int32_t apiType, int32_t appUid, int32_t appPid) {
        Parcel data, reply;
        data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
        data.writeInt32(apiType);
        data.writeInt32(appUid);
        data.writeInt32(appPid);
        status_t err =
                remote()->transact(LOG_FGS_API_END_TRANSACTION, data, &reply, IBinder::FLAG_ONEWAY);
        if (err != NO_ERROR || ((err = reply.readExceptionCode()) != NO_ERROR)) {
            ALOGD("%s: FGS Logger Transaction failed, %d", __func__, err);
            return err;
        }
        return NO_ERROR;
    }

    virtual status_t logFgsApiStateChanged(int32_t apiType, int32_t state, int32_t appUid,
                                           int32_t appPid) {
        Parcel data, reply;
        data.writeInterfaceToken(IActivityManager::getInterfaceDescriptor());
        data.writeInt32(apiType);
        data.writeInt32(state);
        data.writeInt32(appUid);
        data.writeInt32(appPid);
        status_t err = remote()->transact(LOG_FGS_API_STATE_CHANGED_TRANSACTION, data, &reply,
                                          IBinder::FLAG_ONEWAY);
        if (err != NO_ERROR || ((err = reply.readExceptionCode()) != NO_ERROR)) {
            ALOGD("%s: FGS Logger Transaction failed, %d", __func__, err);
            return err;
        }
        return NO_ERROR;
    }
};

// ------------------------------------------------------------------------------------

IMPLEMENT_META_INTERFACE(ActivityManager, "android.app.IActivityManager")

} // namespace android
