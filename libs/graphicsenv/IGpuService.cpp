/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "GpuService"

#include <graphicsenv/IGpuService.h>

#include <binder/IResultReceiver.h>
#include <binder/Parcel.h>

namespace android {

class BpGpuService : public BpInterface<IGpuService> {
public:
    explicit BpGpuService(const sp<IBinder>& impl) : BpInterface<IGpuService>(impl) {}

    virtual void setGpuStats(const std::string driverPackageName,
                             const std::string driverVersionName, const uint64_t driverVersionCode,
                             const std::string appPackageName) {
        Parcel data, reply;
        data.writeInterfaceToken(IGpuService::getInterfaceDescriptor());

        data.writeUtf8AsUtf16(driverPackageName);
        data.writeUtf8AsUtf16(driverVersionName);
        data.writeUint64(driverVersionCode);
        data.writeUtf8AsUtf16(appPackageName);

        remote()->transact(BnGpuService::SET_GPU_STATS, data, &reply);
    }
};

IMPLEMENT_META_INTERFACE(GpuService, "android.graphicsenv.IGpuService");

status_t BnGpuService::onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                                  uint32_t flags) {
    ALOGV("onTransact code[0x%X]", code);

    status_t status;
    switch (code) {
        case SET_GPU_STATS: {
            CHECK_INTERFACE(IGpuService, data, reply);

            std::string driverPackageName;
            if ((status = data.readUtf8FromUtf16(&driverPackageName)) != OK) return status;

            std::string driverVersionName;
            if ((status = data.readUtf8FromUtf16(&driverVersionName)) != OK) return status;

            uint64_t driverVersionCode;
            if ((status = data.readUint64(&driverVersionCode)) != OK) return status;

            std::string appPackageName;
            if ((status = data.readUtf8FromUtf16(&appPackageName)) != OK) return status;

            setGpuStats(driverPackageName, driverVersionName, driverVersionCode, appPackageName);

            return OK;
        }
        case SHELL_COMMAND_TRANSACTION: {
            int in = data.readFileDescriptor();
            int out = data.readFileDescriptor();
            int err = data.readFileDescriptor();

            std::vector<String16> args;
            data.readString16Vector(&args);

            sp<IBinder> unusedCallback;
            if ((status = data.readNullableStrongBinder(&unusedCallback)) != OK) return status;

            sp<IResultReceiver> resultReceiver;
            if ((status = data.readNullableStrongBinder(&resultReceiver)) != OK) return status;

            status = shellCommand(in, out, err, args);
            if (resultReceiver != nullptr) resultReceiver->send(status);

            return OK;
        }
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

} // namespace android
