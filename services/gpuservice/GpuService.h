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

#ifndef ANDROID_GPUSERVICE_H
#define ANDROID_GPUSERVICE_H

#include <binder/IInterface.h>
#include <cutils/compiler.h>
#include <graphicsenv/IGpuService.h>

#include <mutex>
#include <vector>

namespace android {

class GpuService : public BnGpuService {
public:
    static const char* const SERVICE_NAME ANDROID_API;

    GpuService() ANDROID_API;

protected:
    status_t shellCommand(int in, int out, int err, std::vector<String16>& args) override;

private:
    // IGpuService interface
    void setGpuStats(const std::string driverPackageName, const std::string driverVersionName,
                     const uint64_t driverVersionCode, const std::string appPackageName);

    // GpuStats access must be protected by mStateLock
    std::mutex mStateLock;
};

} // namespace android

#endif // ANDROID_GPUSERVICE_H
