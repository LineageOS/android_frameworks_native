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

#define LOG_TAG "GrallocMapper"

#include <array>
#include <string>

#include <log/log.h>
#include <ui/GrallocMapper.h>

namespace android {

namespace Gralloc2 {

typedef const void*(*FetchInterface)(const char* name);

static FetchInterface loadHalLib(const char* pkg_name)
{
    static const std::array<const char*, 3> sSearchDirs = {{
        HAL_LIBRARY_PATH_ODM,
        HAL_LIBRARY_PATH_VENDOR,
        HAL_LIBRARY_PATH_SYSTEM,
    }};
    static const char sSymbolName[] = "HALLIB_FETCH_Interface";

    void* handle = nullptr;
    std::string path;
    for (auto dir : sSearchDirs) {
        path = dir;
        path += pkg_name;
        path += ".hallib.so";
        handle = dlopen(path.c_str(), RTLD_LOCAL | RTLD_NOW);
        if (handle) {
            break;
        }
    }
    if (!handle) {
        return nullptr;
    }

    void* symbol = dlsym(handle, sSymbolName);
    if (!symbol) {
        ALOGE("%s is missing from %s", sSymbolName, path.c_str());
        dlclose(handle);
        return nullptr;
    }

    return reinterpret_cast<FetchInterface>(symbol);
}

Mapper::Mapper()
    : mMapper(nullptr), mDevice(nullptr)
{
    static const char sHalLibName[] = "android.hardware.graphics.mapper";
    static const char sSupportedInterface[] =
        "android.hardware.graphics.mapper@2.0::IMapper";

    FetchInterface fetchInterface = loadHalLib(sHalLibName);
    if (!fetchInterface) {
        return;
    }

    mMapper = static_cast<const IMapper*>(
            fetchInterface(sSupportedInterface));
    if (!mMapper) {
        ALOGE("%s is not supported", sSupportedInterface);
        return;
    }

    if (mMapper->createDevice(&mDevice) != Error::NONE) {
        ALOGE("failed to create mapper device");
        mMapper = nullptr;
    }
}

Mapper::~Mapper()
{
    if (mMapper) {
        mMapper->destroyDevice(mDevice);
    }
}

void Mapper::release(buffer_handle_t handle) const
{
    auto error = mMapper->release(mDevice, handle);
    ALOGE_IF(error != Error::NONE,
            "release(%p) failed with %d", handle, error);
}

int Mapper::unlock(buffer_handle_t handle) const
{
    int releaseFence;
    auto error = mMapper->unlock(mDevice, handle, &releaseFence);
    if (error != Error::NONE) {
        ALOGE("unlock(%p) failed with %d", handle, error);
        releaseFence = -1;
    }

    return releaseFence;
}

} // namespace Gralloc2

} // namespace android
