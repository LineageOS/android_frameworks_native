/*
 * Copyright 2017 The Android Open Source Project
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

//#define LOG_NDEBUG 1
#define LOG_TAG "GraphicsEnv"
#include <gui/GraphicsEnv.h>

#include <mutex>

#include <log/log.h>
#include <nativeloader/dlext_namespaces.h>

namespace android {

/*static*/ GraphicsEnv& GraphicsEnv::getInstance() {
    static GraphicsEnv env;
    return env;
}

void GraphicsEnv::setDriverPath(const std::string path) {
    if (!mDriverPath.empty()) {
        ALOGV("ignoring attempt to change driver path from '%s' to '%s'",
                mDriverPath.c_str(), path.c_str());
        return;
    }
    ALOGV("setting driver path to '%s'", path.c_str());
    mDriverPath = path;
}

android_namespace_t* GraphicsEnv::getDriverNamespace() {
    static std::once_flag once;
    std::call_once(once, [this]() {
        // TODO; In the next version of Android, all graphics drivers will be
        // loaded into a custom namespace. To minimize risk for this release,
        // only updated drivers use a custom namespace.
        //
        // Additionally, the custom namespace will be
        // ANDROID_NAMESPACE_TYPE_ISOLATED, and will only have access to a
        // subset of the system.
        if (mDriverPath.empty())
            return;

        char defaultPath[PATH_MAX];
        android_get_LD_LIBRARY_PATH(defaultPath, sizeof(defaultPath));
        size_t defaultPathLen = strlen(defaultPath);

        std::string path;
        path.reserve(mDriverPath.size() + 1 + defaultPathLen);
        path.append(mDriverPath);
        path.push_back(':');
        path.append(defaultPath, defaultPathLen);

        mDriverNamespace = android_create_namespace(
                "gfx driver",
                nullptr,                    // ld_library_path
                path.c_str(),               // default_library_path
                ANDROID_NAMESPACE_TYPE_SHARED,
                nullptr,                    // permitted_when_isolated_path
                nullptr);                   // parent
    });
    return mDriverNamespace;
}

} // namespace android

extern "C" android_namespace_t* android_getDriverNamespace() {
    return android::GraphicsEnv::getInstance().getDriverNamespace();
}
