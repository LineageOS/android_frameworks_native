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
#include <graphicsenv/GraphicsEnv.h>

#include <dlfcn.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android/dlext.h>
#include <cutils/properties.h>
#include <log/log.h>
#include <sys/prctl.h>

#include <mutex>

// TODO(b/37049319) Get this from a header once one exists
extern "C" {
android_namespace_t* android_get_exported_namespace(const char*);
android_namespace_t* android_create_namespace(const char* name, const char* ld_library_path,
                                              const char* default_library_path, uint64_t type,
                                              const char* permitted_when_isolated_path,
                                              android_namespace_t* parent);
bool android_link_namespaces(android_namespace_t* from, android_namespace_t* to,
                             const char* shared_libs_sonames);

enum {
    ANDROID_NAMESPACE_TYPE_ISOLATED = 1,
    ANDROID_NAMESPACE_TYPE_SHARED = 2,
};
}

namespace android {

enum NativeLibrary {
    LLNDK = 0,
    VNDKSP = 1,
};

static constexpr const char* kNativeLibrariesSystemConfigPath[] = {"/etc/llndk.libraries.txt",
                                                                   "/etc/vndksp.libraries.txt"};

static std::string vndkVersionStr() {
#ifdef __BIONIC__
    std::string version = android::base::GetProperty("ro.vndk.version", "");
    if (version != "" && version != "current") {
        return "." + version;
    }
#endif
    return "";
}

static void insertVndkVersionStr(std::string* fileName) {
    LOG_ALWAYS_FATAL_IF(!fileName, "fileName should never be nullptr");
    size_t insertPos = fileName->find_last_of(".");
    if (insertPos == std::string::npos) {
        insertPos = fileName->length();
    }
    fileName->insert(insertPos, vndkVersionStr());
}

static bool readConfig(const std::string& configFile, std::vector<std::string>* soNames) {
    // Read list of public native libraries from the config file.
    std::string fileContent;
    if (!base::ReadFileToString(configFile, &fileContent)) {
        return false;
    }

    std::vector<std::string> lines = base::Split(fileContent, "\n");

    for (auto& line : lines) {
        auto trimmedLine = base::Trim(line);
        if (!trimmedLine.empty()) {
            soNames->push_back(trimmedLine);
        }
    }

    return true;
}

static const std::string getSystemNativeLibraries(NativeLibrary type) {
    static const char* androidRootEnv = getenv("ANDROID_ROOT");
    static const std::string rootDir = androidRootEnv != nullptr ? androidRootEnv : "/system";

    std::string nativeLibrariesSystemConfig = rootDir + kNativeLibrariesSystemConfigPath[type];

    insertVndkVersionStr(&nativeLibrariesSystemConfig);

    std::vector<std::string> soNames;
    if (!readConfig(nativeLibrariesSystemConfig, &soNames)) {
        ALOGE("Failed to retrieve library names from %s", nativeLibrariesSystemConfig.c_str());
        return "";
    }

    return base::Join(soNames, ':');
}

/*static*/ GraphicsEnv& GraphicsEnv::getInstance() {
    static GraphicsEnv env;
    return env;
}

int GraphicsEnv::getCanLoadSystemLibraries() {
    if (property_get_bool("ro.debuggable", false) && prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)) {
        // Return an integer value since this crosses library boundaries
        return 1;
    }
    return 0;
}

void GraphicsEnv::setDriverPath(const std::string path) {
    if (!mDriverPath.empty()) {
        ALOGV("ignoring attempt to change driver path from '%s' to '%s'", mDriverPath.c_str(),
              path.c_str());
        return;
    }
    ALOGV("setting driver path to '%s'", path.c_str());
    mDriverPath = path;
}

void GraphicsEnv::setAngleInfo(const std::string path, const std::string appName,
                               bool developerOptIn, const int rulesFd, const long rulesOffset,
                               const long rulesLength) {
    if (!mAnglePath.empty()) {
        ALOGV("ignoring attempt to change ANGLE path from '%s' to '%s'", mAnglePath.c_str(),
              path.c_str());
    } else {
        ALOGV("setting ANGLE path to '%s'", path.c_str());
        mAnglePath = path;
    }

    if (!mAngleAppName.empty()) {
        ALOGV("ignoring attempt to change ANGLE app name from '%s' to '%s'", mAngleAppName.c_str(),
              appName.c_str());
    } else {
        ALOGV("setting ANGLE app name to '%s'", appName.c_str());
        mAngleAppName = appName;
    }

    mAngleDeveloperOptIn = developerOptIn;

    ALOGV("setting ANGLE rules file descriptor to '%i'", rulesFd);
    mAngleRulesFd = rulesFd;
    ALOGV("setting ANGLE rules offset to '%li'", rulesOffset);
    mAngleRulesOffset = rulesOffset;
    ALOGV("setting ANGLE rules length to '%li'", rulesLength);
    mAngleRulesLength = rulesLength;
}

void GraphicsEnv::setLayerPaths(NativeLoaderNamespace* appNamespace, const std::string layerPaths) {
    if (mLayerPaths.empty()) {
        mLayerPaths = layerPaths;
        mAppNamespace = appNamespace;
    } else {
        ALOGV("Vulkan layer search path already set, not clobbering with '%s' for namespace %p'",
              layerPaths.c_str(), appNamespace);
    }
}

NativeLoaderNamespace* GraphicsEnv::getAppNamespace() {
    return mAppNamespace;
}

const char* GraphicsEnv::getAngleAppName() {
    if (mAngleAppName.empty()) return nullptr;
    return mAngleAppName.c_str();
}

bool GraphicsEnv::getAngleDeveloperOptIn() {
    return mAngleDeveloperOptIn;
}

int GraphicsEnv::getAngleRulesFd() {
    return mAngleRulesFd;
}

long GraphicsEnv::getAngleRulesOffset() {
    return mAngleRulesOffset;
}

long GraphicsEnv::getAngleRulesLength() {
    return mAngleRulesLength;
}

const std::string& GraphicsEnv::getLayerPaths() {
    return mLayerPaths;
}

const std::string& GraphicsEnv::getDebugLayers() {
    return mDebugLayers;
}

const std::string& GraphicsEnv::getDebugLayersGLES() {
    return mDebugLayersGLES;
}

void GraphicsEnv::setDebugLayers(const std::string layers) {
    mDebugLayers = layers;
}

void GraphicsEnv::setDebugLayersGLES(const std::string layers) {
    mDebugLayersGLES = layers;
}

android_namespace_t* GraphicsEnv::getDriverNamespace() {
    static std::once_flag once;
    std::call_once(once, [this]() {
        if (mDriverPath.empty()) return;

        auto vndkNamespace = android_get_exported_namespace("vndk");
        if (!vndkNamespace) return;

        mDriverNamespace = android_create_namespace("gfx driver",
                                                    mDriverPath.c_str(), // ld_library_path
                                                    mDriverPath.c_str(), // default_library_path
                                                    ANDROID_NAMESPACE_TYPE_ISOLATED,
                                                    nullptr, // permitted_when_isolated_path
                                                    nullptr);

        const std::string llndkLibraries = getSystemNativeLibraries(NativeLibrary::LLNDK);
        if (llndkLibraries.empty()) {
            mDriverNamespace = nullptr;
            return;
        }
        if (!android_link_namespaces(mDriverNamespace, nullptr, llndkLibraries.c_str())) {
            ALOGE("Failed to link default namespace[%s]", dlerror());
            mDriverNamespace = nullptr;
            return;
        }

        const std::string vndkspLibraries = getSystemNativeLibraries(NativeLibrary::VNDKSP);
        if (vndkspLibraries.empty()) {
            mDriverNamespace = nullptr;
            return;
        }
        if (!android_link_namespaces(mDriverNamespace, vndkNamespace, vndkspLibraries.c_str())) {
            ALOGE("Failed to link vndk namespace[%s]", dlerror());
            mDriverNamespace = nullptr;
            return;
        }
    });

    return mDriverNamespace;
}

android_namespace_t* GraphicsEnv::getAngleNamespace() {
    static std::once_flag once;
    std::call_once(once, [this]() {
        if (mAnglePath.empty()) return;

        mAngleNamespace = android_create_namespace("ANGLE",
                                                   nullptr,            // ld_library_path
                                                   mAnglePath.c_str(), // default_library_path
                                                   ANDROID_NAMESPACE_TYPE_SHARED |
                                                           ANDROID_NAMESPACE_TYPE_ISOLATED,
                                                   nullptr, // permitted_when_isolated_path
                                                   nullptr);
        if (!mAngleNamespace) ALOGD("Could not create ANGLE namespace from default");
    });

    return mAngleNamespace;
}

} // namespace android
