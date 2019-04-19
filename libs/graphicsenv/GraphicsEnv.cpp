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

void GraphicsEnv::setDriverPathAndSphalLibraries(const std::string path,
                                                 const std::string sphalLibraries) {
    if (!mDriverPath.empty() || !mSphalLibraries.empty()) {
        ALOGV("ignoring attempt to change driver path from '%s' to '%s' or change sphal libraries "
              "from '%s' to '%s'",
              mDriverPath.c_str(), path.c_str(), mSphalLibraries.c_str(), sphalLibraries.c_str());
        return;
    }
    ALOGV("setting driver path to '%s' and sphal libraries to '%s'", path.c_str(),
          sphalLibraries.c_str());
    mDriverPath = path;
    mSphalLibraries = sphalLibraries;
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

const std::string GraphicsEnv::getLayerPaths(){
    return mLayerPaths;
}

const std::string GraphicsEnv::getDebugLayers() {
    return mDebugLayers;
}

void GraphicsEnv::setDebugLayers(const std::string layers) {
    mDebugLayers = layers;
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

        if (mSphalLibraries.empty()) return;

        // Make additional libraries in sphal to be accessible
        auto sphalNamespace = android_get_exported_namespace("sphal");
        if (!sphalNamespace) {
            ALOGE("Depend on these libraries[%s] in sphal, but failed to get sphal namespace",
                  mSphalLibraries.c_str());
            mDriverNamespace = nullptr;
            return;
        }

        if (!android_link_namespaces(mDriverNamespace, sphalNamespace, mSphalLibraries.c_str())) {
            ALOGE("Failed to link sphal namespace[%s]", dlerror());
            mDriverNamespace = nullptr;
            return;
        }
    });

    return mDriverNamespace;
}

} // namespace android

extern "C" android_namespace_t* android_getDriverNamespace() {
    return android::GraphicsEnv::getInstance().getDriverNamespace();
}
