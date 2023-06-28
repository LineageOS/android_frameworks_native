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

#ifndef ANDROID_UI_GRAPHICS_ENV_H
#define ANDROID_UI_GRAPHICS_ENV_H 1

#include <graphicsenv/GpuStatsInfo.h>

#include <mutex>
#include <string>
#include <vector>

struct android_namespace_t;

namespace android {

struct NativeLoaderNamespace;

// The GraphicsEnv is a singleton per application process and is used to properly set up the
// graphics drivers for the application process during application starts. The architecture of
// the graphics driver loader does not support runtime switch and only supports switch to different
// graphics drivers when application process launches and hence the only way to switch to different
// graphics drivers is to completely kill the application process and relaunch the application.
class GraphicsEnv {
public:
    static GraphicsEnv& getInstance();

    // Check if the process is debuggable. It returns false except in any of the
    // following circumstances:
    // 1. ANDROID_DEBUGGABLE is defined (global debuggable enabled).
    // 2. android:debuggable="true" in the manifest for an individual app.
    // 3. An app which explicitly calls prctl(PR_SET_DUMPABLE, 1).
    // 4. GraphicsEnv calls prctl(PR_SET_DUMPABLE, 1) in the presence of
    //    <meta-data android:name="com.android.graphics.injectLayers.enable"
    //               android:value="true"/>
    //    in the application manifest.
    bool isDebuggable();

    /*
     * Apis for updatable driver
     */
    // Set a search path for loading graphics drivers. The path is a list of
    // directories separated by ':'. A directory can be contained in a zip file
    // (drivers must be stored uncompressed and page aligned); such elements
    // in the search path must have a '!' after the zip filename, e.g.
    //     /data/app/com.example.driver/base.apk!/lib/arm64-v8a
    // Also set additional required sphal libraries to the linker for loading
    // graphics drivers. The string is a list of libraries separated by ':',
    // which is required by android_link_namespaces.
    void setDriverPathAndSphalLibraries(const std::string& path, const std::string& sphalLibraries);
    // Get the updatable driver namespace.
    android_namespace_t* getDriverNamespace();
    std::string getDriverPath() const;

    /*
     * Apis for GpuStats
     */
    // Hint there's real activity launching on the app process.
    void hintActivityLaunch();
    // Set the initial GpuStats.
    void setGpuStats(const std::string& driverPackageName, const std::string& driverVersionName,
                     uint64_t versionCode, int64_t driverBuildTime,
                     const std::string& appPackageName, const int32_t vulkanVersion);
    // Set stats for target GpuStatsInfo::Stats type.
    void setTargetStats(const GpuStatsInfo::Stats stats, const uint64_t value = 0);
    // Set array of stats for target GpuStatsInfo::Stats type.
    void setTargetStatsArray(const GpuStatsInfo::Stats stats, const uint64_t* values,
                             const uint32_t valueCount);
    // Set which driver is intended to load.
    void setDriverToLoad(GpuStatsInfo::Driver driver);
    // Set which driver is actually loaded.
    void setDriverLoaded(GpuStatsInfo::Api api, bool isDriverLoaded, int64_t driverLoadingTime);
    // Set which instance extensions are enabled for the app.
    void setVulkanInstanceExtensions(uint32_t enabledExtensionCount,
                                     const char* const* ppEnabledExtensionNames);
    // Set which device extensions are enabled for the app.
    void setVulkanDeviceExtensions(uint32_t enabledExtensionCount,
                                   const char* const* ppEnabledExtensionNames);

    /*
     * Api for Vk/GL layer injection.  Presently, drivers enable certain
     * profiling features when prctl(PR_GET_DUMPABLE) returns true.
     * Calling this when layer injection metadata is present allows the driver
     * to enable profiling even when in a non-debuggable app
     */
    bool setInjectLayersPrSetDumpable();

    /*
     * Apis for ANGLE
     */
    // Check if this app process should use ANGLE.
    bool shouldUseAngle();
    // Set a search path for loading ANGLE libraries. The path is a list of
    // directories separated by ':'. A directory can be contained in a zip file
    // (libraries must be stored uncompressed and page aligned); such elements
    // in the search path must have a '!' after the zip filename, e.g.
    //     /system/app/ANGLEPrebuilt/ANGLEPrebuilt.apk!/lib/arm64-v8a
    void setAngleInfo(const std::string& path, const bool useSystemAngle,
                      const std::string& packageName, const std::vector<std::string> eglFeatures);
    // Get the ANGLE driver namespace.
    android_namespace_t* getAngleNamespace();
    // Get the app package name.
    std::string& getPackageName();
    const std::vector<std::string>& getAngleEglFeatures();
    // Set the persist.graphics.egl system property value.
    void nativeToggleAngleAsSystemDriver(bool enabled);
    bool shouldUseSystemAngle();

    /*
     * Apis for debug layer
     */
    // Set additional layer search paths.
    void setLayerPaths(NativeLoaderNamespace* appNamespace, const std::string& layerPaths);
    // Get the app namespace for loading layers.
    NativeLoaderNamespace* getAppNamespace();
    // Get additional layer search paths.
    const std::string& getLayerPaths();
    // Set the Vulkan debug layers.
    void setDebugLayers(const std::string& layers);
    // Set the GL debug layers.
    void setDebugLayersGLES(const std::string& layers);
    // Get the debug layers to load.
    const std::string& getDebugLayers();
    // Get the debug layers to load.
    const std::string& getDebugLayersGLES();

private:
    // Link updatable driver namespace with llndk and vndk-sp libs.
    bool linkDriverNamespaceLocked(android_namespace_t* destNamespace,
                                   android_namespace_t* vndkNamespace,
                                   const std::string& sharedSphalLibraries);
    // Check whether this process is ready to send stats.
    bool readyToSendGpuStatsLocked();
    // Send the initial complete GpuStats to GpuService.
    void sendGpuStatsLocked(GpuStatsInfo::Api api, bool isDriverLoaded, int64_t driverLoadingTime);

    GraphicsEnv() = default;

    // This mutex protects the namespace creation.
    std::mutex mNamespaceMutex;

    /**
     * Updatable driver variables.
     */
    // Path to updatable driver libs.
    std::string mDriverPath;
    // Path to additional sphal libs linked to updatable driver namespace.
    std::string mSphalLibraries;
    // Updatable driver namespace.
    android_namespace_t* mDriverNamespace = nullptr;

    /**
     * ANGLE variables.
     */
    // Path to ANGLE libs.
    std::string mAnglePath;
    // App's package name.
    std::string mPackageName;
    // ANGLE EGL features;
    std::vector<std::string> mAngleEglFeatures;
    // Whether ANGLE should be used.
    bool mShouldUseAngle = false;
    // Whether loader should load system ANGLE.
    bool mShouldUseSystemAngle = false;
    // ANGLE namespace.
    android_namespace_t* mAngleNamespace = nullptr;

    /**
     * GPU metrics.
     */
    // This mutex protects mGpuStats and get gpuservice call.
    std::mutex mStatsLock;
    // Cache the activity launch info
    bool mActivityLaunched = false;
    // Information bookkept for GpuStats.
    GpuStatsInfo mGpuStats;

    /**
     * Debug layers.
     */
    // Vulkan debug layers libs.
    std::string mDebugLayers;
    // GL debug layers libs.
    std::string mDebugLayersGLES;
    // Additional debug layers search path.
    std::string mLayerPaths;
    // This App's namespace to open native libraries.
    NativeLoaderNamespace* mAppNamespace = nullptr;
};

} // namespace android

#endif // ANDROID_UI_GRAPHICS_ENV_H
