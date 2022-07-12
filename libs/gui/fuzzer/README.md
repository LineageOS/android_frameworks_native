# Fuzzers for Libgui

## Table of contents
+ [libgui_surfaceComposer_fuzzer](#SurfaceComposer)

# <a name="libgui_surfaceComposer_fuzzer"></a> Fuzzer for SurfaceComposer

SurfaceComposer supports the following parameters:
1. SurfaceWidth (parameter name:`width`)
2. SurfaceHeight (parameter name:`height`)
3. TransactionStateFlags (parameter name:`flags`)
4. TransformHint (parameter name:`outTransformHint`)
5. SurfacePixelFormat (parameter name:`format`)
6. LayerId (parameter name:`outLayerId`)
7. SurfaceComposerTags (parameter name:`surfaceTag`)
8. PowerBoostID (parameter name:`boostId`)
9. VsyncSource (parameter name:`vsyncSource`)
10. EventRegistrationFlags (parameter name:`eventRegistration`)
11. FrameRateCompatibility (parameter name:`frameRateCompatibility`)
12. ChangeFrameRateStrategy (parameter name:`changeFrameRateStrategy`)
13. HdrTypes (parameter name:`hdrTypes`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`surfaceTag` | 0.`BnSurfaceComposer::BOOT_FINISHED`, 1.`BnSurfaceComposer::CREATE_CONNECTION`, 2.`BnSurfaceComposer::GET_STATIC_DISPLAY_INFO`, 3.`BnSurfaceComposer::CREATE_DISPLAY_EVENT_CONNECTION`, 4.`BnSurfaceComposer::CREATE_DISPLAY`, 5.`BnSurfaceComposer::DESTROY_DISPLAY`, 6.`BnSurfaceComposer::GET_PHYSICAL_DISPLAY_TOKEN`, 7.`BnSurfaceComposer::SET_TRANSACTION_STATE`, 8.`BnSurfaceComposer::AUTHENTICATE_SURFACE`, 9.`BnSurfaceComposer::GET_SUPPORTED_FRAME_TIMESTAMPS`, 10.`BnSurfaceComposer::GET_DISPLAY_STATE`, 11.`BnSurfaceComposer::CAPTURE_DISPLAY`, 12.`BnSurfaceComposer::CAPTURE_LAYERS`, 13.`BnSurfaceComposer::CLEAR_ANIMATION_FRAME_STATS`, 14.`BnSurfaceComposer::GET_ANIMATION_FRAME_STATS`, 15.`BnSurfaceComposer::SET_POWER_MODE`, 16.`BnSurfaceComposer::GET_DISPLAY_STATS`, 17.`BnSurfaceComposer::SET_ACTIVE_COLOR_MODE`, 18.`BnSurfaceComposer::ENABLE_VSYNC_INJECTIONS`, 19.`BnSurfaceComposer::INJECT_VSYNC`, 20.`BnSurfaceComposer::GET_LAYER_DEBUG_INFO`, 21.`BnSurfaceComposer::GET_COMPOSITION_PREFERENCE`, 22.`BnSurfaceComposer::GET_COLOR_MANAGEMENT`, 23.`BnSurfaceComposer::GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES`, 24.`BnSurfaceComposer::SET_DISPLAY_CONTENT_SAMPLING_ENABLED`, 25.`BnSurfaceComposer::GET_DISPLAYED_CONTENT_SAMPLE`, 26.`BnSurfaceComposer::GET_PROTECTED_CONTENT_SUPPORT`, 27.`BnSurfaceComposer::IS_WIDE_COLOR_DISPLAY`, 28.`BnSurfaceComposer::GET_DISPLAY_NATIVE_PRIMARIES`, 29.`BnSurfaceComposer::GET_PHYSICAL_DISPLAY_IDS`, 30.`BnSurfaceComposer::ADD_REGION_SAMPLING_LISTENER`, 31.`BnSurfaceComposer::REMOVE_REGION_SAMPLING_LISTENER`, 32.`BnSurfaceComposer::SET_DESIRED_DISPLAY_MODE_SPECS`, 33.`BnSurfaceComposer::GET_DESIRED_DISPLAY_MODE_SPECS`, 34.`BnSurfaceComposer::GET_DISPLAY_BRIGHTNESS_SUPPORT`, 35.`BnSurfaceComposer::SET_DISPLAY_BRIGHTNESS`, 36.`BnSurfaceComposer::CAPTURE_DISPLAY_BY_ID`, 37.`BnSurfaceComposer::NOTIFY_POWER_BOOST`, 38.`BnSurfaceComposer::SET_GLOBAL_SHADOW_SETTINGS`, 39.`BnSurfaceComposer::SET_AUTO_LOW_LATENCY_MODE`, 40.`BnSurfaceComposer::SET_GAME_CONTENT_TYPE`, 41.`BnSurfaceComposer::SET_FRAME_RATE`, 42.`BnSurfaceComposer::ACQUIRE_FRAME_RATE_FLEXIBILITY_TOKEN`, 43.`BnSurfaceComposer::SET_FRAME_TIMELINE_INFO`, 44.`BnSurfaceComposer::ADD_TRANSACTION_TRACE_LISTENER`, 45.`BnSurfaceComposer::GET_GPU_CONTEXT_PRIORITY`, 46.`BnSurfaceComposer::GET_MAX_ACQUIRED_BUFFER_COUNT`, 47.`BnSurfaceComposer::GET_DYNAMIC_DISPLAY_INFO`, 48.`BnSurfaceComposer::ADD_FPS_LISTENER`, 49.`BnSurfaceComposer::REMOVE_FPS_LISTENER`, 50.`BnSurfaceComposer::OVERRIDE_HDR_TYPES`, 51.`BnSurfaceComposer::ADD_HDR_LAYER_INFO_LISTENER`, 52.`BnSurfaceComposer::REMOVE_HDR_LAYER_INFO_LISTENER`, 53.`BnSurfaceComposer::ON_PULL_ATOM`, 54.`BnSurfaceComposer::ADD_TUNNEL_MODE_ENABLED_LISTENER`, 55.`BnSurfaceComposer::REMOVE_TUNNEL_MODE_ENABLED_LISTENER` | Value obtained from FuzzedDataProvider|
|`boostId`| 0.`hardware::power::Boost::INTERACTION`, 1.`hardware::power::Boost::DISPLAY_UPDATE_IMMINENT`, 2.`hardware::power::Boost::ML_ACC`, 3.`hardware::power::Boost::AUDIO_LAUNCH`, 4.`hardware::power::Boost::CAMERA_LAUNCH`, 5.`hardware::power::Boost::CAMERA_SHOT` |Value obtained from FuzzedDataProvider|
|`vsyncSource`| 0.`ISurfaceComposer::eVsyncSourceApp`, 1.`ISurfaceComposer::eVsyncSourceSurfaceFlinger`, |Value obtained from FuzzedDataProvider|
|`eventRegistration`| 0.`ISurfaceComposer::EventRegistration::modeChanged`, 1.`ISurfaceComposer::EventRegistration::frameRateOverride` |Value obtained from FuzzedDataProvider|
|`frameRateCompatibility`| 0.`ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_DEFAULT`, 1.`ANATIVEWINDOW_FRAME_RATE_COMPATIBILITY_FIXED_SOURCE` |Value obtained from FuzzedDataProvider|
|`changeFrameRateStrategy`| 0.`ANATIVEWINDOW_CHANGE_FRAME_RATE_ONLY_IF_SEAMLESS`, 1.`ANATIVEWINDOW_CHANGE_FRAME_RATE_ALWAYS` |Value obtained from FuzzedDataProvider|
|`hdrTypes`| 0.`ui::Hdr::DOLBY_VISION`, 1.`ui::Hdr::HDR10`, 2.`ui::Hdr::HLG`, 3.`ui::Hdr::HDR10_PLUS` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) libgui_surfaceComposer_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/libgui_surfaceComposer_fuzzer/libgui_surfaceComposer_fuzzer
```
