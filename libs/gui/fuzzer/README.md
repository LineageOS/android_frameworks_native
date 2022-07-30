# Fuzzers for Libgui

## Table of contents
+ [libgui_surfaceComposer_fuzzer](#SurfaceComposer)
+ [libgui_surfaceComposerClient_fuzzer](#SurfaceComposerClient)
+ [libgui_parcelable_fuzzer](#Libgui_Parcelable)
+ [libgui_bufferQueue_fuzzer](#BufferQueue)
+ [libgui_consumer_fuzzer](#Libgui_Consumer)
+ [libgui_displayEvent_fuzzer](#LibGui_DisplayEvent)

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

# <a name="libgui_surfaceComposerClient_fuzzer"></a> Fuzzer for SurfaceComposerClient

SurfaceComposerClient supports the following data sources:
1. SurfaceWidth (parameter name:`width`)
2. SurfaceHeight (parameter name:`height`)
3. TransactionStateFlags (parameter name:`flags`)
4. TransformHint (parameter name:`outTransformHint`)
5. SurfacePixelFormat (parameter name:`format`)
6. LayerId (parameter name:`outLayerId`)
7. SurfaceComposerClientTags (parameter name:`surfaceTag`)
8. DefaultMode (parameter name:`defaultMode`)
9. PrimaryRefreshRateMin (parameter name:`primaryRefreshRateMin`)
10. PrimaryRefreshRateMax (parameter name:`primaryRefreshRateMax`)
11. AppRefreshRateMin (parameter name:`appRefreshRateMin`)
12. AppRefreshRateMax (parameter name:`appRefreshRateMax`)
13. DisplayPowerMode (parameter name:`mode`)
14. CacheId (parameter name:`cacheId`)
15. DisplayBrightness (parameter name:`brightness`)
16. PowerBoostID (parameter name:`boostId`)
17. AtomId (parameter name:`atomId`)
18. ComponentMask (parameter name:`componentMask`)
19. MaxFrames (parameter name:`maxFrames`)
20. TaskId (parameter name:`taskId`)
21. Alpha (parameter name:`aplha`)
22. CornerRadius (parameter name:`cornerRadius`)
23. BackgroundBlurRadius (parameter name:`backgroundBlurRadius`)
24. Half3Color (parameter name:`color`)
25. LayerStack (parameter name:`layerStack`)
26. Dataspace (parameter name:`dataspace`)
27. Api (parameter name:`api`)
28. Priority (parameter name:`priority`)
29. TouchableRegionPointX (parameter name:`pointX`)
30. TouchableRegionPointY (parameter name:`pointY`)
31. ColorMode (parameter name:`colorMode`)
32. WindowInfoFlags (parameter name:`flags`)
33. WindowInfoTransformOrientation (parameter name:`transform`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`surfaceTag`| 0.`Tag::CREATE_SURFACE`, 1.`Tag::CREATE_WITH_SURFACE_PARENT`, 2.`Tag::CLEAR_LAYER_FRAME_STATS`, 3.`Tag::GET_LAYER_FRAME_STATS`, 4.`Tag::MIRROR_SURFACE`, 5.`Tag::LAST` |Value obtained from FuzzedDataProvider|
|`mode`| 0.`gui::TouchOcclusionMode::BLOCK_UNTRUSTED`, 1.`gui::TouchOcclusionMode::USE_OPACITY`, 2.`gui::TouchOcclusionMode::ALLOW` |Value obtained from FuzzedDataProvider|
|`boostId`| 0.`hardware::power::Boost::INTERACTION`, 1.`hardware::power::Boost::DISPLAY_UPDATE_IMMINENT`, 2.`hardware::power::Boost::ML_ACC`, 3.`hardware::power::Boost::AUDIO_LAUNCH`, 4.`hardware::power::Boost::CAMERA_LAUNCH`, 5.`hardware::power::Boost::CAMERA_SHOT` |Value obtained from FuzzedDataProvider|
|`colorMode`|0.`ui::ColorMode::NATIVE`, 1.`ui::ColorMode::STANDARD_BT601_625`, 2.`ui::ColorMode::STANDARD_BT601_625_UNADJUSTED`, 3.`ui::ColorMode::STANDARD_BT601_525`, 4.`ui::ColorMode::STANDARD_BT601_525_UNADJUSTED`, 5.`ui::ColorMode::STANDARD_BT709`, 6.`ui::ColorMode::DCI_P3`, 7.`ui::ColorMode::SRGB`, 8.`ui::ColorMode::ADOBE_RGB`, 9.`ui::ColorMode::DISPLAY_P3`, 10.`ui::ColorMode::BT2020`, 11.`ui::ColorMode::BT2100_PQ`, 12.`ui::ColorMode::BT2100_HLG`, 13.`ui::ColorMode::DISPLAY_BT2020` |Value obtained from FuzzedDataProvider|
|`flags`|0 .`gui::WindowInfo::Flag::ALLOW_LOCK_WHILE_SCREEN_ON`, 1.`gui::WindowInfo::Flag::DIM_BEHIND`, 2.`gui::WindowInfo::Flag::BLUR_BEHIND`, 3.`gui::WindowInfo::Flag::NOT_FOCUSABLE`, 4.`gui::WindowInfo::Flag::NOT_TOUCHABLE`, 5.`gui::WindowInfo::Flag::NOT_TOUCH_MODAL`, 6.`gui::WindowInfo::Flag::TOUCHABLE_WHEN_WAKING`, 7.`gui::WindowInfo::Flag::KEEP_SCREEN_ON`, 8.`gui::WindowInfo::Flag::LAYOUT_IN_SCREEN`, 9.`gui::WindowInfo::Flag::LAYOUT_NO_LIMITS`, 10.`gui::WindowInfo::Flag::FULLSCREEN`, 11.`gui::WindowInfo::Flag::FORCE_NOT_FULLSCREEN`, 12.`gui::WindowInfo::Flag::DITHER`, 13.`gui::WindowInfo::Flag::SECURE`, 14.`gui::WindowInfo::Flag::SCALED`, 15.`gui::WindowInfo::Flag::IGNORE_CHEEK_PRESSES`, 16.`gui::WindowInfo::Flag::LAYOUT_INSET_DECOR`, 17.`gui::WindowInfo::Flag::ALT_FOCUSABLE_IM`, 18.`gui::WindowInfo::Flag::WATCH_OUTSIDE_TOUCH`, 19.`gui::WindowInfo::Flag::SHOW_WHEN_LOCKED`, 20.`gui::WindowInfo::Flag::SHOW_WALLPAPER`, 21.`gui::WindowInfo::Flag::TURN_SCREEN_ON`, 22.`gui::WindowInfo::Flag::DISMISS_KEYGUARD`, 23.`gui::WindowInfo::Flag::SPLIT_TOUCH`, 24.`gui::WindowInfo::Flag::HARDWARE_ACCELERATED`, 25.`gui::WindowInfo::Flag::LAYOUT_IN_OVERSCAN`, 26.`gui::WindowInfo::Flag::TRANSLUCENT_STATUS`, 27.`gui::WindowInfo::Flag::TRANSLUCENT_NAVIGATION`, 28.`gui::WindowInfo::Flag::LOCAL_FOCUS_MODE`, 29.`gui::WindowInfo::Flag::SLIPPERY`, 30.`gui::WindowInfo::Flag::LAYOUT_ATTACHED_IN_DECOR`, 31.`gui::WindowInfo::Flag::DRAWS_SYSTEM_BAR_BACKGROUNDS`, |Value obtained from FuzzedDataProvider|
|`dataspace`| 0.`ui::Dataspace::UNKNOWN`, 1.`ui::Dataspace::ARBITRARY`, 2.`ui::Dataspace::STANDARD_SHIFT`, 3.`ui::Dataspace::STANDARD_MASK`, 4.`ui::Dataspace::STANDARD_UNSPECIFIED`, 5.`ui::Dataspace::STANDARD_BT709`, 6.`ui::Dataspace::STANDARD_BT601_625`, 7.`ui::Dataspace::STANDARD_BT601_625_UNADJUSTED`, 8.`ui::Dataspace::STANDARD_BT601_525`, 9.`ui::Dataspace::STANDARD_BT601_525_UNADJUSTED`, 10.`ui::Dataspace::STANDARD_BT2020`, 11.`ui::Dataspace::STANDARD_BT2020_CONSTANT_LUMINANCE`, 12.`ui::Dataspace::STANDARD_BT470M`, 13.`ui::Dataspace::STANDARD_FILM`, 14.`ui::Dataspace::STANDARD_DCI_P3`, 15.`ui::Dataspace::STANDARD_ADOBE_RGB`, 16.`ui::Dataspace::TRANSFER_SHIFT`, 17.`ui::Dataspace::TRANSFER_MASK`, 18.`ui::Dataspace::TRANSFER_UNSPECIFIED`, 19.`ui::Dataspace::TRANSFER_LINEAR`, 20.`ui::Dataspace::TRANSFER_SRGB`, 21.`ui::Dataspace::TRANSFER_SMPTE_170M`, 22.`ui::Dataspace::TRANSFER_GAMMA2_2`, 23.`ui::Dataspace::TRANSFER_GAMMA2_6`, 24.`ui::Dataspace::TRANSFER_GAMMA2_8`, 25.`ui::Dataspace::TRANSFER_ST2084`, 26.`ui::Dataspace::TRANSFER_HLG`, 27.`ui::Dataspace::RANGE_SHIFT`, 28.`ui::Dataspace::RANGE_MASK`, 29.`ui::Dataspace::RANGE_UNSPECIFIED`, 30.`ui::Dataspace::RANGE_FULL`, 31.`ui::Dataspace::RANGE_LIMITED`, 32.`ui::Dataspace::RANGE_EXTENDED`, 33.`ui::Dataspace::SRGB_LINEAR`, 34.`ui::Dataspace::V0_SRGB_LINEAR`, 35.`ui::Dataspace::V0_SCRGB_LINEAR`, 36.`ui::Dataspace::SRGB`, 37.`ui::Dataspace::V0_SRGB`, 38.`ui::Dataspace::V0_SCRGB`, 39.`ui::Dataspace::JFIF`, 40.`ui::Dataspace::V0_JFIF`, 41.`ui::Dataspace::BT601_625`, 42.`ui::Dataspace::V0_BT601_625`, 43.`ui::Dataspace::BT601_525`, 44.`ui::Dataspace::V0_BT601_525`, 45.`ui::Dataspace::BT709`, 46.`ui::Dataspace::V0_BT709`, 47.`ui::Dataspace::DCI_P3_LINEAR`, 48.`ui::Dataspace::DCI_P3`, 49.`ui::Dataspace::DISPLAY_P3_LINEAR`, 50.`ui::Dataspace::DISPLAY_P3`, 51.`ui::Dataspace::ADOBE_RGB`, 52.`ui::Dataspace::BT2020_LINEAR`, 53.`ui::Dataspace::BT2020`, 54.`ui::Dataspace::BT2020_PQ`, 55.`ui::Dataspace::DEPTH`, 56.`ui::Dataspace::SENSOR`, 57.`ui::Dataspace::BT2020_ITU`, 58.`ui::Dataspace::BT2020_ITU_PQ`, 59.`ui::Dataspace::BT2020_ITU_HLG`, 60.`ui::Dataspace::BT2020_HLG`, 61.`ui::Dataspace::DISPLAY_BT2020`, 62.`ui::Dataspace::DYNAMIC_DEPTH`, 63.`ui::Dataspace::JPEG_APP_SEGMENTS`, 64.`ui::Dataspace::HEIF`, |Value obtained from FuzzedDataProvider|
|`transform`| 0.`ui::Transform::ROT_0`, 1.`ui::Transform::FLIP_H`, 2.`ui::Transform::FLIP_V`, 3.`ui::Transform::ROT_90`, 4.`ui::Transform::ROT_180`, 5.`ui::Transform::ROT_270` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) libgui_surfaceComposerClient_fuzzer
```
2. To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/libgui_surfaceComposerClient_fuzzer/libgui_surfaceComposerClient_fuzzer
```

# <a name="libgui_parcelable_fuzzer"></a> Fuzzer for Libgui_Parcelable

Libgui_Parcelable supports the following parameters:
1. LayerMetadataKey (parameter name:`key`)
2. Dataspace (parameter name:`mDataspace`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`key`| 0.`view::LayerMetadataKey::METADATA_OWNER_UID`, 1.`view::LayerMetadataKey::METADATA_WINDOW_TYPE`, 2.`view::LayerMetadataKey::METADATA_TASK_ID`, 3.`view::LayerMetadataKey::METADATA_MOUSE_CURSOR`, 4.`view::LayerMetadataKey::METADATA_ACCESSIBILITY_ID`, 5.`view::LayerMetadataKey::METADATA_OWNER_PID`, 6.`view::LayerMetadataKey::METADATA_DEQUEUE_TIME`, 7.`view::LayerMetadataKey::METADATA_GAME_MODE`, |Value obtained from FuzzedDataProvider|
|`mDataSpace`| 0.`ui::Dataspace::UNKNOWN`, 1.`ui::Dataspace::ARBITRARY`, 2.`ui::Dataspace::STANDARD_SHIFT`, 3.`ui::Dataspace::STANDARD_MASK`, 4.`ui::Dataspace::STANDARD_UNSPECIFIED`, 5.`ui::Dataspace::STANDARD_BT709`, 6.`ui::Dataspace::STANDARD_BT601_625`, 7.`ui::Dataspace::STANDARD_BT601_625_UNADJUSTED`, 8.`ui::Dataspace::STANDARD_BT601_525`, 9.`ui::Dataspace::STANDARD_BT601_525_UNADJUSTED`, 10.`ui::Dataspace::STANDARD_BT2020`, 11.`ui::Dataspace::STANDARD_BT2020_CONSTANT_LUMINANCE`, 12.`ui::Dataspace::STANDARD_BT470M`, 13.`ui::Dataspace::STANDARD_FILM`, 14.`ui::Dataspace::STANDARD_DCI_P3`, 15.`ui::Dataspace::STANDARD_ADOBE_RGB`, 16.`ui::Dataspace::TRANSFER_SHIFT`, 17.`ui::Dataspace::TRANSFER_MASK`, 18.`ui::Dataspace::TRANSFER_UNSPECIFIED`, 19.`ui::Dataspace::TRANSFER_LINEAR`, 20.`ui::Dataspace::TRANSFER_SRGB`, 21.`ui::Dataspace::TRANSFER_SMPTE_170M`, 22.`ui::Dataspace::TRANSFER_GAMMA2_2`, 23.`ui::Dataspace::TRANSFER_GAMMA2_6`, 24.`ui::Dataspace::TRANSFER_GAMMA2_8`, 25.`ui::Dataspace::TRANSFER_ST2084`, 26.`ui::Dataspace::TRANSFER_HLG`, 27.`ui::Dataspace::RANGE_SHIFT`, 28.`ui::Dataspace::RANGE_MASK`, 29.`ui::Dataspace::RANGE_UNSPECIFIED`, 30.`ui::Dataspace::RANGE_FULL`, 31.`ui::Dataspace::RANGE_LIMITED`, 32.`ui::Dataspace::RANGE_EXTENDED`, 33.`ui::Dataspace::SRGB_LINEAR`, 34.`ui::Dataspace::V0_SRGB_LINEAR`, 35.`ui::Dataspace::V0_SCRGB_LINEAR`, 36.`ui::Dataspace::SRGB`, 37.`ui::Dataspace::V0_SRGB`, 38.`ui::Dataspace::V0_SCRGB`, 39.`ui::Dataspace::JFIF`, 40.`ui::Dataspace::V0_JFIF`, 41.`ui::Dataspace::BT601_625`, 42.`ui::Dataspace::V0_BT601_625`, 43.`ui::Dataspace::BT601_525`, 44.`ui::Dataspace::V0_BT601_525`, 45.`ui::Dataspace::BT709`, 46.`ui::Dataspace::V0_BT709`, 47.`ui::Dataspace::DCI_P3_LINEAR`, 48.`ui::Dataspace::DCI_P3`, 49.`ui::Dataspace::DISPLAY_P3_LINEAR`, 50.`ui::Dataspace::DISPLAY_P3`, 51.`ui::Dataspace::ADOBE_RGB`, 52.`ui::Dataspace::BT2020_LINEAR`, 53.`ui::Dataspace::BT2020`, 54.`ui::Dataspace::BT2020_PQ`, 55.`ui::Dataspace::DEPTH`, 56.`ui::Dataspace::SENSOR`, 57.`ui::Dataspace::BT2020_ITU`, 58.`ui::Dataspace::BT2020_ITU_PQ`, 59.`ui::Dataspace::BT2020_ITU_HLG`, 60.`ui::Dataspace::BT2020_HLG`, 61.`ui::Dataspace::DISPLAY_BT2020`, 62.`ui::Dataspace::DYNAMIC_DEPTH`, 63.`ui::Dataspace::JPEG_APP_SEGMENTS`, 64.`ui::Dataspace::HEIF`, |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) libgui_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/libgui_fuzzer/libgui_fuzzer
```

# <a name="libgui_bufferQueue_fuzzer"></a> Fuzzer for BufferQueue

BufferQueue supports the following parameters:
1. SurfaceWidth (parameter name:`width`)
2. SurfaceHeight (parameter name:`height`)
3. TransactionStateFlags (parameter name:`flags`)
4. TransformHint (parameter name:`outTransformHint`)
5. SurfacePixelFormat (parameter name:`format`)
6. LayerId (parameter name:`layerId`)
7. BufferId (parameter name:`bufferId`)
8. FrameNumber (parameter name:`frameNumber`)
9. FrameRate (parameter name:`frameRate`)
10. Compatability (parameter name:`compatability`)
11. LatchTime (parameter name:`latchTime`)
12. AcquireTime (parameter name:`acquireTime`)
13. RefreshTime (parameter name:`refreshTime`)
14. DequeueTime (parameter name:`dequeueTime`)
15. Slot (parameter name:`slot`)
16. MaxBuffers (parameter name:`maxBuffers`)
17. GenerationNumber (parameter name:`generationNumber`)
18. Api (parameter name:`api`)
19. Usage (parameter name:`usage`)
20. MaxFrameNumber (parameter name:`maxFrameNumber`)
21. BufferCount (parameter name:`bufferCount`)
22. MaxAcquredBufferCount (parameter name:`maxAcquredBufferCount`)
23. Status (parameter name:`status`)
24. ApiConnection (parameter name:`apiConnection`)
25. Dataspace (parameter name:`dataspace`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`status`| 0.`OK`, 1.`NO_MEMORY`, 2.`NO_INIT`, 3.`BAD_VALUE`, 4.`DEAD_OBJECT`, 5.`INVALID_OPERATION`, 6.`TIMED_OUT`, 7.`WOULD_BLOCK`, 8.`UNKNOWN_ERROR`, 9.`ALREADY_EXISTS`, |Value obtained from FuzzedDataProvider|
|`apiConnection`| 0.`BufferQueueCore::CURRENTLY_CONNECTED_API`, 1.`BufferQueueCore::NO_CONNECTED_API`, 2.`NATIVE_WINDOW_API_EGL`, 3.`NATIVE_WINDOW_API_CPU`, 4.`NATIVE_WINDOW_API_MEDIA`, 5.`NATIVE_WINDOW_API_CAMERA`, |Value obtained from FuzzedDataProvider|
|`dataspace`| 0.`ui::Dataspace::UNKNOWN`, 1.`ui::Dataspace::ARBITRARY`, 2.`ui::Dataspace::STANDARD_SHIFT`, 3.`ui::Dataspace::STANDARD_MASK`, 4.`ui::Dataspace::STANDARD_UNSPECIFIED`, 5.`ui::Dataspace::STANDARD_BT709`, 6.`ui::Dataspace::STANDARD_BT601_625`, 7.`ui::Dataspace::STANDARD_BT601_625_UNADJUSTED`, 8.`ui::Dataspace::STANDARD_BT601_525`, 9.`ui::Dataspace::STANDARD_BT601_525_UNADJUSTED`, 10.`ui::Dataspace::STANDARD_BT2020`, 11.`ui::Dataspace::STANDARD_BT2020_CONSTANT_LUMINANCE`, 12.`ui::Dataspace::STANDARD_BT470M`, 13.`ui::Dataspace::STANDARD_FILM`, 14.`ui::Dataspace::STANDARD_DCI_P3`, 15.`ui::Dataspace::STANDARD_ADOBE_RGB`, 16.`ui::Dataspace::TRANSFER_SHIFT`, 17.`ui::Dataspace::TRANSFER_MASK`, 18.`ui::Dataspace::TRANSFER_UNSPECIFIED`, 19.`ui::Dataspace::TRANSFER_LINEAR`, 20.`ui::Dataspace::TRANSFER_SRGB`, 21.`ui::Dataspace::TRANSFER_SMPTE_170M`, 22.`ui::Dataspace::TRANSFER_GAMMA2_2`, 23.`ui::Dataspace::TRANSFER_GAMMA2_6`, 24.`ui::Dataspace::TRANSFER_GAMMA2_8`, 25.`ui::Dataspace::TRANSFER_ST2084`, 26.`ui::Dataspace::TRANSFER_HLG`, 27.`ui::Dataspace::RANGE_SHIFT`, 28.`ui::Dataspace::RANGE_MASK`, 29.`ui::Dataspace::RANGE_UNSPECIFIED`, 30.`ui::Dataspace::RANGE_FULL`, 31.`ui::Dataspace::RANGE_LIMITED`, 32.`ui::Dataspace::RANGE_EXTENDED`, 33.`ui::Dataspace::SRGB_LINEAR`, 34.`ui::Dataspace::V0_SRGB_LINEAR`, 35.`ui::Dataspace::V0_SCRGB_LINEAR`, 36.`ui::Dataspace::SRGB`, 37.`ui::Dataspace::V0_SRGB`, 38.`ui::Dataspace::V0_SCRGB`, 39.`ui::Dataspace::JFIF`, 40.`ui::Dataspace::V0_JFIF`, 41.`ui::Dataspace::BT601_625`, 42.`ui::Dataspace::V0_BT601_625`, 43.`ui::Dataspace::BT601_525`, 44.`ui::Dataspace::V0_BT601_525`, 45.`ui::Dataspace::BT709`, 46.`ui::Dataspace::V0_BT709`, 47.`ui::Dataspace::DCI_P3_LINEAR`, 48.`ui::Dataspace::DCI_P3`, 49.`ui::Dataspace::DISPLAY_P3_LINEAR`, 50.`ui::Dataspace::DISPLAY_P3`, 51.`ui::Dataspace::ADOBE_RGB`, 52.`ui::Dataspace::BT2020_LINEAR`, 53.`ui::Dataspace::BT2020`, 54.`ui::Dataspace::BT2020_PQ`, 55.`ui::Dataspace::DEPTH`, 56.`ui::Dataspace::SENSOR`, 57.`ui::Dataspace::BT2020_ITU`, 58.`ui::Dataspace::BT2020_ITU_PQ`, 59.`ui::Dataspace::BT2020_ITU_HLG`, 60.`ui::Dataspace::BT2020_HLG`, 61.`ui::Dataspace::DISPLAY_BT2020`, 62.`ui::Dataspace::DYNAMIC_DEPTH`, 63.`ui::Dataspace::JPEG_APP_SEGMENTS`, 64.`ui::Dataspace::HEIF`, |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) libgui_bufferQueue_fuzzer
```
2. To run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/libgui_bufferQueue_fuzzer/libgui_bufferQueue_fuzzer
```

# <a name="libgui_consumer_fuzzer"></a> Fuzzer for Libgui_Consumer

Libgui_Consumer supports the following parameters:
1. GraphicWidth (parameter name:`graphicWidth`)
2. GraphicHeight (parameter name:`graphicHeight`)
4. TransformHint (parameter name:`outTransformHint`)
5. GraphicPixelFormat (parameter name:`format`)
6. Usage (parameter name:`usage`)

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) libgui_consumer_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/libgui_consumer_fuzzer/libgui_consumer_fuzzer
```

# <a name="libgui_displayEvent_fuzzer"></a> Fuzzer for LibGui_DisplayEvent

LibGui_DisplayEvent supports the following parameters:
1. DisplayEventType (parameter name:`type`)
2. Events (parameter name:`events`)
3. VsyncSource (parameter name:`vsyncSource`)
4. EventRegistrationFlags (parameter name:`flags`)

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`vsyncSource`| 0.`ISurfaceComposer::eVsyncSourceApp`, 1.`ISurfaceComposer::eVsyncSourceSurfaceFlinger`, |Value obtained from FuzzedDataProvider|
|`flags`| 0.`ISurfaceComposer::EventRegistration::modeChanged`, 1.`ISurfaceComposer::EventRegistration::frameRateOverride`, |Value obtained from FuzzedDataProvider|
|`type`| 0.`DisplayEventReceiver::DISPLAY_EVENT_NULL`, 1.`DisplayEventReceiver::DISPLAY_EVENT_VSYNC`, 2.`DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG`, 3.`DisplayEventReceiver::DISPLAY_EVENT_MODE_CHANGE`, 4.`DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE`, 5.`DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE_FLUSH`, |Value obtained from FuzzedDataProvider|
|`events`| 0.`Looper::EVENT_INPUT`, 1.`Looper::EVENT_OUTPUT`, 2.`Looper::EVENT_ERROR`, 3.`Looper::EVENT_HANGUP`, 4.`Looper::EVENT_INVALID`, |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
  $ mm -j$(nproc) libgui_displayEvent_fuzzer
```
2. Run on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/libgui_displayEvent_fuzzer/libgui_displayEvent_fuzzer
```
