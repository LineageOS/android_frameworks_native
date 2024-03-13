/*
 * Copyright 2024 The Android Open Source Project
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

#define FRAMEWORK_CATEGORIES(C)                                  \
  C(always, "always", "Always category")                         \
  C(graphics, "graphics", "Graphics category")                   \
  C(input, "input", "Input category")                            \
  C(view, "view", "View category")                               \
  C(webview, "webview", "WebView category")                      \
  C(windowmanager, "wm", "WindowManager category")               \
  C(activitymanager, "am", "ActivityManager category")           \
  C(syncmanager, "syncmanager", "SyncManager category")          \
  C(audio, "audio", "Audio category")                            \
  C(video, "video", "Video category")                            \
  C(camera, "camera", "Camera category")                         \
  C(hal, "hal", "HAL category")                                  \
  C(app, "app", "App category")                                  \
  C(resources, "res", "Resources category")                      \
  C(dalvik, "dalvik", "Dalvik category")                         \
  C(rs, "rs", "RS category")                                     \
  C(bionic, "bionic", "Bionic category")                         \
  C(power, "power", "Power category")                            \
  C(packagemanager, "packagemanager", "PackageManager category") \
  C(systemserver, "ss", "System Server category")                \
  C(database, "database", "Database category")                   \
  C(network, "network", "Network category")                      \
  C(adb, "adb", "ADB category")                                  \
  C(vibrator, "vibrator", "Vibrator category")                   \
  C(aidl, "aidl", "AIDL category")                               \
  C(nnapi, "nnapi", "NNAPI category")                            \
  C(rro, "rro", "RRO category")                                  \
  C(thermal, "thermal", "Thermal category")

#include "tracing_perfetto_internal.h"

#include <inttypes.h>

#include <mutex>

#include <android_os.h>

#include "perfetto/public/compiler.h"
#include "perfetto/public/producer.h"
#include "perfetto/public/te_category_macros.h"
#include "perfetto/public/te_macros.h"
#include "perfetto/public/track_event.h"
#include "trace_categories.h"
#include "trace_result.h"

namespace tracing_perfetto {

namespace internal {

namespace {

PERFETTO_TE_CATEGORIES_DECLARE(FRAMEWORK_CATEGORIES);

PERFETTO_TE_CATEGORIES_DEFINE(FRAMEWORK_CATEGORIES);

std::atomic_bool is_perfetto_registered = false;

struct PerfettoTeCategory* toCategory(uint64_t inCategory) {
  switch (inCategory) {
    case TRACE_CATEGORY_ALWAYS:
      return &always;
    case TRACE_CATEGORY_GRAPHICS:
      return &graphics;
    case TRACE_CATEGORY_INPUT:
      return &input;
    case TRACE_CATEGORY_VIEW:
      return &view;
    case TRACE_CATEGORY_WEBVIEW:
      return &webview;
    case TRACE_CATEGORY_WINDOW_MANAGER:
      return &windowmanager;
    case TRACE_CATEGORY_ACTIVITY_MANAGER:
      return &activitymanager;
    case TRACE_CATEGORY_SYNC_MANAGER:
      return &syncmanager;
    case TRACE_CATEGORY_AUDIO:
      return &audio;
    case TRACE_CATEGORY_VIDEO:
      return &video;
    case TRACE_CATEGORY_CAMERA:
      return &camera;
    case TRACE_CATEGORY_HAL:
      return &hal;
    case TRACE_CATEGORY_APP:
      return &app;
    case TRACE_CATEGORY_RESOURCES:
      return &resources;
    case TRACE_CATEGORY_DALVIK:
      return &dalvik;
    case TRACE_CATEGORY_RS:
      return &rs;
    case TRACE_CATEGORY_BIONIC:
      return &bionic;
    case TRACE_CATEGORY_POWER:
      return &power;
    case TRACE_CATEGORY_PACKAGE_MANAGER:
      return &packagemanager;
    case TRACE_CATEGORY_SYSTEM_SERVER:
      return &systemserver;
    case TRACE_CATEGORY_DATABASE:
      return &database;
    case TRACE_CATEGORY_NETWORK:
      return &network;
    case TRACE_CATEGORY_ADB:
      return &adb;
    case TRACE_CATEGORY_VIBRATOR:
      return &vibrator;
    case TRACE_CATEGORY_AIDL:
      return &aidl;
    case TRACE_CATEGORY_NNAPI:
      return &nnapi;
    case TRACE_CATEGORY_RRO:
      return &rro;
    case TRACE_CATEGORY_THERMAL:
      return &thermal;
    default:
      return nullptr;
  }
}

}  // namespace

bool isPerfettoRegistered() {
  return is_perfetto_registered;
}

struct PerfettoTeCategory* toPerfettoCategory(uint64_t category) {
  struct PerfettoTeCategory* perfettoCategory = toCategory(category);
  if (perfettoCategory == nullptr) {
    return nullptr;
  }

  bool enabled = PERFETTO_UNLIKELY(PERFETTO_ATOMIC_LOAD_EXPLICIT(
      (*perfettoCategory).enabled, PERFETTO_MEMORY_ORDER_RELAXED));
  return enabled ? perfettoCategory : nullptr;
}

void registerWithPerfetto(bool test) {
  if (!android::os::perfetto_sdk_tracing()) {
    return;
  }

  static std::once_flag registration;
  std::call_once(registration, [test]() {
    struct PerfettoProducerInitArgs args = PERFETTO_PRODUCER_INIT_ARGS_INIT();
    args.backends = test ? PERFETTO_BACKEND_IN_PROCESS : PERFETTO_BACKEND_SYSTEM;
    PerfettoProducerInit(args);
    PerfettoTeInit();
    PERFETTO_TE_REGISTER_CATEGORIES(FRAMEWORK_CATEGORIES);
    is_perfetto_registered = true;
  });
}

Result perfettoTraceBegin(const struct PerfettoTeCategory& category, const char* name) {
  PERFETTO_TE(category, PERFETTO_TE_SLICE_BEGIN(name));
  return Result::SUCCESS;
}

Result perfettoTraceEnd(const struct PerfettoTeCategory& category) {
  PERFETTO_TE(category, PERFETTO_TE_SLICE_END());
  return Result::SUCCESS;
}

Result perfettoTraceAsyncBeginForTrack(const struct PerfettoTeCategory& category, const char* name,
                                       const char* trackName, uint64_t cookie) {
  PERFETTO_TE(
      category, PERFETTO_TE_SLICE_BEGIN(name),
      PERFETTO_TE_NAMED_TRACK(trackName, cookie, PerfettoTeProcessTrackUuid()));
  return Result::SUCCESS;
}

Result perfettoTraceAsyncEndForTrack(const struct PerfettoTeCategory& category,
                                     const char* trackName, uint64_t cookie) {
  PERFETTO_TE(
      category, PERFETTO_TE_SLICE_END(),
      PERFETTO_TE_NAMED_TRACK(trackName, cookie, PerfettoTeProcessTrackUuid()));
  return Result::SUCCESS;
}

Result perfettoTraceAsyncBegin(const struct PerfettoTeCategory& category, const char* name,
                               uint64_t cookie) {
  return perfettoTraceAsyncBeginForTrack(category, name, name, cookie);
}

Result perfettoTraceAsyncEnd(const struct PerfettoTeCategory& category, const char* name,
                             uint64_t cookie) {
  return perfettoTraceAsyncEndForTrack(category, name, cookie);
}

Result perfettoTraceInstant(const struct PerfettoTeCategory& category, const char* name) {
  PERFETTO_TE(category, PERFETTO_TE_INSTANT(name));
  return Result::SUCCESS;
}

Result perfettoTraceInstantForTrack(const struct PerfettoTeCategory& category,
                                    const char* trackName, const char* name) {
  PERFETTO_TE(
      category, PERFETTO_TE_INSTANT(name),
      PERFETTO_TE_NAMED_TRACK(trackName, 1, PerfettoTeProcessTrackUuid()));
  return Result::SUCCESS;
}

Result perfettoTraceCounter(const struct PerfettoTeCategory& category,
                            [[maybe_unused]] const char* name, int64_t value) {
  PERFETTO_TE(category, PERFETTO_TE_COUNTER(),
              PERFETTO_TE_INT_COUNTER(value));
  return Result::SUCCESS;
}

uint64_t getDefaultCategories() {
  return TRACE_CATEGORIES;
}

}  // namespace internal

}  // namespace tracing_perfetto
