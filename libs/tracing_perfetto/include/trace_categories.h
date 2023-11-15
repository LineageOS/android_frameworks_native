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

#ifndef TRACE_CATEGORIES_H
#define TRACE_CATEGORIES_H

/**
 * Keep these in sync with frameworks/base/core/java/android/os/Trace.java.
 */
#define TRACE_CATEGORY_ALWAYS (1 << 0)
#define TRACE_CATEGORY_GRAPHICS (1 << 1)
#define TRACE_CATEGORY_INPUT (1 << 2)
#define TRACE_CATEGORY_VIEW (1 << 3)
#define TRACE_CATEGORY_WEBVIEW (1 << 4)
#define TRACE_CATEGORY_WINDOW_MANAGER (1 << 5)
#define TRACE_CATEGORY_ACTIVITY_MANAGER (1 << 6)
#define TRACE_CATEGORY_SYNC_MANAGER (1 << 7)
#define TRACE_CATEGORY_AUDIO (1 << 8)
#define TRACE_CATEGORY_VIDEO (1 << 9)
#define TRACE_CATEGORY_CAMERA (1 << 10)
#define TRACE_CATEGORY_HAL (1 << 11)
#define TRACE_CATEGORY_APP (1 << 12)
#define TRACE_CATEGORY_RESOURCES (1 << 13)
#define TRACE_CATEGORY_DALVIK (1 << 14)
#define TRACE_CATEGORY_RS (1 << 15)
#define TRACE_CATEGORY_BIONIC (1 << 16)
#define TRACE_CATEGORY_POWER (1 << 17)
#define TRACE_CATEGORY_PACKAGE_MANAGER (1 << 18)
#define TRACE_CATEGORY_SYSTEM_SERVER (1 << 19)
#define TRACE_CATEGORY_DATABASE (1 << 20)
#define TRACE_CATEGORY_NETWORK (1 << 21)
#define TRACE_CATEGORY_ADB (1 << 22)
#define TRACE_CATEGORY_VIBRATOR (1 << 23)
#define TRACE_CATEGORY_AIDL (1 << 24)
#define TRACE_CATEGORY_NNAPI (1 << 25)
#define TRACE_CATEGORY_RRO (1 << 26)
#define TRACE_CATEGORY_THERMAL (1 << 27)

// Allow all categories except TRACE_CATEGORY_APP
#define TRACE_CATEGORIES                                                      \
  TRACE_CATEGORY_ALWAYS | TRACE_CATEGORY_GRAPHICS | TRACE_CATEGORY_INPUT |    \
      TRACE_CATEGORY_VIEW | TRACE_CATEGORY_WEBVIEW |                          \
      TRACE_CATEGORY_WINDOW_MANAGER | TRACE_CATEGORY_ACTIVITY_MANAGER |       \
      TRACE_CATEGORY_SYNC_MANAGER | TRACE_CATEGORY_AUDIO |                    \
      TRACE_CATEGORY_VIDEO | TRACE_CATEGORY_CAMERA | TRACE_CATEGORY_HAL |     \
      TRACE_CATEGORY_RESOURCES | TRACE_CATEGORY_DALVIK | TRACE_CATEGORY_RS |  \
      TRACE_CATEGORY_BIONIC | TRACE_CATEGORY_POWER |                          \
      TRACE_CATEGORY_PACKAGE_MANAGER | TRACE_CATEGORY_SYSTEM_SERVER |         \
      TRACE_CATEGORY_DATABASE | TRACE_CATEGORY_NETWORK | TRACE_CATEGORY_ADB | \
      TRACE_CATEGORY_VIBRATOR | TRACE_CATEGORY_AIDL | TRACE_CATEGORY_NNAPI |  \
      TRACE_CATEGORY_RRO | TRACE_CATEGORY_THERMAL
#endif  // TRACE_CATEGORIES_H
