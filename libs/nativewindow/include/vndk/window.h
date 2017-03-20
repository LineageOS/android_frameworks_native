/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef ANDROID_VNDK_NATIVEWINDOW_ANATIVEWINDOW_H
#define ANDROID_VNDK_NATIVEWINDOW_ANATIVEWINDOW_H

#include <sys/cdefs.h>

// vndk is a superset of the NDK
#include <android/native_window.h>

__BEGIN_DECLS

// opaque native window structure
struct ANativeWindow;
typedef struct ANativeWindow ANativeWindow_t;



__END_DECLS

#endif /* ANDROID_VNDK_NATIVEWINDOW_ANATIVEWINDOW_H */
