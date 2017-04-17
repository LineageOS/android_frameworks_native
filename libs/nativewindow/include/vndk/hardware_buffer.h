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

#ifndef ANDROID_VNDK_NATIVEWINDOW_AHARDWAREBUFFER_H
#define ANDROID_VNDK_NATIVEWINDOW_AHARDWAREBUFFER_H

// vndk is a superset of the NDK
#include <android/hardware_buffer.h>

#include <cutils/native_handle.h>

__BEGIN_DECLS

const native_handle_t* AHardwareBuffer_getNativeHandle(const AHardwareBuffer* buffer);

__END_DECLS

#endif /* ANDROID_VNDK_NATIVEWINDOW_AHARDWAREBUFFER_H */
