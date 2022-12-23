/*
 ** Copyright 2022, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#ifndef ANDROID_EGL_CACHE_MULTIFILE_H
#define ANDROID_EGL_CACHE_MULTIFILE_H

#include <EGL/egl.h>
#include <EGL/eglext.h>

#include <string>

namespace android {

void setBlobMultifile(const void* key, EGLsizeiANDROID keySize, const void* value,
                      EGLsizeiANDROID valueSize, const std::string& baseDir);
EGLsizeiANDROID getBlobMultifile(const void* key, EGLsizeiANDROID keySize, void* value,
                                 EGLsizeiANDROID valueSize, const std::string& baseDir);
size_t getMultifileCacheSize();
void checkMultifileCacheSize(size_t cacheByteLimit);

}; // namespace android

#endif // ANDROID_EGL_CACHE_MULTIFILE_H
