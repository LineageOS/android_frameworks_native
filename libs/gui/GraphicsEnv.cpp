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
#include <gui/GraphicsEnv.h>

#include <log/log.h>

namespace android {

/*static*/ GraphicsEnv& GraphicsEnv::getInstance() {
    static GraphicsEnv env;
    return env;
}

void GraphicsEnv::setDriverPath(const std::string path) {
    if (!mDriverPath.empty()) {
        ALOGV("ignoring attempt to change driver path from '%s' to '%s'",
                mDriverPath.c_str(), path.c_str());
        return;
    }
    ALOGV("setting driver path to '%s'", path.c_str());
    mDriverPath = path;
}

} // namespace android
