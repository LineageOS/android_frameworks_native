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

#pragma once

#include <layerproto/LayerProtoHeader.h>
#include <utils/Errors.h>
#include <utils/String8.h>

#include <memory>
#include <mutex>

using namespace android::surfaceflinger;

namespace android {

/*
 * SurfaceTracing records layer states during surface flinging.
 */
class SurfaceTracing {
public:
    void enable();
    status_t disable();
    bool isEnabled() const;

    void traceLayers(const char* where, LayersProto);
    void dump(String8& result) const;

private:
    static constexpr auto DEFAULT_FILENAME = "/data/misc/wmtrace/layers_trace.pb";

    status_t writeProtoFileLocked();

    bool mEnabled = false;
    std::string mOutputFileName = DEFAULT_FILENAME;
    mutable std::mutex mTraceMutex;
    std::unique_ptr<LayersTraceFileProto> mTrace;
};

} // namespace android
