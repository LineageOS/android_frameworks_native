/*
 * Copyright 2019 The Android Open Source Project
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

#include <binder/Parcelable.h>

#include <unordered_map>

namespace android::gui {

enum {
    METADATA_OWNER_UID = 1,
    METADATA_WINDOW_TYPE = 2,
    METADATA_TASK_ID = 3,
    METADATA_MOUSE_CURSOR = 4,
    METADATA_ACCESSIBILITY_ID = 5,
    METADATA_OWNER_PID = 6,
    METADATA_DEQUEUE_TIME = 7,
    METADATA_GAME_MODE = 8,
    METADATA_CALLING_UID = 9,
};

struct LayerMetadata : public Parcelable {
    std::unordered_map<uint32_t, std::vector<uint8_t>> mMap;

    LayerMetadata();
    LayerMetadata(const LayerMetadata& other);
    LayerMetadata(LayerMetadata&& other);
    explicit LayerMetadata(std::unordered_map<uint32_t, std::vector<uint8_t>> map);
    LayerMetadata& operator=(const LayerMetadata& other);
    LayerMetadata& operator=(LayerMetadata&& other);

    // Merges other into this LayerMetadata. If eraseEmpty is true, any entries in
    // in this whose keys are paired with empty values in other will be erased.
    bool merge(const LayerMetadata& other, bool eraseEmpty = false);

    status_t writeToParcel(Parcel* parcel) const override;
    status_t readFromParcel(const Parcel* parcel) override;

    bool has(uint32_t key) const;
    int32_t getInt32(uint32_t key, int32_t fallback) const;
    void setInt32(uint32_t key, int32_t value);
    std::optional<int64_t> getInt64(uint32_t key) const;
    void setInt64(uint32_t key, int64_t value);

    std::string itemToString(uint32_t key, const char* separator) const;
};

// Keep in sync with the GameManager.java constants.
enum class GameMode : int32_t {
    Unsupported = 0,
    Standard = 1,
    Performance = 2,
    Battery = 3,
    Custom = 4,

    ftl_last = Custom
};

} // namespace android::gui

using android::gui::METADATA_ACCESSIBILITY_ID;
using android::gui::METADATA_CALLING_UID;
using android::gui::METADATA_DEQUEUE_TIME;
using android::gui::METADATA_GAME_MODE;
using android::gui::METADATA_MOUSE_CURSOR;
using android::gui::METADATA_OWNER_PID;
using android::gui::METADATA_OWNER_UID;
using android::gui::METADATA_TASK_ID;
using android::gui::METADATA_WINDOW_TYPE;
