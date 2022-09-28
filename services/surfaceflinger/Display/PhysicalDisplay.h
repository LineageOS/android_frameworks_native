/*
 * Copyright 2022 The Android Open Source Project
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

#include <functional>
#include <utility>

#include <binder/IBinder.h>
#include <ui/DisplayId.h>
#include <ui/DisplayMap.h>
#include <utils/StrongPointer.h>

#include "DisplaySnapshot.h"
#include "DisplaySnapshotRef.h"

namespace android::display {

// TODO(b/229877597): Replace with AIDL type.
using DisplayToken = IBinder;

class PhysicalDisplay {
public:
    template <typename... Args>
    PhysicalDisplay(sp<DisplayToken> token, Args&&... args)
          : mToken(std::move(token)), mSnapshot(std::forward<Args>(args)...) {}

    PhysicalDisplay(const PhysicalDisplay&) = delete;
    PhysicalDisplay(PhysicalDisplay&&) = default;

    const sp<DisplayToken>& token() const { return mToken; }
    const DisplaySnapshot& snapshot() const { return mSnapshot; }

    // Transformers for PhysicalDisplays::get.

    DisplaySnapshotRef snapshotRef() const { return std::cref(mSnapshot); }

    bool isInternal() const {
        return mSnapshot.connectionType() == ui::DisplayConnectionType::Internal;
    }

    // Predicate for ftl::find_if on PhysicalDisplays.
    static constexpr auto hasToken(const sp<DisplayToken>& token) {
        return [&token](const std::pair<const PhysicalDisplayId, PhysicalDisplay>& pair) {
            return pair.second.token() == token;
        };
    }

private:
    const sp<DisplayToken> mToken;

    // Effectively const except in move constructor.
    DisplaySnapshot mSnapshot;
};

using PhysicalDisplays = ui::PhysicalDisplayMap<PhysicalDisplayId, PhysicalDisplay>;

// Combinator for ftl::Optional<PhysicalDisplayId>::and_then.
constexpr auto getPhysicalDisplay(const PhysicalDisplays& displays) {
    return [&](PhysicalDisplayId id) { return displays.get(id); };
}

} // namespace android::display
