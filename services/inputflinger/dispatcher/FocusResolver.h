/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <stdint.h>
#include <optional>
#include <unordered_map>

#include <android/FocusRequest.h>
#include <binder/Binder.h>
#include <input/InputWindow.h>

namespace android::inputdispatcher {

// Keeps track of the focused window per display. The class listens to updates from input dispatcher
// and provides focus changes.
//
// Focus Policy
//   Window focusabilty - A window token can be focused if there is at least one window handle that
//   is visible with the same token and all window handles with the same token are focusable.
//   See FocusResolver::isTokenFocusable
//
//   Focus request - Request will be granted if the window is focusable. If the window is not
//   visible, then the request is kept in a pending state and granted when it becomes visible.
//   If window becomes not focusable, or another request comes in, the pending request is dropped.
//
//   Window handle updates - Focus is lost when the currently focused window becomes not focusable.
class FocusResolver {
public:
    // Returns the focused window token on the specified display.
    sp<IBinder> getFocusedWindowToken(int32_t displayId) const;

    struct FocusChanges {
        sp<IBinder> oldFocus;
        sp<IBinder> newFocus;
        int32_t displayId;
        std::string reason;
    };
    std::optional<FocusResolver::FocusChanges> setInputWindows(
            int32_t displayId, const std::vector<sp<InputWindowHandle>>& windows);
    std::optional<FocusResolver::FocusChanges> setFocusedWindow(
            const FocusRequest& request, const std::vector<sp<InputWindowHandle>>& windows);

    // exposed for debugging
    bool hasFocusedWindowTokens() const { return !mFocusedWindowTokenByDisplay.empty(); }
    std::string dumpFocusedWindows() const;
    std::string dump() const;

private:
    enum class FocusResult {
        OK,
        NO_WINDOW,
        NOT_FOCUSABLE,
        NOT_VISIBLE,
    };

    // Checks if the window token can be focused on a display. The token can be focused if there is
    // at least one window handle that is visible with the same token and all window handles with
    // the same token are focusable.
    //
    // In the case of mirroring, two windows may share the same window token and their visibility
    // might be different. Example, the mirrored window can cover the window its mirroring. However,
    // we expect the focusability of the windows to match since its hard to reason why one window
    // can receive focus events and the other cannot when both are backed by the same input channel.
    //
    static FocusResult isTokenFocusable(const sp<IBinder>& token,
                                        const std::vector<sp<InputWindowHandle>>& windows);

    // Focus tracking for keys, trackball, etc. A window token can be associated with one or
    // more InputWindowHandles. If a window is mirrored, the window and its mirror will share
    // the same token. Focus is tracked by the token per display and the events are dispatched
    // to the channel associated by this token.
    typedef std::pair<std::string /* name */, sp<IBinder>> NamedToken;
    std::unordered_map<int32_t /* displayId */, NamedToken> mFocusedWindowTokenByDisplay;

    // This map will store a single pending focus request per display that cannot be currently
    // processed. This can happen if the window requested to be focused is not currently visible.
    // Such a window might become visible later, and these requests would be processed at that time.
    std::unordered_map<int32_t /* displayId */, FocusRequest> mPendingFocusRequests;

    std::optional<FocusResolver::FocusChanges> updateFocusedWindow(
            int32_t displayId, const std::string& reason, const sp<IBinder>& token,
            const std::string& tokenName = "");
    std::optional<FocusRequest> getPendingRequest(int32_t displayId);
};

} // namespace android::inputdispatcher