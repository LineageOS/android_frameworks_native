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

#define LOG_TAG "FocusResolver"
#define ATRACE_TAG ATRACE_TAG_INPUT

#define INDENT "  "
#define INDENT2 "    "

// Log debug messages about input focus tracking.
static constexpr bool DEBUG_FOCUS = false;

#include <inttypes.h>

#include <android-base/stringprintf.h>
#include <binder/Binder.h>
#include <input/InputWindow.h>
#include <input/NamedEnum.h>
#include <log/log.h>

#include "FocusResolver.h"

namespace android::inputdispatcher {

sp<IBinder> FocusResolver::getFocusedWindowToken(int32_t displayId) const {
    auto it = mFocusedWindowTokenByDisplay.find(displayId);
    return it != mFocusedWindowTokenByDisplay.end() ? it->second.second : nullptr;
}

std::optional<FocusRequest> FocusResolver::getPendingRequest(int32_t displayId) {
    auto it = mPendingFocusRequests.find(displayId);
    return it != mPendingFocusRequests.end() ? std::make_optional<>(it->second) : std::nullopt;
}

std::optional<FocusResolver::FocusChanges> FocusResolver::setInputWindows(
        int32_t displayId, const std::vector<sp<InputWindowHandle>>& windows) {
    // If the current focused window becomes unfocusable, remove focus.
    sp<IBinder> currentFocus = getFocusedWindowToken(displayId);
    if (currentFocus) {
        FocusResult result = isTokenFocusable(currentFocus, windows);
        if (result != FocusResult::OK) {
            return updateFocusedWindow(displayId, NamedEnum::string(result), nullptr);
        }
    }

    // Check if any pending focus requests can be resolved.
    std::optional<FocusRequest> pendingRequest = getPendingRequest(displayId);
    if (!pendingRequest) {
        return std::nullopt;
    }

    sp<IBinder> requestedFocus = pendingRequest->token;
    std::string windowName = pendingRequest->windowName;
    if (currentFocus == requestedFocus) {
        ALOGD_IF(DEBUG_FOCUS,
                 "setFocusedWindow %s on display %" PRId32 " ignored, reason: already focused",
                 windowName.c_str(), displayId);
        mPendingFocusRequests.erase(displayId);
        return std::nullopt;
    }

    FocusResult result = isTokenFocusable(requestedFocus, windows);
    // If the window from the pending request is now visible, provide it focus.
    if (result == FocusResult::OK) {
        mPendingFocusRequests.erase(displayId);
        return updateFocusedWindow(displayId, "Window became visible", requestedFocus, windowName);
    }

    if (result != FocusResult::NOT_VISIBLE) {
        // Drop the request if we are unable to change the focus for a reason other than visibility.
        ALOGW("Focus request %s on display %" PRId32 " ignored, reason:%s", windowName.c_str(),
              displayId, NamedEnum::string(result).c_str());
        mPendingFocusRequests.erase(displayId);
    }
    return std::nullopt;
}

std::optional<FocusResolver::FocusChanges> FocusResolver::setFocusedWindow(
        const FocusRequest& request, const std::vector<sp<InputWindowHandle>>& windows) {
    const int32_t displayId = request.displayId;
    const sp<IBinder> currentFocus = getFocusedWindowToken(displayId);
    if (request.focusedToken && currentFocus != request.focusedToken) {
        ALOGW("setFocusedWindow %s on display %" PRId32
              " ignored, reason: focusedToken  %s is not focused",
              request.windowName.c_str(), displayId, request.focusedWindowName.c_str());
        return std::nullopt;
    }

    std::optional<FocusRequest> pendingRequest = getPendingRequest(displayId);
    if (pendingRequest) {
        ALOGW("Pending focus request %s on display %" PRId32
              " ignored, reason:replaced by new request",
              pendingRequest->windowName.c_str(), displayId);

        // clear any pending focus requests
        mPendingFocusRequests.erase(displayId);
    }

    if (currentFocus == request.token) {
        ALOGD_IF(DEBUG_FOCUS,
                 "setFocusedWindow %s on display %" PRId32 " ignored, reason:already focused",
                 request.windowName.c_str(), displayId);
        return std::nullopt;
    }

    FocusResult result = isTokenFocusable(request.token, windows);
    if (result == FocusResult::OK) {
        std::string reason =
                (request.focusedToken) ? "setFocusedWindow with focus check" : "setFocusedWindow";
        return updateFocusedWindow(displayId, reason, request.token, request.windowName);
    }

    if (result == FocusResult::NOT_VISIBLE) {
        // The requested window is not currently visible. Wait for the window to become visible
        // and then provide it focus. This is to handle situations where a user action triggers
        // a new window to appear. We want to be able to queue any key events after the user
        // action and deliver it to the newly focused window. In order for this to happen, we
        // take focus from the currently focused window so key events can be queued.
        ALOGD_IF(DEBUG_FOCUS,
                 "setFocusedWindow %s on display %" PRId32
                 " pending, reason: window is not visible",
                 request.windowName.c_str(), displayId);
        mPendingFocusRequests[displayId] = request;
        return updateFocusedWindow(displayId, "Waiting for window to be visible", nullptr);
    } else {
        ALOGW("setFocusedWindow %s on display %" PRId32 " ignored, reason:%s",
              request.windowName.c_str(), displayId, NamedEnum::string(result).c_str());
    }

    return std::nullopt;
}

FocusResolver::FocusResult FocusResolver::isTokenFocusable(
        const sp<IBinder>& token, const std::vector<sp<InputWindowHandle>>& windows) {
    bool allWindowsAreFocusable = true;
    bool visibleWindowFound = false;
    bool windowFound = false;
    for (const sp<InputWindowHandle>& window : windows) {
        if (window->getToken() != token) {
            continue;
        }
        windowFound = true;
        if (window->getInfo()->visible) {
            // Check if at least a single window is visible.
            visibleWindowFound = true;
        }
        if (!window->getInfo()->focusable) {
            // Check if all windows with the window token are focusable.
            allWindowsAreFocusable = false;
            break;
        }
    }

    if (!windowFound) {
        return FocusResult::NO_WINDOW;
    }
    if (!allWindowsAreFocusable) {
        return FocusResult::NOT_FOCUSABLE;
    }
    if (!visibleWindowFound) {
        return FocusResult::NOT_VISIBLE;
    }

    return FocusResult::OK;
}

std::optional<FocusResolver::FocusChanges> FocusResolver::updateFocusedWindow(
        int32_t displayId, const std::string& reason, const sp<IBinder>& newFocus,
        const std::string& tokenName) {
    sp<IBinder> oldFocus = getFocusedWindowToken(displayId);
    if (newFocus == oldFocus) {
        return std::nullopt;
    }
    if (newFocus) {
        mFocusedWindowTokenByDisplay[displayId] = {tokenName, newFocus};
    } else {
        mFocusedWindowTokenByDisplay.erase(displayId);
    }

    return {{oldFocus, newFocus, displayId, reason}};
}

std::string FocusResolver::dumpFocusedWindows() const {
    if (mFocusedWindowTokenByDisplay.empty()) {
        return INDENT "FocusedWindows: <none>\n";
    }

    std::string dump;
    dump += INDENT "FocusedWindows:\n";
    for (const auto& [displayId, namedToken] : mFocusedWindowTokenByDisplay) {
        dump += base::StringPrintf(INDENT2 "displayId=%" PRId32 ", name='%s'\n", displayId,
                                   namedToken.first.c_str());
    }
    return dump;
}

std::string FocusResolver::dump() const {
    std::string dump = dumpFocusedWindows();

    if (mPendingFocusRequests.empty()) {
        return dump + INDENT "PendingFocusRequests: <none>\n";
    }

    dump += INDENT "PendingFocusRequests:\n";
    for (const auto& [displayId, request] : mPendingFocusRequests) {
        dump += base::StringPrintf(INDENT2 "displayId=%" PRId32 ", name='%s'\n", displayId,
                                   request.windowName.c_str());
    }
    return dump;
}

} // namespace android::inputdispatcher
