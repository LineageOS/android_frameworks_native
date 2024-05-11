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
#include <optional>
#define LOG_TAG "InputDispatcher"
#define ATRACE_TAG ATRACE_TAG_INPUT

#define INDENT "  "
#define INDENT2 "    "

#include <inttypes.h>

#include <android-base/stringprintf.h>
#include <binder/Binder.h>
#include <ftl/enum.h>
#include <gui/WindowInfo.h>
#include <unordered_set>

#include "DebugConfig.h"
#include "FocusResolver.h"

using android::gui::FocusRequest;
using android::gui::WindowInfoHandle;

namespace android::inputdispatcher {

template <typename T>
struct SpHash {
    size_t operator()(const sp<T>& k) const { return std::hash<T*>()(k.get()); }
};

sp<IBinder> FocusResolver::getFocusedWindowToken(ui::LogicalDisplayId displayId) const {
    auto it = mFocusedWindowTokenByDisplay.find(displayId);
    return it != mFocusedWindowTokenByDisplay.end() ? it->second.second : nullptr;
}

std::optional<FocusRequest> FocusResolver::getFocusRequest(ui::LogicalDisplayId displayId) {
    auto it = mFocusRequestByDisplay.find(displayId);
    return it != mFocusRequestByDisplay.end() ? std::make_optional<>(it->second) : std::nullopt;
}

/**
 * 'setInputWindows' is called when the window properties change. Here we will check whether the
 * currently focused window can remain focused. If the currently focused window remains eligible
 * for focus ('isTokenFocusable' returns OK), then we will continue to grant it focus otherwise
 * we will check if the previous focus request is eligible to receive focus.
 */
std::optional<FocusResolver::FocusChanges> FocusResolver::setInputWindows(
        ui::LogicalDisplayId displayId, const std::vector<sp<WindowInfoHandle>>& windows) {
    std::string removeFocusReason;

    const std::optional<FocusRequest> request = getFocusRequest(displayId);
    const sp<IBinder> currentFocus = getFocusedWindowToken(displayId);

    // Find the next focused token based on the latest FocusRequest. If the requested focus window
    // cannot be focused, focus will be removed.
    if (request) {
        sp<IBinder> requestedFocus = request->token;
        sp<WindowInfoHandle> resolvedFocusWindow;
        Focusability result = getResolvedFocusWindow(requestedFocus, windows, resolvedFocusWindow);
        if (result == Focusability::OK && resolvedFocusWindow->getToken() == currentFocus) {
            return std::nullopt;
        }
        const Focusability previousResult = mLastFocusResultByDisplay[displayId];
        mLastFocusResultByDisplay[displayId] = result;
        if (result == Focusability::OK) {
            LOG_ALWAYS_FATAL_IF(!resolvedFocusWindow,
                                "Focused window should be non-null when result is OK!");
            return updateFocusedWindow(displayId,
                                       "Window became focusable. Previous reason: " +
                                               ftl::enum_string(previousResult),
                                       resolvedFocusWindow->getToken(),
                                       resolvedFocusWindow->getName());
        }
        removeFocusReason = ftl::enum_string(result);
    }

    // Focused window is no longer focusable and we don't have a suitable focus request to grant.
    // Remove focus if needed.
    return updateFocusedWindow(displayId, removeFocusReason, nullptr);
}

std::optional<FocusResolver::FocusChanges> FocusResolver::setFocusedWindow(
        const FocusRequest& request, const std::vector<sp<WindowInfoHandle>>& windows) {
    const ui::LogicalDisplayId displayId = ui::LogicalDisplayId{request.displayId};
    const sp<IBinder> currentFocus = getFocusedWindowToken(displayId);
    if (currentFocus == request.token) {
        ALOGD_IF(DEBUG_FOCUS, "setFocusedWindow %s on display %s ignored, reason: already focused",
                 request.windowName.c_str(), displayId.toString().c_str());
        return std::nullopt;
    }

    sp<WindowInfoHandle> resolvedFocusWindow;
    Focusability result = getResolvedFocusWindow(request.token, windows, resolvedFocusWindow);
    // Update focus request. The focus resolver will always try to handle this request if there is
    // no focused window on the display.
    mFocusRequestByDisplay[displayId] = request;
    mLastFocusResultByDisplay[displayId] = result;

    if (result == Focusability::OK) {
        LOG_ALWAYS_FATAL_IF(!resolvedFocusWindow,
                            "Focused window should be non-null when result is OK!");
        return updateFocusedWindow(displayId, "setFocusedWindow", resolvedFocusWindow->getToken(),
                                   resolvedFocusWindow->getName());
    }

    // The requested window is not currently focusable. Wait for the window to become focusable
    // but remove focus from the current window so that input events can go into a pending queue
    // and be sent to the window when it becomes focused.
    return updateFocusedWindow(displayId, "Waiting for window because " + ftl::enum_string(result),
                               nullptr);
}

FocusResolver::Focusability FocusResolver::getResolvedFocusWindow(
        const sp<IBinder>& token, const std::vector<sp<WindowInfoHandle>>& windows,
        sp<WindowInfoHandle>& outFocusableWindow) {
    sp<IBinder> curFocusCandidate = token;
    bool focusedWindowFound = false;

    // Keep track of all windows reached to prevent a cyclical transferFocus request.
    std::unordered_set<sp<IBinder>, SpHash<IBinder>> tokensReached;

    while (curFocusCandidate != nullptr && tokensReached.count(curFocusCandidate) == 0) {
        tokensReached.emplace(curFocusCandidate);
        Focusability result = isTokenFocusable(curFocusCandidate, windows, outFocusableWindow);
        if (result == Focusability::OK) {
            LOG_ALWAYS_FATAL_IF(!outFocusableWindow,
                                "Focused window should be non-null when result is OK!");
            focusedWindowFound = true;
            // outFocusableWindow has been updated by isTokenFocusable to contain
            // the window info for curFocusCandidate. See if we can grant focus
            // to the token that it wants to transfer its focus to.
            curFocusCandidate = outFocusableWindow->getInfo()->focusTransferTarget;
        }

        // If the initial token is not focusable, return early with the failed result.
        if (!focusedWindowFound) {
            return result;
        }
    }

    return focusedWindowFound ? Focusability::OK : Focusability::NO_WINDOW;
}

FocusResolver::Focusability FocusResolver::isTokenFocusable(
        const sp<IBinder>& token, const std::vector<sp<WindowInfoHandle>>& windows,
        sp<WindowInfoHandle>& outFocusableWindow) {
    bool allWindowsAreFocusable = true;
    bool windowFound = false;
    sp<WindowInfoHandle> visibleWindowHandle = nullptr;
    for (const sp<WindowInfoHandle>& window : windows) {
        if (window->getToken() != token) {
            continue;
        }
        windowFound = true;
        if (!window->getInfo()->inputConfig.test(gui::WindowInfo::InputConfig::NOT_VISIBLE)) {
            // Check if at least a single window is visible.
            visibleWindowHandle = window;
        }
        if (window->getInfo()->inputConfig.test(gui::WindowInfo::InputConfig::NOT_FOCUSABLE)) {
            // Check if all windows with the window token are focusable.
            allWindowsAreFocusable = false;
            break;
        }
    }

    if (!windowFound) {
        return Focusability::NO_WINDOW;
    }
    if (!allWindowsAreFocusable) {
        return Focusability::NOT_FOCUSABLE;
    }
    if (!visibleWindowHandle) {
        return Focusability::NOT_VISIBLE;
    }

    // Only set the outFoundWindow if the window can be focused
    outFocusableWindow = visibleWindowHandle;
    return Focusability::OK;
}

std::optional<FocusResolver::FocusChanges> FocusResolver::updateFocusedWindow(
        ui::LogicalDisplayId displayId, const std::string& reason, const sp<IBinder>& newFocus,
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
        dump += base::StringPrintf(INDENT2 "displayId=%s, name='%s'\n",
                                   displayId.toString().c_str(), namedToken.first.c_str());
    }
    return dump;
}

std::string FocusResolver::dump() const {
    std::string dump = dumpFocusedWindows();
    if (mFocusRequestByDisplay.empty()) {
        return dump + INDENT "FocusRequests: <none>\n";
    }

    dump += INDENT "FocusRequests:\n";
    for (const auto& [displayId, request] : mFocusRequestByDisplay) {
        auto it = mLastFocusResultByDisplay.find(displayId);
        std::string result =
                it != mLastFocusResultByDisplay.end() ? ftl::enum_string(it->second) : "";
        dump += base::StringPrintf(INDENT2 "displayId=%s, name='%s' result='%s'\n",
                                   displayId.toString().c_str(), request.windowName.c_str(),
                                   result.c_str());
    }
    return dump;
}

void FocusResolver::displayRemoved(ui::LogicalDisplayId displayId) {
    mFocusRequestByDisplay.erase(displayId);
    mLastFocusResultByDisplay.erase(displayId);
}

} // namespace android::inputdispatcher
