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

#include <gtest/gtest.h>

#include "../FocusResolver.h"

#define ASSERT_FOCUS_CHANGE(_changes, _oldFocus, _newFocus) \
    {                                                       \
        ASSERT_EQ(_oldFocus, _changes->oldFocus);           \
        ASSERT_EQ(_newFocus, _changes->newFocus);           \
    }

// atest inputflinger_tests:FocusResolverTest

using android::gui::FocusRequest;
using android::gui::WindowInfoHandle;

namespace android::inputdispatcher {

class FakeWindowHandle : public WindowInfoHandle {
public:
    FakeWindowHandle(const std::string& name, const sp<IBinder>& token, bool focusable,
                     bool visible) {
        mInfo.token = token;
        mInfo.name = name;
        setFocusable(focusable);
        setVisible(visible);
    }

    void setFocusable(bool focusable) {
        mInfo.setInputConfig(gui::WindowInfo::InputConfig::NOT_FOCUSABLE, !focusable);
    }
    void setVisible(bool visible) {
        mInfo.setInputConfig(gui::WindowInfo::InputConfig::NOT_VISIBLE, !visible);
    }
};

TEST(FocusResolverTest, SetFocusedWindow) {
    sp<IBinder> focusableWindowToken = sp<BBinder>::make();
    sp<IBinder> invisibleWindowToken = sp<BBinder>::make();
    sp<IBinder> unfocusableWindowToken = sp<BBinder>::make();
    std::vector<sp<WindowInfoHandle>> windows;
    windows.push_back(sp<FakeWindowHandle>::make("Focusable", focusableWindowToken,
                                                 /*focusable=*/true, /*visible=*/true));
    windows.push_back(sp<FakeWindowHandle>::make("Invisible", invisibleWindowToken,
                                                 /*focusable=*/true, /*visible=*/false));
    windows.push_back(sp<FakeWindowHandle>::make("unfocusable", unfocusableWindowToken,
                                                 /*focusable=*/false, /*visible=*/true));

    // focusable window can get focused
    FocusRequest request;
    request.displayId = 42;
    request.token = focusableWindowToken;
    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ focusableWindowToken);
    ASSERT_EQ(request.displayId, changes->displayId);

    // invisible window cannot get focused
    request.token = invisibleWindowToken;
    changes = focusResolver.setFocusedWindow(request, windows);
    ASSERT_EQ(focusableWindowToken, changes->oldFocus);
    ASSERT_EQ(nullptr, changes->newFocus);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ focusableWindowToken, /*to*/ nullptr);

    // unfocusableWindowToken window cannot get focused
    request.token = unfocusableWindowToken;
    changes = focusResolver.setFocusedWindow(request, windows);
    ASSERT_FALSE(changes);
}

TEST(FocusResolverTest, RemoveFocusFromFocusedWindow) {
    sp<IBinder> focusableWindowToken = sp<BBinder>::make();
    std::vector<sp<WindowInfoHandle>> windows;
    windows.push_back(sp<FakeWindowHandle>::make("Focusable", focusableWindowToken,
                                                 /*focusable=*/true, /*visible=*/true));

    FocusRequest request;
    request.displayId = 42;
    request.token = focusableWindowToken;
    FocusResolver focusResolver;
    // Focusable window gets focus.
    request.token = focusableWindowToken;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    ASSERT_FOCUS_CHANGE(changes, nullptr, focusableWindowToken);

    // Window token of a request is null, focus should be revoked.
    request.token = NULL;
    changes = focusResolver.setFocusedWindow(request, windows);
    ASSERT_EQ(focusableWindowToken, changes->oldFocus);
    ASSERT_EQ(nullptr, changes->newFocus);
    ASSERT_FOCUS_CHANGE(changes, focusableWindowToken, nullptr);
}

TEST(FocusResolverTest, SetFocusedMirroredWindow) {
    sp<IBinder> focusableWindowToken = sp<BBinder>::make();
    sp<IBinder> invisibleWindowToken = sp<BBinder>::make();
    sp<IBinder> unfocusableWindowToken = sp<BBinder>::make();
    std::vector<sp<WindowInfoHandle>> windows;
    windows.push_back(sp<FakeWindowHandle>::make("Mirror1", focusableWindowToken,
                                                 /*focusable=*/true, /*visible=*/true));
    windows.push_back(sp<FakeWindowHandle>::make("Mirror1", focusableWindowToken,
                                                 /*focusable=*/true, /*visible=*/true));

    windows.push_back(sp<FakeWindowHandle>::make("Mirror2Visible", invisibleWindowToken,
                                                 /*focusable=*/true, /*visible=*/true));
    windows.push_back(sp<FakeWindowHandle>::make("Mirror2Invisible", invisibleWindowToken,
                                                 /*focusable=*/true, /*visible=*/false));

    windows.push_back(sp<FakeWindowHandle>::make("Mirror3Focusable", unfocusableWindowToken,
                                                 /*focusable=*/true, /*visible=*/true));
    windows.push_back(sp<FakeWindowHandle>::make("Mirror3Unfocusable", unfocusableWindowToken,
                                                 /*focusable=*/false, /*visible=*/true));

    // mirrored window can get focused
    FocusRequest request;
    request.displayId = 42;
    request.token = focusableWindowToken;
    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ focusableWindowToken);

    // mirrored window with one visible window can get focused
    request.token = invisibleWindowToken;
    changes = focusResolver.setFocusedWindow(request, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ focusableWindowToken, /*to*/ invisibleWindowToken);

    // mirrored window with one or more unfocusable window cannot get focused
    request.token = unfocusableWindowToken;
    changes = focusResolver.setFocusedWindow(request, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ invisibleWindowToken, /*to*/ nullptr);
}

TEST(FocusResolverTest, SetInputWindows) {
    sp<IBinder> focusableWindowToken = sp<BBinder>::make();
    std::vector<sp<WindowInfoHandle>> windows;
    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make("Focusable", focusableWindowToken, /*focusable=*/true,
                                       /*visible=*/true);
    windows.push_back(window);

    // focusable window can get focused
    FocusRequest request;
    request.displayId = 42;
    request.token = focusableWindowToken;
    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    ASSERT_EQ(focusableWindowToken, changes->newFocus);

    // Window visibility changes and the window loses focus
    window->setVisible(false);
    changes = focusResolver.setInputWindows(request.displayId, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ focusableWindowToken, /*to*/ nullptr);
}

TEST(FocusResolverTest, FocusRequestsCanBePending) {
    sp<IBinder> invisibleWindowToken = sp<BBinder>::make();
    std::vector<sp<WindowInfoHandle>> windows;

    sp<FakeWindowHandle> invisibleWindow =
            sp<FakeWindowHandle>::make("Invisible", invisibleWindowToken, /*focusable=*/true,
                                       /*visible=*/false);
    windows.push_back(invisibleWindow);

    // invisible window cannot get focused
    FocusRequest request;
    request.displayId = 42;
    request.token = invisibleWindowToken;
    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    ASSERT_FALSE(changes);

    // Window visibility changes and the window gets focused
    invisibleWindow->setVisible(true);
    changes = focusResolver.setInputWindows(request.displayId, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ invisibleWindowToken);
}

TEST(FocusResolverTest, FocusRequestsArePersistent) {
    sp<IBinder> windowToken = sp<BBinder>::make();
    std::vector<sp<WindowInfoHandle>> windows;

    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make("Test Window", windowToken, /*focusable=*/false,
                                       /*visible=*/true);
    windows.push_back(window);

    // non-focusable window cannot get focused
    FocusRequest request;
    request.displayId = 42;
    request.token = windowToken;
    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    ASSERT_FALSE(changes);

    // Focusability changes and the window gets focused
    window->setFocusable(true);
    changes = focusResolver.setInputWindows(request.displayId, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ windowToken);

    // Visibility changes and the window loses focus
    window->setVisible(false);
    changes = focusResolver.setInputWindows(request.displayId, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ windowToken, /*to*/ nullptr);

    // Visibility changes and the window gets focused
    window->setVisible(true);
    changes = focusResolver.setInputWindows(request.displayId, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ windowToken);

    // Window is gone and the window loses focus
    changes = focusResolver.setInputWindows(request.displayId, {});
    ASSERT_FOCUS_CHANGE(changes, /*from*/ windowToken, /*to*/ nullptr);

    // Window returns and the window gains focus
    changes = focusResolver.setInputWindows(request.displayId, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ windowToken);
}

TEST(FocusResolverTest, ConditionalFocusRequestsAreNotPersistent) {
    sp<IBinder> hostWindowToken = sp<BBinder>::make();
    std::vector<sp<WindowInfoHandle>> windows;

    sp<FakeWindowHandle> hostWindow =
            sp<FakeWindowHandle>::make("Host Window", hostWindowToken, /*focusable=*/true,
                                       /*visible=*/true);
    windows.push_back(hostWindow);
    sp<IBinder> embeddedWindowToken = sp<BBinder>::make();
    sp<FakeWindowHandle> embeddedWindow =
            sp<FakeWindowHandle>::make("Embedded Window", embeddedWindowToken, /*focusable=*/true,
                                       /*visible=*/true);
    windows.push_back(embeddedWindow);

    FocusRequest request;
    request.displayId = 42;
    request.token = hostWindowToken;
    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ hostWindowToken);

    request.focusedToken = hostWindow->getToken();
    request.token = embeddedWindowToken;
    changes = focusResolver.setFocusedWindow(request, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ hostWindowToken, /*to*/ embeddedWindowToken);

    embeddedWindow->setFocusable(false);
    changes = focusResolver.setInputWindows(request.displayId, windows);
    // The embedded window is no longer focusable, provide focus back to the original focused
    // window.
    ASSERT_FOCUS_CHANGE(changes, /*from*/ embeddedWindowToken, /*to*/ hostWindowToken);

    embeddedWindow->setFocusable(true);
    changes = focusResolver.setInputWindows(request.displayId, windows);
    // The embedded window is focusable again, but we it cannot gain focus unless there is another
    // focus request.
    ASSERT_FALSE(changes);

    embeddedWindow->setVisible(false);
    changes = focusResolver.setFocusedWindow(request, windows);
    // If the embedded window is not visible/focusable, then we do not grant it focus and the
    // request is dropped.
    ASSERT_FALSE(changes);

    embeddedWindow->setVisible(true);
    changes = focusResolver.setInputWindows(request.displayId, windows);
    // If the embedded window becomes visble/focusable, nothing changes since the request has been
    // dropped.
    ASSERT_FALSE(changes);
}
TEST(FocusResolverTest, FocusRequestsAreClearedWhenWindowIsRemoved) {
    sp<IBinder> windowToken = sp<BBinder>::make();
    std::vector<sp<WindowInfoHandle>> windows;

    sp<FakeWindowHandle> window =
            sp<FakeWindowHandle>::make("Test Window", windowToken, /*focusable=*/true,
                                       /*visible=*/true);
    windows.push_back(window);

    FocusRequest request;
    request.displayId = 42;
    request.token = windowToken;
    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ windowToken);
    ASSERT_EQ(request.displayId, changes->displayId);

    // Start with a focused window
    window->setFocusable(true);
    changes = focusResolver.setInputWindows(request.displayId, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ windowToken);

    // When a display is removed, all windows are removed from the display
    // and our focused window loses focus
    changes = focusResolver.setInputWindows(request.displayId, {});
    ASSERT_FOCUS_CHANGE(changes, /*from*/ windowToken, /*to*/ nullptr);
    focusResolver.displayRemoved(request.displayId);

    // When a display is readded, the window does not get focus since the request was cleared.
    changes = focusResolver.setInputWindows(request.displayId, windows);
    ASSERT_FALSE(changes);
}

} // namespace android::inputdispatcher
