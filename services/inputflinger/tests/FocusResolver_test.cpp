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
        ASSERT_TRUE(_changes.has_value());                  \
        ASSERT_EQ(_oldFocus, _changes->oldFocus);           \
        ASSERT_EQ(_newFocus, _changes->newFocus);           \
    }

// atest inputflinger_tests:FocusResolverTest

using android::gui::FocusRequest;
using android::gui::WindowInfoHandle;

namespace android::inputdispatcher {

namespace {

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

} // namespace

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
    ASSERT_EQ(ui::LogicalDisplayId{request.displayId}, changes->displayId);

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

TEST(FocusResolverTest, FocusTransferToMirror) {
    sp<IBinder> focusableWindowToken = sp<BBinder>::make();
    auto window = sp<FakeWindowHandle>::make("Window", focusableWindowToken,
                                             /*focusable=*/true, /*visible=*/true);
    auto mirror = sp<FakeWindowHandle>::make("Mirror", focusableWindowToken,
                                             /*focusable=*/true, /*visible=*/true);

    FocusRequest request;
    request.displayId = 42;
    request.token = focusableWindowToken;
    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, {window, mirror});
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ focusableWindowToken);

    // The mirror window now comes on top, and the focus does not change
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId},
                                            {mirror, window});
    ASSERT_FALSE(changes.has_value());

    // The window now comes on top while the mirror is removed, and the focus does not change
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, {window});
    ASSERT_FALSE(changes.has_value());

    // The window is removed but the mirror is on top, and focus does not change
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, {mirror});
    ASSERT_FALSE(changes.has_value());

    // All windows removed
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, {});
    ASSERT_FOCUS_CHANGE(changes, /*from*/ focusableWindowToken, /*to*/ nullptr);
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

    // When there are no changes to the window, focus does not change
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FALSE(changes.has_value());

    // Window visibility changes and the window loses focus
    window->setVisible(false);
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
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
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
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
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ windowToken);

    // Visibility changes and the window loses focus
    window->setVisible(false);
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ windowToken, /*to*/ nullptr);

    // Visibility changes and the window gets focused
    window->setVisible(true);
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ windowToken);

    // Window is gone and the window loses focus
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, {});
    ASSERT_FOCUS_CHANGE(changes, /*from*/ windowToken, /*to*/ nullptr);

    // Window returns and the window gains focus
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ windowToken);
}

TEST(FocusResolverTest, FocusTransferTarget) {
    sp<IBinder> hostWindowToken = sp<BBinder>::make();
    std::vector<sp<WindowInfoHandle>> windows;

    sp<FakeWindowHandle> hostWindow =
            sp<FakeWindowHandle>::make("Host Window", hostWindowToken, /*focusable=*/true,
                                       /*visible=*/true);
    windows.push_back(hostWindow);
    sp<IBinder> embeddedWindowToken = sp<BBinder>::make();
    sp<FakeWindowHandle> embeddedWindow =
            sp<FakeWindowHandle>::make("Embedded Window", embeddedWindowToken, /*focusable=*/false,
                                       /*visible=*/true);
    windows.push_back(embeddedWindow);

    FocusRequest request;
    request.displayId = 42;
    request.token = hostWindowToken;

    // Host wants to transfer touch to embedded.
    hostWindow->editInfo()->focusTransferTarget = embeddedWindowToken;

    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    // Embedded was not focusable so host gains focus.
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ hostWindowToken);

    // Embedded is now focusable so will gain focus
    embeddedWindow->setFocusable(true);
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ hostWindowToken, /*to*/ embeddedWindowToken);

    // Embedded is not visible so host will get focus
    embeddedWindow->setVisible(false);
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ embeddedWindowToken, /*to*/ hostWindowToken);

    // Embedded is now visible so will get focus
    embeddedWindow->setVisible(true);
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ hostWindowToken, /*to*/ embeddedWindowToken);

    // Remove focusTransferTarget from host. Host will gain focus.
    hostWindow->editInfo()->focusTransferTarget = nullptr;
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ embeddedWindowToken, /*to*/ hostWindowToken);

    // Set invalid token for focusTransferTarget. Host will remain focus
    hostWindow->editInfo()->focusTransferTarget = sp<BBinder>::make();
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FALSE(changes);
}

TEST(FocusResolverTest, FocusTransferMultipleInChain) {
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

    sp<IBinder> embeddedWindowToken2 = sp<BBinder>::make();
    sp<FakeWindowHandle> embeddedWindow2 =
            sp<FakeWindowHandle>::make("Embedded Window2", embeddedWindowToken2, /*focusable=*/true,
                                       /*visible=*/true);
    windows.push_back(embeddedWindow2);

    FocusRequest request;
    request.displayId = 42;
    request.token = hostWindowToken;

    hostWindow->editInfo()->focusTransferTarget = embeddedWindowToken;
    embeddedWindow->editInfo()->focusTransferTarget = embeddedWindowToken2;

    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ embeddedWindowToken2);
}

TEST(FocusResolverTest, FocusTransferTargetCycle) {
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

    sp<IBinder> embeddedWindowToken2 = sp<BBinder>::make();
    sp<FakeWindowHandle> embeddedWindow2 =
            sp<FakeWindowHandle>::make("Embedded Window2", embeddedWindowToken2, /*focusable=*/true,
                                       /*visible=*/true);
    windows.push_back(embeddedWindow2);

    FocusRequest request;
    request.displayId = 42;
    request.token = hostWindowToken;

    hostWindow->editInfo()->focusTransferTarget = embeddedWindowToken;
    embeddedWindow->editInfo()->focusTransferTarget = embeddedWindowToken2;
    embeddedWindow2->editInfo()->focusTransferTarget = hostWindowToken;

    FocusResolver focusResolver;
    std::optional<FocusResolver::FocusChanges> changes =
            focusResolver.setFocusedWindow(request, windows);
    // Cycle will be detected and stop right before trying to transfer token to host again.
    ASSERT_FOCUS_CHANGE(changes, /*from*/ nullptr, /*to*/ embeddedWindowToken2);
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
    ASSERT_EQ(ui::LogicalDisplayId{request.displayId}, changes->displayId);

    // When a display is removed, all windows are removed from the display
    // and our focused window loses focus
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, {});
    ASSERT_FOCUS_CHANGE(changes, /*from*/ windowToken, /*to*/ nullptr);
    focusResolver.displayRemoved(ui::LogicalDisplayId{request.displayId});

    // When a display is re-added, the window does not get focus since the request was cleared.
    changes = focusResolver.setInputWindows(ui::LogicalDisplayId{request.displayId}, windows);
    ASSERT_FALSE(changes);
}

} // namespace android::inputdispatcher
