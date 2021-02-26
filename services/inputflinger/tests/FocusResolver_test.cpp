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

namespace android::inputdispatcher {

class FakeWindowHandle : public InputWindowHandle {
public:
    FakeWindowHandle(const std::string& name, const sp<IBinder>& token, bool focusable,
                     bool visible) {
        mInfo.token = token;
        mInfo.name = name;
        mInfo.visible = visible;
        mInfo.focusable = focusable;
    }

    bool updateInfo() { return true; }
    void setFocusable(bool focusable) { mInfo.focusable = focusable; }
    void setVisible(bool visible) { mInfo.visible = visible; }
};

TEST(FocusResolverTest, SetFocusedWindow) {
    sp<IBinder> focusableWindowToken = new BBinder();
    sp<IBinder> invisibleWindowToken = new BBinder();
    sp<IBinder> unfocusableWindowToken = new BBinder();
    std::vector<sp<InputWindowHandle>> windows;
    windows.push_back(new FakeWindowHandle("Focusable", focusableWindowToken, true /* focusable */,
                                           true /* visible */));
    windows.push_back(new FakeWindowHandle("Invisible", invisibleWindowToken, true /* focusable */,
                                           false /* visible */));
    windows.push_back(new FakeWindowHandle("unfocusable", unfocusableWindowToken,
                                           false /* focusable */, true /* visible */));

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

TEST(FocusResolverTest, SetFocusedMirroredWindow) {
    sp<IBinder> focusableWindowToken = new BBinder();
    sp<IBinder> invisibleWindowToken = new BBinder();
    sp<IBinder> unfocusableWindowToken = new BBinder();
    std::vector<sp<InputWindowHandle>> windows;
    windows.push_back(new FakeWindowHandle("Mirror1", focusableWindowToken, true /* focusable */,
                                           true /* visible */));
    windows.push_back(new FakeWindowHandle("Mirror1", focusableWindowToken, true /* focusable */,
                                           true /* visible */));

    windows.push_back(new FakeWindowHandle("Mirror2Visible", invisibleWindowToken,
                                           true /* focusable */, true /* visible */));
    windows.push_back(new FakeWindowHandle("Mirror2Invisible", invisibleWindowToken,
                                           true /* focusable */, false /* visible */));

    windows.push_back(new FakeWindowHandle("Mirror3Focusable", unfocusableWindowToken,
                                           true /* focusable */, true /* visible */));
    windows.push_back(new FakeWindowHandle("Mirror3Unfocusable", unfocusableWindowToken,
                                           false /* focusable */, true /* visible */));

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
    sp<IBinder> focusableWindowToken = new BBinder();
    std::vector<sp<InputWindowHandle>> windows;
    sp<FakeWindowHandle> window = new FakeWindowHandle("Focusable", focusableWindowToken,
                                                       true /* focusable */, true /* visible */);
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
    sp<IBinder> invisibleWindowToken = new BBinder();
    std::vector<sp<InputWindowHandle>> windows;

    sp<FakeWindowHandle> invisibleWindow =
            new FakeWindowHandle("Invisible", invisibleWindowToken, true /* focusable */,
                                 false /* visible */);
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
    sp<IBinder> windowToken = new BBinder();
    std::vector<sp<InputWindowHandle>> windows;

    sp<FakeWindowHandle> window = new FakeWindowHandle("Test Window", windowToken,
                                                       false /* focusable */, true /* visible */);
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
    sp<IBinder> hostWindowToken = new BBinder();
    std::vector<sp<InputWindowHandle>> windows;

    sp<FakeWindowHandle> hostWindow =
            new FakeWindowHandle("Host Window", hostWindowToken, true /* focusable */,
                                 true /* visible */);
    windows.push_back(hostWindow);
    sp<IBinder> embeddedWindowToken = new BBinder();
    sp<FakeWindowHandle> embeddedWindow =
            new FakeWindowHandle("Embedded Window", embeddedWindowToken, true /* focusable */,
                                 true /* visible */);
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

} // namespace android::inputdispatcher
