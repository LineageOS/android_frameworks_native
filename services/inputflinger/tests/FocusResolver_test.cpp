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
    ASSERT_EQ(nullptr, changes->oldFocus);
    ASSERT_EQ(focusableWindowToken, changes->newFocus);
    ASSERT_EQ(request.displayId, changes->displayId);

    // invisible window cannot get focused
    request.token = invisibleWindowToken;
    changes = focusResolver.setFocusedWindow(request, windows);
    ASSERT_EQ(focusableWindowToken, changes->oldFocus);
    ASSERT_EQ(nullptr, changes->newFocus);

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
    ASSERT_EQ(nullptr, changes->oldFocus);
    ASSERT_EQ(focusableWindowToken, changes->newFocus);

    // mirrored window with one visible window can get focused
    request.token = invisibleWindowToken;
    changes = focusResolver.setFocusedWindow(request, windows);
    ASSERT_EQ(focusableWindowToken, changes->oldFocus);
    ASSERT_EQ(invisibleWindowToken, changes->newFocus);

    // mirrored window with one or more unfocusable window cannot get focused
    request.token = unfocusableWindowToken;
    changes = focusResolver.setFocusedWindow(request, windows);
    ASSERT_FALSE(changes);
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

    // Window visibility changes and the window loses focused
    window->setVisible(false);
    changes = focusResolver.setInputWindows(request.displayId, windows);
    ASSERT_EQ(nullptr, changes->newFocus);
    ASSERT_EQ(focusableWindowToken, changes->oldFocus);
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
    ASSERT_EQ(nullptr, changes->oldFocus);
    ASSERT_EQ(invisibleWindowToken, changes->newFocus);
}

} // namespace android::inputdispatcher
