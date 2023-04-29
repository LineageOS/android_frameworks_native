/*
 * Copyright 2023 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "LibSurfaceFlingerUnittests"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "Scheduler/VSyncDispatch.h"
#include "mock/MockVSyncDispatch.h"

using namespace testing;

namespace android::scheduler {

class VSyncCallbackRegistrationTest : public Test {
protected:
    VSyncDispatch::Callback mCallback = [](nsecs_t, nsecs_t, nsecs_t) {};

    std::shared_ptr<mock::VSyncDispatch> mVsyncDispatch = std::make_shared<mock::VSyncDispatch>();
    VSyncDispatch::CallbackToken mCallbackToken{7};
    std::string mCallbackName = "callback";

    std::shared_ptr<mock::VSyncDispatch> mVsyncDispatch2 = std::make_shared<mock::VSyncDispatch>();
    VSyncDispatch::CallbackToken mCallbackToken2{42};
    std::string mCallbackName2 = "callback2";

    void assertDispatch(const VSyncCallbackRegistration& registration,
                        std::shared_ptr<VSyncDispatch> dispatch) {
        ASSERT_EQ(registration.mDispatch, dispatch);
    }

    void assertToken(const VSyncCallbackRegistration& registration,
                     const std::optional<VSyncDispatch::CallbackToken>& token) {
        ASSERT_EQ(registration.mToken, token);
    }
};

TEST_F(VSyncCallbackRegistrationTest, unregistersCallbackOnDestruction) {
    // TODO (b/279581095): With ftl::Function, `_` can be replaced with
    // `mCallback`, here and in other calls to `registerCallback, since the
    // ftl version has an operator==, unlike std::function.
    EXPECT_CALL(*mVsyncDispatch, registerCallback(_, mCallbackName))
            .WillOnce(Return(mCallbackToken));
    EXPECT_CALL(*mVsyncDispatch, unregisterCallback(mCallbackToken)).Times(1);

    VSyncCallbackRegistration registration(mVsyncDispatch, mCallback, mCallbackName);
    ASSERT_NO_FATAL_FAILURE(assertDispatch(registration, mVsyncDispatch));
    ASSERT_NO_FATAL_FAILURE(assertToken(registration, mCallbackToken));
}

TEST_F(VSyncCallbackRegistrationTest, unregistersCallbackOnPointerMove) {
    {
        InSequence seq;
        EXPECT_CALL(*mVsyncDispatch, registerCallback(_, mCallbackName))
                .WillOnce(Return(mCallbackToken));
        EXPECT_CALL(*mVsyncDispatch2, registerCallback(_, mCallbackName2))
                .WillOnce(Return(mCallbackToken2));
        EXPECT_CALL(*mVsyncDispatch2, unregisterCallback(mCallbackToken2)).Times(1);
        EXPECT_CALL(*mVsyncDispatch, unregisterCallback(mCallbackToken)).Times(1);
    }

    auto registration =
            std::make_unique<VSyncCallbackRegistration>(mVsyncDispatch, mCallback, mCallbackName);

    auto registration2 =
            std::make_unique<VSyncCallbackRegistration>(mVsyncDispatch2, mCallback, mCallbackName2);

    registration2 = std::move(registration);

    ASSERT_NO_FATAL_FAILURE(assertDispatch(*registration2.get(), mVsyncDispatch));
    ASSERT_NO_FATAL_FAILURE(assertToken(*registration2.get(), mCallbackToken));
}

TEST_F(VSyncCallbackRegistrationTest, unregistersCallbackOnMoveOperator) {
    {
        InSequence seq;
        EXPECT_CALL(*mVsyncDispatch, registerCallback(_, mCallbackName))
                .WillOnce(Return(mCallbackToken));
        EXPECT_CALL(*mVsyncDispatch2, registerCallback(_, mCallbackName2))
                .WillOnce(Return(mCallbackToken2));
        EXPECT_CALL(*mVsyncDispatch2, unregisterCallback(mCallbackToken2)).Times(1);
        EXPECT_CALL(*mVsyncDispatch, unregisterCallback(mCallbackToken)).Times(1);
    }

    VSyncCallbackRegistration registration(mVsyncDispatch, mCallback, mCallbackName);

    VSyncCallbackRegistration registration2(mVsyncDispatch2, mCallback, mCallbackName2);

    registration2 = std::move(registration);

    ASSERT_NO_FATAL_FAILURE(assertDispatch(registration, nullptr));
    ASSERT_NO_FATAL_FAILURE(assertToken(registration, std::nullopt));

    ASSERT_NO_FATAL_FAILURE(assertDispatch(registration2, mVsyncDispatch));
    ASSERT_NO_FATAL_FAILURE(assertToken(registration2, mCallbackToken));
}

TEST_F(VSyncCallbackRegistrationTest, moveConstructor) {
    EXPECT_CALL(*mVsyncDispatch, registerCallback(_, mCallbackName))
            .WillOnce(Return(mCallbackToken));
    EXPECT_CALL(*mVsyncDispatch, unregisterCallback(mCallbackToken)).Times(1);

    VSyncCallbackRegistration registration(mVsyncDispatch, mCallback, mCallbackName);
    VSyncCallbackRegistration registration2(std::move(registration));

    ASSERT_NO_FATAL_FAILURE(assertDispatch(registration, nullptr));
    ASSERT_NO_FATAL_FAILURE(assertToken(registration, std::nullopt));

    ASSERT_NO_FATAL_FAILURE(assertDispatch(registration2, mVsyncDispatch));
    ASSERT_NO_FATAL_FAILURE(assertToken(registration2, mCallbackToken));
}

TEST_F(VSyncCallbackRegistrationTest, moveOperatorEqualsSelf) {
    EXPECT_CALL(*mVsyncDispatch, registerCallback(_, mCallbackName))
            .WillOnce(Return(mCallbackToken));
    EXPECT_CALL(*mVsyncDispatch, unregisterCallback(mCallbackToken)).Times(1);

    VSyncCallbackRegistration registration(mVsyncDispatch, mCallback, mCallbackName);

    // Use a reference so the compiler doesn't realize that registration is
    // being moved to itself.
    VSyncCallbackRegistration& registrationRef = registration;
    registration = std::move(registrationRef);

    ASSERT_NO_FATAL_FAILURE(assertDispatch(registration, mVsyncDispatch));
    ASSERT_NO_FATAL_FAILURE(assertToken(registration, mCallbackToken));
}

} // namespace android::scheduler
