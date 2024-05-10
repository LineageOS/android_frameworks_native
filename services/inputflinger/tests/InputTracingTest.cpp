/*
 * Copyright 2024 The Android Open Source Project
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

#include "../InputCommonConverter.h"
#include "../dispatcher/InputDispatcher.h"
#include "../dispatcher/trace/InputTracingPerfettoBackend.h"
#include "../dispatcher/trace/ThreadedBackend.h"
#include "FakeApplicationHandle.h"
#include "FakeInputDispatcherPolicy.h"
#include "FakeWindows.h"
#include "InputTraceSession.h"
#include "TestEventMatchers.h"

#include <NotifyArgsBuilders.h>
#include <android-base/logging.h>
#include <android/content/pm/IPackageManagerNative.h>
#include <gtest/gtest.h>
#include <input/Input.h>
#include <perfetto/trace/android/android_input_event.pbzero.h>
#include <perfetto/trace/trace.pbzero.h>
#include <private/android_filesystem_config.h>
#include <map>
#include <vector>

namespace android::inputdispatcher::trace {

using perfetto::protos::pbzero::AndroidInputEventConfig;

namespace {

constexpr ui::LogicalDisplayId DISPLAY_ID = ui::LogicalDisplayId::DEFAULT;

// Ensure common actions are interchangeable between keys and motions for convenience.
static_assert(static_cast<int32_t>(AMOTION_EVENT_ACTION_DOWN) ==
              static_cast<int32_t>(AKEY_EVENT_ACTION_DOWN));
static_assert(static_cast<int32_t>(AMOTION_EVENT_ACTION_UP) ==
              static_cast<int32_t>(AKEY_EVENT_ACTION_UP));
constexpr int32_t ACTION_DOWN = AMOTION_EVENT_ACTION_DOWN;
constexpr int32_t ACTION_MOVE = AMOTION_EVENT_ACTION_MOVE;
constexpr int32_t ACTION_UP = AMOTION_EVENT_ACTION_UP;
constexpr int32_t ACTION_CANCEL = AMOTION_EVENT_ACTION_CANCEL;

constexpr gui::Pid PID{1};

constexpr gui::Uid ALLOWED_UID_1{10012};
constexpr gui::Uid ALLOWED_UID_2{10013};
constexpr gui::Uid DISALLOWED_UID_1{1};
constexpr gui::Uid DISALLOWED_UID_2{99};
constexpr gui::Uid UNLISTED_UID{12345};

const std::string ALLOWED_PKG_1{"allowed.pkg.1"};
const std::string ALLOWED_PKG_2{"allowed.pkg.2"};
const std::string DISALLOWED_PKG_1{"disallowed.pkg.1"};
const std::string DISALLOWED_PKG_2{"disallowed.pkg.2"};

const std::map<std::string, gui::Uid> kPackageUidMap{
        {ALLOWED_PKG_1, ALLOWED_UID_1},
        {ALLOWED_PKG_2, ALLOWED_UID_2},
        {DISALLOWED_PKG_1, DISALLOWED_UID_1},
        {DISALLOWED_PKG_2, DISALLOWED_UID_2},
};

class FakePackageManager : public content::pm::IPackageManagerNativeDefault {
public:
    binder::Status getPackageUid(const ::std::string& pkg, int64_t flags, int32_t userId,
            int32_t* outUid) override {
        auto it = kPackageUidMap.find(pkg);
        *outUid = it != kPackageUidMap.end() ? static_cast<int32_t>(it->second.val()) : -1;
        return binder::Status::ok();
    }
};

const sp<testing::NiceMock<FakePackageManager>> kPackageManager =
        sp<testing::NiceMock<FakePackageManager>>::make();

const std::shared_ptr<FakeApplicationHandle> APP = std::make_shared<FakeApplicationHandle>();

} // namespace

// --- InputTracingTest ---

class InputTracingTest : public testing::Test {
protected:
    std::unique_ptr<FakeInputDispatcherPolicy> mFakePolicy;
    std::unique_ptr<InputDispatcher> mDispatcher;

    void SetUp() override {
        impl::PerfettoBackend::sUseInProcessBackendForTest = true;
        impl::PerfettoBackend::sPackageManagerProvider = []() { return kPackageManager; };
        mFakePolicy = std::make_unique<FakeInputDispatcherPolicy>();

        auto tracingBackend = std::make_unique<impl::ThreadedBackend<impl::PerfettoBackend>>(
                impl::PerfettoBackend());
        mRequestTracerIdle = tracingBackend->getIdleWaiterForTesting();
        mDispatcher = std::make_unique<InputDispatcher>(*mFakePolicy, std::move(tracingBackend));

        mDispatcher->setInputDispatchMode(/*enabled=*/true, /*frozen=*/false);
        ASSERT_EQ(OK, mDispatcher->start());
    }

    void TearDown() override {
        ASSERT_EQ(OK, mDispatcher->stop());
        mDispatcher.reset();
        mFakePolicy.reset();
    }

    void waitForTracerIdle() {
        mDispatcher->waitForIdle();
        mRequestTracerIdle();
    }

    void setFocusedWindow(const sp<gui::WindowInfoHandle>& window) {
        gui::FocusRequest request;
        request.token = window->getToken();
        request.windowName = window->getName();
        request.timestamp = systemTime(SYSTEM_TIME_MONOTONIC);
        request.displayId = window->getInfo()->displayId.val();
        mDispatcher->setFocusedWindow(request);
    }

    void tapAndExpect(const std::vector<const sp<FakeWindowHandle>>& windows,
                      Level inboundTraceLevel, Level dispatchTraceLevel, InputTraceSession& s) {
        const auto down = MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                                  .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(110))
                                  .build();
        mDispatcher->notifyMotion(down);
        s.expectMotionTraced(inboundTraceLevel, toMotionEvent(down));
        for (const auto& window : windows) {
            auto consumed = window->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
            s.expectDispatchTraced(dispatchTraceLevel, {*consumed, window});
        }

        const auto up = MotionArgsBuilder(ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN)
                                .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(110))
                                .build();
        mDispatcher->notifyMotion(up);
        s.expectMotionTraced(inboundTraceLevel, toMotionEvent(up));
        for (const auto& window : windows) {
            auto consumed = window->consumeMotionEvent(WithMotionAction(ACTION_UP));
            s.expectDispatchTraced(dispatchTraceLevel, {*consumed, window});
        }
    }

    void keypressAndExpect(const std::vector<const sp<FakeWindowHandle>>& windows,
                           Level inboundTraceLevel, Level dispatchTraceLevel,
                           InputTraceSession& s) {
        const auto down = KeyArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_KEYBOARD).build();
        mDispatcher->notifyKey(down);
        s.expectKeyTraced(inboundTraceLevel, toKeyEvent(down));
        for (const auto& window : windows) {
            auto consumed = window->consumeKeyEvent(WithKeyAction(ACTION_DOWN));
            s.expectDispatchTraced(dispatchTraceLevel, {*consumed, window});
        }

        const auto up = KeyArgsBuilder(ACTION_UP, AINPUT_SOURCE_KEYBOARD).build();
        mDispatcher->notifyKey(up);
        s.expectKeyTraced(inboundTraceLevel, toKeyEvent(up));
        for (const auto& window : windows) {
            auto consumed = window->consumeKeyEvent(WithKeyAction(ACTION_UP));
            s.expectDispatchTraced(dispatchTraceLevel, {*consumed, window});
        }
    }

private:
    std::function<void()> mRequestTracerIdle;
};

TEST_F(InputTracingTest, EmptyConfigTracesNothing) {
    InputTraceSession s{[](auto& config) {}};

    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});
    setFocusedWindow(window);
    window->consumeFocusEvent(true);

    tapAndExpect({window}, Level::NONE, Level::NONE, s);
    keypressAndExpect({window}, Level::NONE, Level::NONE, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, TraceAll) {
    InputTraceSession s{
            [](auto& config) { config->set_mode(AndroidInputEventConfig::TRACE_MODE_TRACE_ALL); }};

    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});
    setFocusedWindow(window);
    window->consumeFocusEvent(true);

    tapAndExpect({window}, Level::COMPLETE, Level::COMPLETE, s);
    keypressAndExpect({window}, Level::COMPLETE, Level::COMPLETE, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, NoRulesTracesNothing) {
    InputTraceSession s{[](auto& config) {
        config->set_trace_dispatcher_input_events(true);
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
    }};

    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});
    setFocusedWindow(window);
    window->consumeFocusEvent(true);

    tapAndExpect({window}, Level::NONE, Level::NONE, s);
    keypressAndExpect({window}, Level::NONE, Level::NONE, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, EmptyRuleMatchesEverything) {
    InputTraceSession s{[](auto& config) {
        config->set_trace_dispatcher_input_events(true);
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Match everything as COMPLETE
        auto rule = config->add_rules();
        rule->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_COMPLETE);
    }};

    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});
    setFocusedWindow(window);
    window->consumeFocusEvent(true);

    tapAndExpect({window}, Level::COMPLETE, Level::COMPLETE, s);
    keypressAndExpect({window}, Level::COMPLETE, Level::COMPLETE, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, UnspecifiedTracelLevel) {
    InputTraceSession s{[](auto& config) {
        config->set_trace_dispatcher_input_events(true);
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Match everything, trace level unspecified
        auto rule = config->add_rules();
    }};

    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});
    setFocusedWindow(window);
    window->consumeFocusEvent(true);

    // Event is not traced by default if trace level is unspecified
    tapAndExpect({window}, Level::NONE, Level::NONE, s);
    keypressAndExpect({window}, Level::NONE, Level::NONE, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, MatchSecureWindow) {
    InputTraceSession s{[](auto& config) {
        config->set_trace_dispatcher_input_events(true);
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Match secure windows as COMPLETE
        auto rule = config->add_rules();
        rule->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_COMPLETE);
        rule->set_match_secure(true);
    }};

    // Add a normal window and a spy window.
    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    auto spy = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    spy->setSpy(true);
    spy->setTrustedOverlay(true);
    mDispatcher->onWindowInfosChanged({{*spy->getInfo(), *window->getInfo()}, {}, 0, 0});

    // Since neither are secure windows, events should not be traced.
    tapAndExpect({spy, window}, Level::NONE, Level::NONE, s);

    // Events should be matched as secure if any of the target windows is marked as secure.
    spy->setSecure(true);
    mDispatcher->onWindowInfosChanged({{*spy->getInfo(), *window->getInfo()}, {}, 0, 0});
    tapAndExpect({spy, window}, Level::COMPLETE, Level::COMPLETE, s);

    spy->setSecure(false);
    window->setSecure(true);
    mDispatcher->onWindowInfosChanged({{*spy->getInfo(), *window->getInfo()}, {}, 0, 0});
    tapAndExpect({spy, window}, Level::COMPLETE, Level::COMPLETE, s);

    spy->setSecure(true);
    window->setSecure(true);
    mDispatcher->onWindowInfosChanged({{*spy->getInfo(), *window->getInfo()}, {}, 0, 0});
    tapAndExpect({spy, window}, Level::COMPLETE, Level::COMPLETE, s);

    spy->setSecure(false);
    window->setSecure(false);
    mDispatcher->onWindowInfosChanged({{*spy->getInfo(), *window->getInfo()}, {}, 0, 0});
    tapAndExpect({spy, window}, Level::NONE, Level::NONE, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, MatchImeConnectionActive) {
    InputTraceSession s{[](auto& config) {
        config->set_trace_dispatcher_input_events(true);
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Match IME Connection Active as COMPLETE
        auto rule = config->add_rules();
        rule->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_COMPLETE);
        rule->set_match_ime_connection_active(true);
    }};

    // Add a normal window and a spy window.
    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    auto spy = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    spy->setSpy(true);
    spy->setTrustedOverlay(true);
    mDispatcher->onWindowInfosChanged({{*spy->getInfo(), *window->getInfo()}, {}, 0, 0});

    // Since IME connection is not active, events should not be traced.
    tapAndExpect({spy, window}, Level::NONE, Level::NONE, s);

    mDispatcher->setInputMethodConnectionIsActive(true);
    tapAndExpect({spy, window}, Level::COMPLETE, Level::COMPLETE, s);

    mDispatcher->setInputMethodConnectionIsActive(false);
    tapAndExpect({spy, window}, Level::NONE, Level::NONE, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, MatchAllPackages) {
    InputTraceSession s{[](auto& config) {
        config->set_trace_dispatcher_input_events(true);
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Match all package as COMPLETE
        auto rule = config->add_rules();
        rule->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_COMPLETE);
        rule->add_match_all_packages(ALLOWED_PKG_1);
        rule->add_match_all_packages(ALLOWED_PKG_2);
    }};

    // All windows are allowlisted.
    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    window->setOwnerInfo(PID, ALLOWED_UID_1);
    auto spy = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    spy->setOwnerInfo(PID, ALLOWED_UID_2);
    spy->setSpy(true);
    spy->setTrustedOverlay(true);
    auto systemSpy = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    systemSpy->setOwnerInfo(PID, gui::Uid{AID_SYSTEM});
    systemSpy->setSpy(true);
    systemSpy->setTrustedOverlay(true);
    mDispatcher->onWindowInfosChanged(
            {{*systemSpy->getInfo(), *spy->getInfo(), *window->getInfo()}, {}, 0, 0});

    tapAndExpect({systemSpy, spy, window}, Level::COMPLETE, Level::COMPLETE, s);

    // Add a disallowed spy. This will result in the event not being traced for all windows.
    auto disallowedSpy = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    disallowedSpy->setOwnerInfo(PID, DISALLOWED_UID_1);
    disallowedSpy->setSpy(true);
    disallowedSpy->setTrustedOverlay(true);
    mDispatcher->onWindowInfosChanged({{*systemSpy->getInfo(), *spy->getInfo(),
                                        *disallowedSpy->getInfo(), *window->getInfo()},
                                       {},
                                       0,
                                       0});

    tapAndExpect({systemSpy, spy, disallowedSpy, window}, Level::NONE, Level::NONE, s);

    // Change the owner of the disallowed spy to one for which we don't have a package mapping.
    disallowedSpy->setOwnerInfo(PID, UNLISTED_UID);
    mDispatcher->onWindowInfosChanged({{*systemSpy->getInfo(), *spy->getInfo(),
                                        *disallowedSpy->getInfo(), *window->getInfo()},
                                       {},
                                       0,
                                       0});

    tapAndExpect({systemSpy, spy, disallowedSpy, window}, Level::NONE, Level::NONE, s);

    // Remove the disallowed spy. Events are traced again.
    mDispatcher->onWindowInfosChanged(
            {{*systemSpy->getInfo(), *spy->getInfo(), *window->getInfo()}, {}, 0, 0});

    tapAndExpect({systemSpy, spy, window}, Level::COMPLETE, Level::COMPLETE, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, MatchAnyPackages) {
    InputTraceSession s{[](auto& config) {
        config->set_trace_dispatcher_input_events(true);
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Match any package as COMPLETE
        auto rule = config->add_rules();
        rule->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_COMPLETE);
        rule->add_match_any_packages(ALLOWED_PKG_1);
        rule->add_match_any_packages(ALLOWED_PKG_2);
    }};

    // Just a disallowed window. Events are not traced.
    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    window->setOwnerInfo(PID, DISALLOWED_UID_1);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});

    tapAndExpect({window}, Level::NONE, Level::NONE, s);

    // Add a spy for which we don't have a package mapping. Events are still not traced.
    auto disallowedSpy = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    disallowedSpy->setOwnerInfo(PID, UNLISTED_UID);
    disallowedSpy->setSpy(true);
    disallowedSpy->setTrustedOverlay(true);
    mDispatcher->onWindowInfosChanged({{*disallowedSpy->getInfo(), *window->getInfo()}, {}, 0, 0});

    tapAndExpect({disallowedSpy, window}, Level::NONE, Level::NONE, s);

    // Add an allowed spy. Events are now traced for all packages.
    auto spy = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    spy->setOwnerInfo(PID, ALLOWED_UID_1);
    spy->setSpy(true);
    spy->setTrustedOverlay(true);
    mDispatcher->onWindowInfosChanged(
            {{*disallowedSpy->getInfo(), *spy->getInfo(), *window->getInfo()}, {}, 0, 0});

    tapAndExpect({disallowedSpy, spy, window}, Level::COMPLETE, Level::COMPLETE, s);

    // Add another disallowed spy. Events are still traced.
    auto disallowedSpy2 = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    disallowedSpy2->setOwnerInfo(PID, DISALLOWED_UID_2);
    disallowedSpy2->setSpy(true);
    disallowedSpy2->setTrustedOverlay(true);
    mDispatcher->onWindowInfosChanged({{*disallowedSpy->getInfo(), *disallowedSpy2->getInfo(),
                                        *spy->getInfo(), *window->getInfo()},
                                       {},
                                       0,
                                       0});

    tapAndExpect({disallowedSpy, disallowedSpy2, spy, window}, Level::COMPLETE, Level::COMPLETE, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, MultipleMatchersInOneRule) {
    InputTraceSession s{[](auto& config) {
        config->set_trace_dispatcher_input_events(true);
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Match all of the following conditions as COMPLETE
        auto rule = config->add_rules();
        rule->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_COMPLETE);
        rule->add_match_all_packages(ALLOWED_PKG_1);
        rule->add_match_all_packages(ALLOWED_PKG_2);
        rule->add_match_any_packages(ALLOWED_PKG_1);
        rule->add_match_any_packages(DISALLOWED_PKG_1);
        rule->set_match_secure(false);
        rule->set_match_ime_connection_active(false);
    }};

    // A single window into an allowed UID. Matches all matchers.
    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    window->setOwnerInfo(PID, ALLOWED_UID_1);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});

    tapAndExpect({window}, Level::COMPLETE, Level::COMPLETE, s);

    // Secure window does not match.
    window->setSecure(true);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});

    tapAndExpect({window}, Level::NONE, Level::NONE, s);

    // IME Connection Active does not match.
    window->setSecure(false);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});
    mDispatcher->setInputMethodConnectionIsActive(true);

    tapAndExpect({window}, Level::NONE, Level::NONE, s);

    // Event going to DISALLOWED_PKG_1 does not match because it's not listed in match_all_packages.
    mDispatcher->setInputMethodConnectionIsActive(false);
    auto disallowedSpy = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    disallowedSpy->setOwnerInfo(PID, DISALLOWED_UID_1);
    disallowedSpy->setSpy(true);
    disallowedSpy->setTrustedOverlay(true);
    mDispatcher->onWindowInfosChanged({{*disallowedSpy->getInfo(), *window->getInfo()}, {}, 0, 0});

    tapAndExpect({disallowedSpy, window}, Level::NONE, Level::NONE, s);

    // Event going to ALLOWED_PKG_1 does not match because it's not listed in match_any_packages.
    window->setOwnerInfo(PID, ALLOWED_UID_2);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});

    tapAndExpect({window}, Level::NONE, Level::NONE, s);

    // All conditions match.
    auto spy = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    spy->setOwnerInfo(PID, ALLOWED_UID_1);
    spy->setSpy(true);
    spy->setTrustedOverlay(true);
    mDispatcher->onWindowInfosChanged({{*spy->getInfo(), *window->getInfo()}, {}, 0, 0});

    tapAndExpect({spy, window}, Level::COMPLETE, Level::COMPLETE, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, MultipleRulesMatchInOrder) {
    InputTraceSession s{[](auto& config) {
        config->set_trace_dispatcher_input_events(true);
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Don't trace secure events
        auto rule1 = config->add_rules();
        rule1->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_NONE);
        rule1->set_match_secure(true);
        // Rule: Trace matched packages as COMPLETE when IME inactive
        auto rule2 = config->add_rules();
        rule2->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_COMPLETE);
        rule2->add_match_all_packages(ALLOWED_PKG_1);
        rule2->add_match_all_packages(ALLOWED_PKG_2);
        rule2->set_match_ime_connection_active(false);
        // Rule: Trace the rest of the events as REDACTED
        auto rule3 = config->add_rules();
        rule3->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_REDACTED);
    }};

    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    window->setOwnerInfo(PID, ALLOWED_UID_1);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});

    tapAndExpect({window}, Level::COMPLETE, Level::COMPLETE, s);

    // Verify that the first rule that matches in the order that they are specified is the
    // one that applies to the event.
    mDispatcher->setInputMethodConnectionIsActive(true);
    tapAndExpect({window}, Level::REDACTED, Level::REDACTED, s);

    mDispatcher->setInputMethodConnectionIsActive(false);
    auto spy = sp<FakeWindowHandle>::make(APP, mDispatcher, "Spy", DISPLAY_ID);
    spy->setOwnerInfo(PID, ALLOWED_UID_2);
    spy->setSpy(true);
    spy->setTrustedOverlay(true);
    spy->setSecure(true);
    mDispatcher->onWindowInfosChanged({{*spy->getInfo(), *window->getInfo()}, {}, 0, 0});

    tapAndExpect({spy, window}, Level::NONE, Level::NONE, s);

    spy->setSecure(false);
    mDispatcher->onWindowInfosChanged({{*spy->getInfo(), *window->getInfo()}, {}, 0, 0});

    tapAndExpect({spy, window}, Level::COMPLETE, Level::COMPLETE, s);

    spy->setOwnerInfo(PID, DISALLOWED_UID_1);
    mDispatcher->onWindowInfosChanged({{*spy->getInfo(), *window->getInfo()}, {}, 0, 0});

    tapAndExpect({spy, window}, Level::REDACTED, Level::REDACTED, s);

    waitForTracerIdle();
}

TEST_F(InputTracingTest, TraceInboundEvents) {
    InputTraceSession s{[](auto& config) {
        // Only trace inbounds events - don't trace window dispatch
        config->set_trace_dispatcher_input_events(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Trace everything as REDACTED
        auto rule1 = config->add_rules();
        rule1->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_REDACTED);
    }};

    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    window->setOwnerInfo(PID, ALLOWED_UID_1);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});

    // Only the inbound events are traced. No dispatch events are traced.
    tapAndExpect({window}, Level::REDACTED, Level::NONE, s);

    // Notify a down event, which should be traced.
    const auto down = MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                              .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(110))
                              .build();
    s.expectMotionTraced(Level::REDACTED, toMotionEvent(down));
    mDispatcher->notifyMotion(down);
    auto consumed = window->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
    s.expectDispatchTraced(Level::NONE, {*consumed, window});

    // Force a cancel event to be synthesized. This should not be traced, because only inbound
    // events are requested.
    mDispatcher->cancelCurrentTouch();
    consumed = window->consumeMotionEvent(WithMotionAction(ACTION_CANCEL));
    s.expectMotionTraced(Level::NONE, *consumed);
    s.expectDispatchTraced(Level::NONE, {*consumed, window});

    waitForTracerIdle();
}

TEST_F(InputTracingTest, TraceWindowDispatch) {
    InputTraceSession s{[](auto& config) {
        // Only trace window dispatch - don't trace event details
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Trace everything as REDACTED
        auto rule1 = config->add_rules();
        rule1->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_REDACTED);
    }};

    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    window->setOwnerInfo(PID, ALLOWED_UID_1);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});

    // Only dispatch events are traced. No inbound events are traced.
    tapAndExpect({window}, Level::NONE, Level::REDACTED, s);

    // Notify a down event; the dispatch should be traced.
    const auto down = MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                              .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(110))
                              .build();
    s.expectMotionTraced(Level::NONE, toMotionEvent(down));
    mDispatcher->notifyMotion(down);
    auto consumed = window->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
    s.expectDispatchTraced(Level::REDACTED, {*consumed, window});

    // Force a cancel event to be synthesized. All events that are dispatched should be traced.
    mDispatcher->cancelCurrentTouch();
    consumed = window->consumeMotionEvent(WithMotionAction(ACTION_CANCEL));
    s.expectMotionTraced(Level::NONE, *consumed);
    s.expectDispatchTraced(Level::REDACTED, {*consumed, window});

    waitForTracerIdle();
}

// TODO(b/336097719): Investigate flakiness and re-enable this test.
TEST_F(InputTracingTest, DISABLED_SimultaneousTracingSessions) {
    auto s1 = std::make_unique<InputTraceSession>(
            [](auto& config) { config->set_mode(AndroidInputEventConfig::TRACE_MODE_TRACE_ALL); });

    auto window = sp<FakeWindowHandle>::make(APP, mDispatcher, "Window", DISPLAY_ID);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});
    setFocusedWindow(window);
    window->consumeFocusEvent(true);

    tapAndExpect({window}, Level::COMPLETE, Level::COMPLETE, *s1);
    keypressAndExpect({window}, Level::COMPLETE, Level::COMPLETE, *s1);

    auto s2 = std::make_unique<InputTraceSession>([](auto& config) {
        config->set_trace_dispatcher_input_events(true);
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Trace all events as REDACTED when IME inactive
        auto rule = config->add_rules();
        rule->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_REDACTED);
        rule->set_match_ime_connection_active(false);
    });

    auto s3 = std::make_unique<InputTraceSession>([](auto& config) {
        // Only trace window dispatch
        config->set_trace_dispatcher_window_dispatch(true);
        config->set_mode(AndroidInputEventConfig::TRACE_MODE_USE_RULES);
        // Rule: Trace non-secure events as COMPLETE
        auto rule = config->add_rules();
        rule->set_trace_level(AndroidInputEventConfig::TRACE_LEVEL_COMPLETE);
        rule->set_match_secure(false);
    });

    // Down event should be recorded on all traces.
    const auto down = MotionArgsBuilder(ACTION_DOWN, AINPUT_SOURCE_TOUCHSCREEN)
                              .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(110))
                              .build();
    mDispatcher->notifyMotion(down);
    s1->expectMotionTraced(Level::COMPLETE, toMotionEvent(down));
    s2->expectMotionTraced(Level::REDACTED, toMotionEvent(down));
    s3->expectMotionTraced(Level::NONE, toMotionEvent(down));
    auto consumed = window->consumeMotionEvent(WithMotionAction(ACTION_DOWN));
    s1->expectDispatchTraced(Level::COMPLETE, {*consumed, window});
    s2->expectDispatchTraced(Level::REDACTED, {*consumed, window});
    s3->expectDispatchTraced(Level::COMPLETE, {*consumed, window});

    // Move event when IME is active.
    mDispatcher->setInputMethodConnectionIsActive(true);
    const auto move1 = MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                               .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(110))
                               .build();
    mDispatcher->notifyMotion(move1);
    s1->expectMotionTraced(Level::COMPLETE, toMotionEvent(move1));
    s2->expectMotionTraced(Level::NONE, toMotionEvent(move1));
    s3->expectMotionTraced(Level::NONE, toMotionEvent(move1));
    consumed = window->consumeMotionEvent(WithMotionAction(ACTION_MOVE));
    s1->expectDispatchTraced(Level::COMPLETE, {*consumed, window});
    s2->expectDispatchTraced(Level::NONE, {*consumed, window});
    s3->expectDispatchTraced(Level::COMPLETE, {*consumed, window});

    // Move event after window became secure.
    mDispatcher->setInputMethodConnectionIsActive(false);
    window->setSecure(true);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});
    const auto move2 = MotionArgsBuilder(ACTION_MOVE, AINPUT_SOURCE_TOUCHSCREEN)
                               .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(110))
                               .build();
    mDispatcher->notifyMotion(move2);
    s1->expectMotionTraced(Level::COMPLETE, toMotionEvent(move2));
    s2->expectMotionTraced(Level::REDACTED, toMotionEvent(move2));
    s3->expectMotionTraced(Level::NONE, toMotionEvent(move2));
    consumed = window->consumeMotionEvent(WithMotionAction(ACTION_MOVE));
    s1->expectDispatchTraced(Level::COMPLETE, {*consumed, window});
    s2->expectDispatchTraced(Level::REDACTED, {*consumed, window});
    s3->expectDispatchTraced(Level::NONE, {*consumed, window});

    waitForTracerIdle();
    s2.reset();

    // Up event.
    window->setSecure(false);
    mDispatcher->onWindowInfosChanged({{*window->getInfo()}, {}, 0, 0});
    const auto up = MotionArgsBuilder(ACTION_UP, AINPUT_SOURCE_TOUCHSCREEN)
                            .pointer(PointerBuilder(0, ToolType::FINGER).x(100).y(110))
                            .build();
    mDispatcher->notifyMotion(up);
    s1->expectMotionTraced(Level::COMPLETE, toMotionEvent(up));
    s3->expectMotionTraced(Level::NONE, toMotionEvent(up));
    consumed = window->consumeMotionEvent(WithMotionAction(ACTION_UP));
    s1->expectDispatchTraced(Level::COMPLETE, {*consumed, window});
    s3->expectDispatchTraced(Level::COMPLETE, {*consumed, window});

    waitForTracerIdle();
    s3.reset();

    tapAndExpect({window}, Level::COMPLETE, Level::COMPLETE, *s1);
    keypressAndExpect({window}, Level::COMPLETE, Level::COMPLETE, *s1);

    waitForTracerIdle();
    s1.reset();
}

} // namespace android::inputdispatcher::trace
