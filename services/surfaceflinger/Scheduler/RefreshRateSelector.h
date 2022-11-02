/*
 * Copyright 2019 The Android Open Source Project
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

#include <algorithm>
#include <numeric>
#include <type_traits>
#include <utility>
#include <variant>

#include <ftl/concat.h>
#include <ftl/optional.h>
#include <gui/DisplayEventReceiver.h>

#include <scheduler/Fps.h>
#include <scheduler/Seamlessness.h>

#include "DisplayHardware/DisplayMode.h"
#include "DisplayHardware/HWComposer.h"
#include "Scheduler/OneShotTimer.h"
#include "Scheduler/StrongTyping.h"
#include "ThreadContext.h"
#include "Utils/Dumper.h"

namespace android::scheduler {

using namespace std::chrono_literals;

enum class DisplayModeEvent : unsigned { None = 0b0, Changed = 0b1 };

inline DisplayModeEvent operator|(DisplayModeEvent lhs, DisplayModeEvent rhs) {
    using T = std::underlying_type_t<DisplayModeEvent>;
    return static_cast<DisplayModeEvent>(static_cast<T>(lhs) | static_cast<T>(rhs));
}

using FrameRateOverride = DisplayEventReceiver::Event::FrameRateOverride;

// Selects the refresh rate of a display by ranking its `DisplayModes` in accordance with
// the DisplayManager (or override) `Policy`, the `LayerRequirement` of each active layer,
// and `GlobalSignals`.
class RefreshRateSelector {
public:
    // Margin used when matching refresh rates to the content desired ones.
    static constexpr nsecs_t MARGIN_FOR_PERIOD_CALCULATION =
            std::chrono::nanoseconds(800us).count();

    class Policy {
        static constexpr int kAllowGroupSwitchingDefault = false;

    public:
        // The default mode, used to ensure we only initiate display mode switches within the
        // same mode group as defaultMode's group.
        DisplayModeId defaultMode;
        // Whether or not we switch mode groups to get the best frame rate.
        bool allowGroupSwitching = kAllowGroupSwitchingDefault;
        // The primary refresh rate range represents display manager's general guidance on the
        // display modes we'll consider when switching refresh rates. Unless we get an explicit
        // signal from an app, we should stay within this range.
        FpsRange primaryRange;
        // The app request refresh rate range allows us to consider more display modes when
        // switching refresh rates. Although we should generally stay within the primary range,
        // specific considerations, such as layer frame rate settings specified via the
        // setFrameRate() api, may cause us to go outside the primary range. We never go outside the
        // app request range. The app request range will be greater than or equal to the primary
        // refresh rate range, never smaller.
        FpsRange appRequestRange;

        Policy() = default;

        Policy(DisplayModeId defaultMode, FpsRange range)
              : Policy(defaultMode, kAllowGroupSwitchingDefault, range, range) {}

        Policy(DisplayModeId defaultMode, bool allowGroupSwitching, FpsRange range)
              : Policy(defaultMode, allowGroupSwitching, range, range) {}

        Policy(DisplayModeId defaultMode, FpsRange primaryRange, FpsRange appRequestRange)
              : Policy(defaultMode, kAllowGroupSwitchingDefault, primaryRange, appRequestRange) {}

        Policy(DisplayModeId defaultMode, bool allowGroupSwitching, FpsRange primaryRange,
               FpsRange appRequestRange)
              : defaultMode(defaultMode),
                allowGroupSwitching(allowGroupSwitching),
                primaryRange(primaryRange),
                appRequestRange(appRequestRange) {}

        bool operator==(const Policy& other) const {
            using namespace fps_approx_ops;
            return defaultMode == other.defaultMode && primaryRange == other.primaryRange &&
                    appRequestRange == other.appRequestRange &&
                    allowGroupSwitching == other.allowGroupSwitching;
        }

        bool operator!=(const Policy& other) const { return !(*this == other); }
        std::string toString() const;
    };

    enum class SetPolicyResult { Invalid, Unchanged, Changed };

    // We maintain the display manager policy and the override policy separately. The override
    // policy is used by CTS tests to get a consistent device state for testing. While the override
    // policy is set, it takes precedence over the display manager policy. Once the override policy
    // is cleared, we revert to using the display manager policy.
    struct DisplayManagerPolicy : Policy {
        using Policy::Policy;
    };

    struct OverridePolicy : Policy {
        using Policy::Policy;
    };

    struct NoOverridePolicy {};

    using PolicyVariant = std::variant<DisplayManagerPolicy, OverridePolicy, NoOverridePolicy>;

    SetPolicyResult setPolicy(const PolicyVariant&) EXCLUDES(mLock) REQUIRES(kMainThreadContext);

    void onModeChangeInitiated() REQUIRES(kMainThreadContext) { mNumModeSwitchesInPolicy++; }

    // Gets the current policy, which will be the override policy if active, and the display manager
    // policy otherwise.
    Policy getCurrentPolicy() const EXCLUDES(mLock);
    // Gets the display manager policy, regardless of whether an override policy is active.
    Policy getDisplayManagerPolicy() const EXCLUDES(mLock);

    // Returns true if mode is allowed by the current policy.
    bool isModeAllowed(DisplayModeId) const EXCLUDES(mLock);

    // Describes the different options the layer voted for refresh rate
    enum class LayerVoteType {
        NoVote,          // Doesn't care about the refresh rate
        Min,             // Minimal refresh rate available
        Max,             // Maximal refresh rate available
        Heuristic,       // Specific refresh rate that was calculated by platform using a heuristic
        ExplicitDefault, // Specific refresh rate that was provided by the app with Default
                         // compatibility
        ExplicitExactOrMultiple, // Specific refresh rate that was provided by the app with
                                 // ExactOrMultiple compatibility
        ExplicitExact,           // Specific refresh rate that was provided by the app with
                                 // Exact compatibility

        ftl_last = ExplicitExact
    };

    // Captures the layer requirements for a refresh rate. This will be used to determine the
    // display refresh rate.
    struct LayerRequirement {
        // Layer's name. Used for debugging purposes.
        std::string name;
        // Layer's owner uid
        uid_t ownerUid = static_cast<uid_t>(-1);
        // Layer vote type.
        LayerVoteType vote = LayerVoteType::NoVote;
        // Layer's desired refresh rate, if applicable.
        Fps desiredRefreshRate;
        // If a seamless mode switch is required.
        Seamlessness seamlessness = Seamlessness::Default;
        // Layer's weight in the range of [0, 1]. The higher the weight the more impact this layer
        // would have on choosing the refresh rate.
        float weight = 0.0f;
        // Whether layer is in focus or not based on WindowManager's state
        bool focused = false;

        bool operator==(const LayerRequirement& other) const {
            return name == other.name && vote == other.vote &&
                    isApproxEqual(desiredRefreshRate, other.desiredRefreshRate) &&
                    seamlessness == other.seamlessness && weight == other.weight &&
                    focused == other.focused;
        }

        bool operator!=(const LayerRequirement& other) const { return !(*this == other); }
    };

    // Global state describing signals that affect refresh rate choice.
    struct GlobalSignals {
        // Whether the user touched the screen recently. Used to apply touch boost.
        bool touch = false;
        // True if the system hasn't seen any buffers posted to layers recently.
        bool idle = false;
        // Whether the display is about to be powered on, or has been in PowerMode::ON
        // within the timeout of DisplayPowerTimer.
        bool powerOnImminent = false;

        bool operator==(GlobalSignals other) const {
            return touch == other.touch && idle == other.idle &&
                    powerOnImminent == other.powerOnImminent;
        }

        auto toString() const {
            return ftl::Concat("{touch=", touch, ", idle=", idle,
                               ", powerOnImminent=", powerOnImminent, '}');
        }
    };

    struct ScoredRefreshRate {
        DisplayModePtr modePtr;
        float score = 0.0f;

        bool operator==(const ScoredRefreshRate& other) const {
            return modePtr == other.modePtr && score == other.score;
        }

        static bool scoresEqual(float lhs, float rhs) {
            constexpr float kEpsilon = 0.0001f;
            return std::abs(lhs - rhs) <= kEpsilon;
        }

        struct DescendingScore {
            bool operator()(const ScoredRefreshRate& lhs, const ScoredRefreshRate& rhs) const {
                return lhs.score > rhs.score && !scoresEqual(lhs.score, rhs.score);
            }
        };
    };

    using RefreshRateRanking = std::vector<ScoredRefreshRate>;

    struct RankedRefreshRates {
        RefreshRateRanking ranking; // Ordered by descending score.
        GlobalSignals consideredSignals;

        bool operator==(const RankedRefreshRates& other) const {
            return ranking == other.ranking && consideredSignals == other.consideredSignals;
        }
    };

    RankedRefreshRates getRankedRefreshRates(const std::vector<LayerRequirement>&,
                                             GlobalSignals) const EXCLUDES(mLock);

    FpsRange getSupportedRefreshRateRange() const EXCLUDES(mLock) {
        std::lock_guard lock(mLock);
        return {mMinRefreshRateModeIt->second->getFps(), mMaxRefreshRateModeIt->second->getFps()};
    }

    std::optional<Fps> onKernelTimerChanged(std::optional<DisplayModeId> desiredActiveModeId,
                                            bool timerExpired) const EXCLUDES(mLock);

    void setActiveModeId(DisplayModeId) EXCLUDES(mLock) REQUIRES(kMainThreadContext);

    // See mActiveModeIt for thread safety.
    DisplayModePtr getActiveModePtr() const EXCLUDES(mLock);
    const DisplayMode& getActiveMode() const REQUIRES(kMainThreadContext);

    // Returns a known frame rate that is the closest to frameRate
    Fps findClosestKnownFrameRate(Fps frameRate) const;

    enum class KernelIdleTimerController { Sysprop, HwcApi, ftl_last = HwcApi };

    // Configuration flags.
    struct Config {
        bool enableFrameRateOverride = false;

        // Specifies the upper refresh rate threshold (inclusive) for layer vote types of multiple
        // or heuristic, such that refresh rates higher than this value will not be voted for. 0 if
        // no threshold is set.
        int frameRateMultipleThreshold = 0;

        // The Idle Timer timeout. 0 timeout means no idle timer.
        std::chrono::milliseconds idleTimerTimeout = 0ms;

        // The controller representing how the kernel idle timer will be configured
        // either on the HWC api or sysprop.
        ftl::Optional<KernelIdleTimerController> kernelIdleTimerController;
    };

    RefreshRateSelector(DisplayModes, DisplayModeId activeModeId,
                        Config config = {.enableFrameRateOverride = false,
                                         .frameRateMultipleThreshold = 0,
                                         .idleTimerTimeout = 0ms,
                                         .kernelIdleTimerController = {}});

    RefreshRateSelector(const RefreshRateSelector&) = delete;
    RefreshRateSelector& operator=(const RefreshRateSelector&) = delete;

    // Returns whether switching modes (refresh rate or resolution) is possible.
    // TODO(b/158780872): Consider HAL support, and skip frame rate detection if the modes only
    // differ in resolution.
    bool canSwitch() const EXCLUDES(mLock) {
        std::lock_guard lock(mLock);
        return mDisplayModes.size() > 1;
    }

    // Class to enumerate options around toggling the kernel timer on and off.
    enum class KernelIdleTimerAction {
        TurnOff, // Turn off the idle timer.
        TurnOn   // Turn on the idle timer.
    };

    // Checks whether kernel idle timer should be active depending the policy decisions around
    // refresh rates.
    KernelIdleTimerAction getIdleTimerAction() const;

    bool supportsFrameRateOverrideByContent() const { return mSupportsFrameRateOverrideByContent; }

    // Return the display refresh rate divisor to match the layer
    // frame rate, or 0 if the display refresh rate is not a multiple of the
    // layer refresh rate.
    static int getFrameRateDivisor(Fps displayRefreshRate, Fps layerFrameRate);

    // Returns if the provided frame rates have a ratio t*1000/1001 or t*1001/1000
    // for an integer t.
    static bool isFractionalPairOrMultiple(Fps, Fps);

    using UidToFrameRateOverride = std::map<uid_t, Fps>;

    // Returns the frame rate override for each uid.
    UidToFrameRateOverride getFrameRateOverrides(const std::vector<LayerRequirement>&,
                                                 Fps displayFrameRate, GlobalSignals) const
            EXCLUDES(mLock);

    std::optional<KernelIdleTimerController> kernelIdleTimerController() {
        return mConfig.kernelIdleTimerController;
    }

    struct IdleTimerCallbacks {
        struct Callbacks {
            std::function<void()> onReset;
            std::function<void()> onExpired;
        };

        Callbacks platform;
        Callbacks kernel;
    };

    void setIdleTimerCallbacks(IdleTimerCallbacks callbacks) EXCLUDES(mIdleTimerCallbacksMutex) {
        std::scoped_lock lock(mIdleTimerCallbacksMutex);
        mIdleTimerCallbacks = std::move(callbacks);
    }

    void clearIdleTimerCallbacks() EXCLUDES(mIdleTimerCallbacksMutex) {
        std::scoped_lock lock(mIdleTimerCallbacksMutex);
        mIdleTimerCallbacks.reset();
    }

    void startIdleTimer() {
        if (mIdleTimer) {
            mIdleTimer->start();
        }
    }

    void stopIdleTimer() {
        if (mIdleTimer) {
            mIdleTimer->stop();
        }
    }

    void resetIdleTimer(bool kernelOnly) {
        if (!mIdleTimer) {
            return;
        }
        if (kernelOnly && !mConfig.kernelIdleTimerController.has_value()) {
            return;
        }
        mIdleTimer->reset();
    }

    void dump(utils::Dumper&) const EXCLUDES(mLock);

    std::chrono::milliseconds getIdleTimerTimeout();

private:
    friend struct TestableRefreshRateSelector;

    void constructAvailableRefreshRates() REQUIRES(mLock);

    // See mActiveModeIt for thread safety.
    DisplayModeIterator getActiveModeItLocked() const REQUIRES(mLock);

    RankedRefreshRates getRankedRefreshRatesLocked(const std::vector<LayerRequirement>&,
                                                   GlobalSignals) const REQUIRES(mLock);

    // Returns number of display frames and remainder when dividing the layer refresh period by
    // display refresh period.
    std::pair<nsecs_t, nsecs_t> getDisplayFrames(nsecs_t layerPeriod, nsecs_t displayPeriod) const;

    // Returns the lowest refresh rate according to the current policy. May change at runtime. Only
    // uses the primary range, not the app request range.
    const DisplayModePtr& getMinRefreshRateByPolicyLocked() const REQUIRES(mLock);

    // Returns the highest refresh rate according to the current policy. May change at runtime. Only
    // uses the primary range, not the app request range.
    const DisplayModePtr& getMaxRefreshRateByPolicyLocked(int anchorGroup) const REQUIRES(mLock);

    struct RefreshRateScoreComparator;

    enum class RefreshRateOrder { Ascending, Descending };

    // Only uses the primary range, not the app request range.
    RefreshRateRanking rankRefreshRates(std::optional<int> anchorGroupOpt, RefreshRateOrder,
                                        std::optional<DisplayModeId> preferredDisplayModeOpt =
                                                std::nullopt) const REQUIRES(mLock);

    const Policy* getCurrentPolicyLocked() const REQUIRES(mLock);
    bool isPolicyValidLocked(const Policy& policy) const REQUIRES(mLock);

    // Returns the refresh rate score as a ratio to max refresh rate, which has a score of 1.
    float calculateRefreshRateScoreForFps(Fps refreshRate) const REQUIRES(mLock);
    // calculates a score for a layer. Used to determine the display refresh rate
    // and the frame rate override for certains applications.
    float calculateLayerScoreLocked(const LayerRequirement&, Fps refreshRate,
                                    bool isSeamlessSwitch) const REQUIRES(mLock);

    float calculateNonExactMatchingLayerScoreLocked(const LayerRequirement&, Fps refreshRate) const
            REQUIRES(mLock);

    void updateDisplayModes(DisplayModes, DisplayModeId activeModeId) EXCLUDES(mLock)
            REQUIRES(kMainThreadContext);

    void initializeIdleTimer();

    std::optional<IdleTimerCallbacks::Callbacks> getIdleTimerCallbacks() const
            REQUIRES(mIdleTimerCallbacksMutex) {
        if (!mIdleTimerCallbacks) return {};
        return mConfig.kernelIdleTimerController.has_value() ? mIdleTimerCallbacks->kernel
                                                             : mIdleTimerCallbacks->platform;
    }

    // The display modes of the active display. The DisplayModeIterators below are pointers into
    // this container, so must be invalidated whenever the DisplayModes change. The Policy below
    // is also dependent, so must be reset as well.
    DisplayModes mDisplayModes GUARDED_BY(mLock);

    // Written under mLock exclusively from kMainThreadContext, so reads from kMainThreadContext
    // need not be under mLock.
    DisplayModeIterator mActiveModeIt GUARDED_BY(mLock) GUARDED_BY(kMainThreadContext);

    DisplayModeIterator mMinRefreshRateModeIt GUARDED_BY(mLock);
    DisplayModeIterator mMaxRefreshRateModeIt GUARDED_BY(mLock);

    // Display modes that satisfy the Policy's ranges, filtered and sorted by refresh rate.
    std::vector<DisplayModeIterator> mPrimaryRefreshRates GUARDED_BY(mLock);
    std::vector<DisplayModeIterator> mAppRequestRefreshRates GUARDED_BY(mLock);

    Policy mDisplayManagerPolicy GUARDED_BY(mLock);
    std::optional<Policy> mOverridePolicy GUARDED_BY(mLock);

    unsigned mNumModeSwitchesInPolicy GUARDED_BY(kMainThreadContext) = 0;

    mutable std::mutex mLock;

    // A sorted list of known frame rates that a Heuristic layer will choose
    // from based on the closest value.
    const std::vector<Fps> mKnownFrameRates;

    const Config mConfig;
    bool mSupportsFrameRateOverrideByContent;

    struct GetRankedRefreshRatesCache {
        std::pair<std::vector<LayerRequirement>, GlobalSignals> arguments;
        RankedRefreshRates result;
    };
    mutable std::optional<GetRankedRefreshRatesCache> mGetRankedRefreshRatesCache GUARDED_BY(mLock);

    // Declare mIdleTimer last to ensure its thread joins before the mutex/callbacks are destroyed.
    std::mutex mIdleTimerCallbacksMutex;
    std::optional<IdleTimerCallbacks> mIdleTimerCallbacks GUARDED_BY(mIdleTimerCallbacksMutex);
    // Used to detect (lack of) frame activity.
    ftl::Optional<scheduler::OneShotTimer> mIdleTimer;
};

} // namespace android::scheduler
