/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _UI_INPUT_DISPATCHER_H
#define _UI_INPUT_DISPATCHER_H

#include "AnrTracker.h"
#include "CancelationOptions.h"
#include "DragState.h"
#include "Entry.h"
#include "FocusResolver.h"
#include "InjectionState.h"
#include "InputDispatcherConfiguration.h"
#include "InputDispatcherInterface.h"
#include "InputDispatcherPolicyInterface.h"
#include "InputState.h"
#include "InputTarget.h"
#include "InputThread.h"
#include "LatencyAggregator.h"
#include "LatencyTracker.h"
#include "Monitor.h"
#include "TouchState.h"
#include "TouchedWindow.h"

#include <attestation/HmacKeyManager.h>
#include <com/android/internal/compat/IPlatformCompatNative.h>
#include <input/Input.h>
#include <input/InputApplication.h>
#include <input/InputTransport.h>
#include <input/InputWindow.h>
#include <limits.h>
#include <stddef.h>
#include <ui/Region.h>
#include <unistd.h>
#include <utils/BitSet.h>
#include <utils/Looper.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>
#include <utils/threads.h>
#include <condition_variable>
#include <deque>
#include <optional>
#include <unordered_map>
#include <unordered_set>

#include <InputListener.h>
#include <InputReporterInterface.h>

namespace android::inputdispatcher {

class Connection;

/* Dispatches events to input targets.  Some functions of the input dispatcher, such as
 * identifying input targets, are controlled by a separate policy object.
 *
 * IMPORTANT INVARIANT:
 *     Because the policy can potentially block or cause re-entrance into the input dispatcher,
 *     the input dispatcher never calls into the policy while holding its internal locks.
 *     The implementation is also carefully designed to recover from scenarios such as an
 *     input channel becoming unregistered while identifying input targets or processing timeouts.
 *
 *     Methods marked 'Locked' must be called with the lock acquired.
 *
 *     Methods marked 'LockedInterruptible' must be called with the lock acquired but
 *     may during the course of their execution release the lock, call into the policy, and
 *     then reacquire the lock.  The caller is responsible for recovering gracefully.
 *
 *     A 'LockedInterruptible' method may called a 'Locked' method, but NOT vice-versa.
 */
class InputDispatcher : public android::InputDispatcherInterface {
protected:
    ~InputDispatcher() override;

public:
    explicit InputDispatcher(const sp<InputDispatcherPolicyInterface>& policy);

    void dump(std::string& dump) override;
    void monitor() override;
    bool waitForIdle() override;
    status_t start() override;
    status_t stop() override;

    void notifyConfigurationChanged(const NotifyConfigurationChangedArgs* args) override;
    void notifyKey(const NotifyKeyArgs* args) override;
    void notifyMotion(const NotifyMotionArgs* args) override;
    void notifySwitch(const NotifySwitchArgs* args) override;
    void notifySensor(const NotifySensorArgs* args) override;
    void notifyVibratorState(const NotifyVibratorStateArgs* args) override;
    void notifyDeviceReset(const NotifyDeviceResetArgs* args) override;
    void notifyPointerCaptureChanged(const NotifyPointerCaptureChangedArgs* args) override;

    android::os::InputEventInjectionResult injectInputEvent(
            const InputEvent* event, int32_t injectorPid, int32_t injectorUid,
            android::os::InputEventInjectionSync syncMode, std::chrono::milliseconds timeout,
            uint32_t policyFlags) override;

    std::unique_ptr<VerifiedInputEvent> verifyInputEvent(const InputEvent& event) override;

    void setInputWindows(const std::unordered_map<int32_t, std::vector<sp<InputWindowHandle>>>&
                                 handlesPerDisplay) override;
    void setFocusedApplication(
            int32_t displayId,
            const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle) override;
    void setFocusedDisplay(int32_t displayId) override;
    void setInputDispatchMode(bool enabled, bool frozen) override;
    void setInputFilterEnabled(bool enabled) override;
    void setInTouchMode(bool inTouchMode) override;
    void setMaximumObscuringOpacityForTouch(float opacity) override;
    void setBlockUntrustedTouchesMode(android::os::BlockUntrustedTouchesMode mode) override;

    bool transferTouchFocus(const sp<IBinder>& fromToken, const sp<IBinder>& toToken,
                            bool isDragDrop = false) override;
    bool transferTouch(const sp<IBinder>& destChannelToken) override;

    base::Result<std::unique_ptr<InputChannel>> createInputChannel(
            const std::string& name) override;
    void setFocusedWindow(const FocusRequest&) override;
    base::Result<std::unique_ptr<InputChannel>> createInputMonitor(int32_t displayId,
                                                                   bool isGestureMonitor,
                                                                   const std::string& name,
                                                                   int32_t pid) override;
    status_t removeInputChannel(const sp<IBinder>& connectionToken) override;
    status_t pilferPointers(const sp<IBinder>& token) override;
    void requestPointerCapture(const sp<IBinder>& windowToken, bool enabled) override;
    bool flushSensor(int deviceId, InputDeviceSensorType sensorType) override;

    std::array<uint8_t, 32> sign(const VerifiedInputEvent& event) const;

    void displayRemoved(int32_t displayId) override;

private:
    enum class DropReason {
        NOT_DROPPED,
        POLICY,
        APP_SWITCH,
        DISABLED,
        BLOCKED,
        STALE,
        NO_POINTER_CAPTURE,
    };

    std::unique_ptr<InputThread> mThread;

    sp<InputDispatcherPolicyInterface> mPolicy;
    android::InputDispatcherConfiguration mConfig;

    std::mutex mLock;

    std::condition_variable mDispatcherIsAlive;
    std::condition_variable mDispatcherEnteredIdle;

    sp<Looper> mLooper;

    std::shared_ptr<EventEntry> mPendingEvent GUARDED_BY(mLock);
    std::deque<std::shared_ptr<EventEntry>> mInboundQueue GUARDED_BY(mLock);
    std::deque<std::shared_ptr<EventEntry>> mRecentQueue GUARDED_BY(mLock);
    std::deque<std::unique_ptr<CommandEntry>> mCommandQueue GUARDED_BY(mLock);

    DropReason mLastDropReason GUARDED_BY(mLock);

    const IdGenerator mIdGenerator;

    // With each iteration, InputDispatcher nominally processes one queued event,
    // a timeout, or a response from an input consumer.
    // This method should only be called on the input dispatcher's own thread.
    void dispatchOnce();

    void dispatchOnceInnerLocked(nsecs_t* nextWakeupTime) REQUIRES(mLock);

    // Enqueues an inbound event.  Returns true if mLooper->wake() should be called.
    bool enqueueInboundEventLocked(std::unique_ptr<EventEntry> entry) REQUIRES(mLock);

    // Cleans up input state when dropping an inbound event.
    void dropInboundEventLocked(const EventEntry& entry, DropReason dropReason) REQUIRES(mLock);

    // Enqueues a focus event.
    void enqueueFocusEventLocked(const sp<IBinder>& windowToken, bool hasFocus,
                                 const std::string& reason) REQUIRES(mLock);
    // Enqueues a drag event.
    void enqueueDragEventLocked(const sp<InputWindowHandle>& windowToken, bool isExiting,
                                const MotionEntry& motionEntry) REQUIRES(mLock);

    // Adds an event to a queue of recent events for debugging purposes.
    void addRecentEventLocked(std::shared_ptr<EventEntry> entry) REQUIRES(mLock);

    // App switch latency optimization.
    bool mAppSwitchSawKeyDown GUARDED_BY(mLock);
    nsecs_t mAppSwitchDueTime GUARDED_BY(mLock);

    bool isAppSwitchKeyEvent(const KeyEntry& keyEntry);
    bool isAppSwitchPendingLocked() REQUIRES(mLock);
    void resetPendingAppSwitchLocked(bool handled) REQUIRES(mLock);

    // Blocked event latency optimization.  Drops old events when the user intends
    // to transfer focus to a new application.
    std::shared_ptr<EventEntry> mNextUnblockedEvent GUARDED_BY(mLock);

    sp<InputWindowHandle> findTouchedWindowAtLocked(int32_t displayId, int32_t x, int32_t y,
                                                    TouchState* touchState,
                                                    bool addOutsideTargets = false,
                                                    bool addPortalWindows = false,
                                                    bool ignoreDragWindow = false) REQUIRES(mLock);

    sp<Connection> getConnectionLocked(const sp<IBinder>& inputConnectionToken) const
            REQUIRES(mLock);

    std::string getConnectionNameLocked(const sp<IBinder>& connectionToken) const REQUIRES(mLock);

    void removeConnectionLocked(const sp<Connection>& connection) REQUIRES(mLock);

    template <typename T>
    struct StrongPointerHash {
        std::size_t operator()(const sp<T>& b) const { return std::hash<T*>{}(b.get()); }
    };

    // All registered connections mapped by input channel token.
    std::unordered_map<sp<IBinder>, sp<Connection>, StrongPointerHash<IBinder>> mConnectionsByToken
            GUARDED_BY(mLock);

    // Finds the display ID of the gesture monitor identified by the provided token.
    std::optional<int32_t> findGestureMonitorDisplayByTokenLocked(const sp<IBinder>& token)
            REQUIRES(mLock);
    // Find a monitor pid by the provided token.
    std::optional<int32_t> findMonitorPidByTokenLocked(const sp<IBinder>& token) REQUIRES(mLock);

    // Input channels that will receive a copy of all input events sent to the provided display.
    std::unordered_map<int32_t, std::vector<Monitor>> mGlobalMonitorsByDisplay GUARDED_BY(mLock);

    // Input channels that will receive pointer events that start within the corresponding display.
    // These are a bit special when compared to global monitors since they'll cause gesture streams
    // to continue even when there isn't a touched window,and have the ability to steal the rest of
    // the pointer stream in order to claim it for a system gesture.
    std::unordered_map<int32_t, std::vector<Monitor>> mGestureMonitorsByDisplay GUARDED_BY(mLock);

    const HmacKeyManager mHmacKeyManager;
    const std::array<uint8_t, 32> getSignature(const MotionEntry& motionEntry,
                                               const DispatchEntry& dispatchEntry) const;
    const std::array<uint8_t, 32> getSignature(const KeyEntry& keyEntry,
                                               const DispatchEntry& dispatchEntry) const;

    // Event injection and synchronization.
    std::condition_variable mInjectionResultAvailable;
    bool hasInjectionPermission(int32_t injectorPid, int32_t injectorUid);
    void setInjectionResult(EventEntry& entry,
                            android::os::InputEventInjectionResult injectionResult);

    std::condition_variable mInjectionSyncFinished;
    void incrementPendingForegroundDispatches(EventEntry& entry);
    void decrementPendingForegroundDispatches(EventEntry& entry);

    // Key repeat tracking.
    struct KeyRepeatState {
        std::shared_ptr<KeyEntry> lastKeyEntry; // or null if no repeat
        nsecs_t nextRepeatTime;
    } mKeyRepeatState GUARDED_BY(mLock);

    void resetKeyRepeatLocked() REQUIRES(mLock);
    std::shared_ptr<KeyEntry> synthesizeKeyRepeatLocked(nsecs_t currentTime) REQUIRES(mLock);

    // Key replacement tracking
    struct KeyReplacement {
        int32_t keyCode;
        int32_t deviceId;
        bool operator==(const KeyReplacement& rhs) const {
            return keyCode == rhs.keyCode && deviceId == rhs.deviceId;
        }
    };
    struct KeyReplacementHash {
        size_t operator()(const KeyReplacement& key) const {
            return std::hash<int32_t>()(key.keyCode) ^ (std::hash<int32_t>()(key.deviceId) << 1);
        }
    };
    // Maps the key code replaced, device id tuple to the key code it was replaced with
    std::unordered_map<KeyReplacement, int32_t, KeyReplacementHash> mReplacedKeys GUARDED_BY(mLock);
    // Process certain Meta + Key combinations
    void accelerateMetaShortcuts(const int32_t deviceId, const int32_t action, int32_t& keyCode,
                                 int32_t& metaState);

    // Deferred command processing.
    bool haveCommandsLocked() const REQUIRES(mLock);
    bool runCommandsLockedInterruptible() REQUIRES(mLock);
    void postCommandLocked(std::unique_ptr<CommandEntry> commandEntry) REQUIRES(mLock);

    nsecs_t processAnrsLocked() REQUIRES(mLock);
    std::chrono::nanoseconds getDispatchingTimeoutLocked(const sp<IBinder>& token) REQUIRES(mLock);

    // Input filter processing.
    bool shouldSendKeyToInputFilterLocked(const NotifyKeyArgs* args) REQUIRES(mLock);
    bool shouldSendMotionToInputFilterLocked(const NotifyMotionArgs* args) REQUIRES(mLock);

    // Inbound event processing.
    void drainInboundQueueLocked() REQUIRES(mLock);
    void releasePendingEventLocked() REQUIRES(mLock);
    void releaseInboundEventLocked(std::shared_ptr<EventEntry> entry) REQUIRES(mLock);

    // Dispatch state.
    bool mDispatchEnabled GUARDED_BY(mLock);
    bool mDispatchFrozen GUARDED_BY(mLock);
    bool mInputFilterEnabled GUARDED_BY(mLock);
    bool mInTouchMode GUARDED_BY(mLock);
    float mMaximumObscuringOpacityForTouch GUARDED_BY(mLock);
    android::os::BlockUntrustedTouchesMode mBlockUntrustedTouchesMode GUARDED_BY(mLock);

    std::unordered_map<int32_t, std::vector<sp<InputWindowHandle>>> mWindowHandlesByDisplay
            GUARDED_BY(mLock);
    void setInputWindowsLocked(const std::vector<sp<InputWindowHandle>>& inputWindowHandles,
                               int32_t displayId) REQUIRES(mLock);
    // Get a reference to window handles by display, return an empty vector if not found.
    const std::vector<sp<InputWindowHandle>>& getWindowHandlesLocked(int32_t displayId) const
            REQUIRES(mLock);
    sp<InputWindowHandle> getWindowHandleLocked(const sp<IBinder>& windowHandleToken) const
            REQUIRES(mLock);

    // Same function as above, but faster. Since displayId is provided, this avoids the need
    // to loop through all displays.
    sp<InputWindowHandle> getWindowHandleLocked(const sp<IBinder>& windowHandleToken,
                                                int displayId) const REQUIRES(mLock);
    sp<InputWindowHandle> getWindowHandleLocked(const sp<InputWindowHandle>& windowHandle) const
            REQUIRES(mLock);
    std::shared_ptr<InputChannel> getInputChannelLocked(const sp<IBinder>& windowToken) const
            REQUIRES(mLock);
    sp<InputWindowHandle> getFocusedWindowHandleLocked(int displayId) const REQUIRES(mLock);
    bool hasResponsiveConnectionLocked(InputWindowHandle& windowHandle) const REQUIRES(mLock);

    /*
     * Validate and update InputWindowHandles for a given display.
     */
    void updateWindowHandlesForDisplayLocked(
            const std::vector<sp<InputWindowHandle>>& inputWindowHandles, int32_t displayId)
            REQUIRES(mLock);

    std::unordered_map<int32_t, TouchState> mTouchStatesByDisplay GUARDED_BY(mLock);
    std::unique_ptr<DragState> mDragState GUARDED_BY(mLock);

    void setFocusedApplicationLocked(
            int32_t displayId,
            const std::shared_ptr<InputApplicationHandle>& inputApplicationHandle) REQUIRES(mLock);
    // Focused applications.
    std::unordered_map<int32_t, std::shared_ptr<InputApplicationHandle>>
            mFocusedApplicationHandlesByDisplay GUARDED_BY(mLock);

    // Top focused display.
    int32_t mFocusedDisplayId GUARDED_BY(mLock);

    // Keeps track of the focused window per display and determines focus changes.
    FocusResolver mFocusResolver GUARDED_BY(mLock);

    // The enabled state of this request is true iff the focused window on the focused display has
    // requested Pointer Capture. This request also contains the sequence number associated with the
    // current request. The state of this variable should always be in sync with the state of
    // Pointer Capture in the policy, and is only updated through setPointerCaptureLocked(request).
    PointerCaptureRequest mCurrentPointerCaptureRequest GUARDED_BY(mLock);

    // The window token that has Pointer Capture.
    // This should be in sync with PointerCaptureChangedEvents dispatched to the input channel.
    sp<IBinder> mWindowTokenWithPointerCapture GUARDED_BY(mLock);

    // Disable Pointer Capture as a result of loss of window focus.
    void disablePointerCaptureForcedLocked() REQUIRES(mLock);

    // Set the Pointer Capture state in the Policy.
    void setPointerCaptureLocked(bool enable) REQUIRES(mLock);

    // Dispatcher state at time of last ANR.
    std::string mLastAnrState GUARDED_BY(mLock);

    // The connection tokens of the channels that the user last interacted, for debugging
    std::unordered_set<sp<IBinder>, StrongPointerHash<IBinder>> mInteractionConnectionTokens
            GUARDED_BY(mLock);
    void updateInteractionTokensLocked(const EventEntry& entry,
                                       const std::vector<InputTarget>& targets) REQUIRES(mLock);

    // Dispatch inbound events.
    bool dispatchConfigurationChangedLocked(nsecs_t currentTime,
                                            const ConfigurationChangedEntry& entry) REQUIRES(mLock);
    bool dispatchDeviceResetLocked(nsecs_t currentTime, const DeviceResetEntry& entry)
            REQUIRES(mLock);
    bool dispatchKeyLocked(nsecs_t currentTime, std::shared_ptr<KeyEntry> entry,
                           DropReason* dropReason, nsecs_t* nextWakeupTime) REQUIRES(mLock);
    bool dispatchMotionLocked(nsecs_t currentTime, std::shared_ptr<MotionEntry> entry,
                              DropReason* dropReason, nsecs_t* nextWakeupTime) REQUIRES(mLock);
    void dispatchFocusLocked(nsecs_t currentTime, std::shared_ptr<FocusEntry> entry)
            REQUIRES(mLock);
    void dispatchPointerCaptureChangedLocked(
            nsecs_t currentTime, const std::shared_ptr<PointerCaptureChangedEntry>& entry,
            DropReason& dropReason) REQUIRES(mLock);
    void dispatchEventLocked(nsecs_t currentTime, std::shared_ptr<EventEntry> entry,
                             const std::vector<InputTarget>& inputTargets) REQUIRES(mLock);
    void dispatchSensorLocked(nsecs_t currentTime, std::shared_ptr<SensorEntry> entry,
                              DropReason* dropReason, nsecs_t* nextWakeupTime) REQUIRES(mLock);
    void dispatchDragLocked(nsecs_t currentTime, std::shared_ptr<DragEntry> entry) REQUIRES(mLock);
    void logOutboundKeyDetails(const char* prefix, const KeyEntry& entry);
    void logOutboundMotionDetails(const char* prefix, const MotionEntry& entry);

    /**
     * This field is set if there is no focused window, and we have an event that requires
     * a focused window to be dispatched (for example, a KeyEvent).
     * When this happens, we will wait until *mNoFocusedWindowTimeoutTime before
     * dropping the event and raising an ANR for that application.
     * This is useful if an application is slow to add a focused window.
     */
    std::optional<nsecs_t> mNoFocusedWindowTimeoutTime GUARDED_BY(mLock);

    bool shouldPruneInboundQueueLocked(const MotionEntry& motionEntry) REQUIRES(mLock);

    /**
     * Time to stop waiting for the events to be processed while trying to dispatch a key.
     * When this time expires, we just send the pending key event to the currently focused window,
     * without waiting on other events to be processed first.
     */
    std::optional<nsecs_t> mKeyIsWaitingForEventsTimeout GUARDED_BY(mLock);
    bool shouldWaitToSendKeyLocked(nsecs_t currentTime, const char* focusedWindowName)
            REQUIRES(mLock);

    /**
     * The focused application at the time when no focused window was present.
     * Used to raise an ANR when we have no focused window.
     */
    std::shared_ptr<InputApplicationHandle> mAwaitedFocusedApplication GUARDED_BY(mLock);
    /**
     * The displayId that the focused application is associated with.
     */
    int32_t mAwaitedApplicationDisplayId GUARDED_BY(mLock);
    void processNoFocusedWindowAnrLocked() REQUIRES(mLock);

    /**
     * Tell policy about a window or a monitor that just became unresponsive. Starts ANR.
     */
    void processConnectionUnresponsiveLocked(const Connection& connection, std::string reason)
            REQUIRES(mLock);
    /**
     * Tell policy about a window or a monitor that just became responsive.
     */
    void processConnectionResponsiveLocked(const Connection& connection) REQUIRES(mLock);

    /**
     * Post `doNotifyMonitorUnresponsiveLockedInterruptible` command.
     */
    void sendMonitorUnresponsiveCommandLocked(int32_t pid, std::string reason) REQUIRES(mLock);
    /**
     * Post `doNotifyWindowUnresponsiveLockedInterruptible` command.
     */
    void sendWindowUnresponsiveCommandLocked(sp<IBinder> connectionToken, std::string reason)
            REQUIRES(mLock);
    /**
     * Post `doNotifyMonitorResponsiveLockedInterruptible` command.
     */
    void sendMonitorResponsiveCommandLocked(int32_t pid) REQUIRES(mLock);
    /**
     * Post `doNotifyWindowResponsiveLockedInterruptible` command.
     */
    void sendWindowResponsiveCommandLocked(sp<IBinder> connectionToken) REQUIRES(mLock);


    // Optimization: AnrTracker is used to quickly find which connection is due for a timeout next.
    // AnrTracker must be kept in-sync with all responsive connection.waitQueues.
    // If a connection is not responsive, then the entries should not be added to the AnrTracker.
    // Once a connection becomes unresponsive, its entries are removed from AnrTracker to
    // prevent unneeded wakeups.
    AnrTracker mAnrTracker GUARDED_BY(mLock);

    // Contains the last window which received a hover event.
    sp<InputWindowHandle> mLastHoverWindowHandle GUARDED_BY(mLock);

    void cancelEventsForAnrLocked(const sp<Connection>& connection) REQUIRES(mLock);
    nsecs_t getTimeSpentWaitingForApplicationLocked(nsecs_t currentTime) REQUIRES(mLock);
    // If a focused application changes, we should stop counting down the "no focused window" time,
    // because we will have no way of knowing when the previous application actually added a window.
    // This also means that we will miss cases like pulling down notification shade when the
    // focused application does not have a focused window (no ANR will be raised if notification
    // shade is pulled down while we are counting down the timeout).
    void resetNoFocusedWindowTimeoutLocked() REQUIRES(mLock);

    int32_t getTargetDisplayId(const EventEntry& entry);
    android::os::InputEventInjectionResult findFocusedWindowTargetsLocked(
            nsecs_t currentTime, const EventEntry& entry, std::vector<InputTarget>& inputTargets,
            nsecs_t* nextWakeupTime) REQUIRES(mLock);
    android::os::InputEventInjectionResult findTouchedWindowTargetsLocked(
            nsecs_t currentTime, const MotionEntry& entry, std::vector<InputTarget>& inputTargets,
            nsecs_t* nextWakeupTime, bool* outConflictingPointerActions) REQUIRES(mLock);
    std::vector<TouchedMonitor> findTouchedGestureMonitorsLocked(
            int32_t displayId, const std::vector<sp<InputWindowHandle>>& portalWindows) const
            REQUIRES(mLock);
    std::vector<TouchedMonitor> selectResponsiveMonitorsLocked(
            const std::vector<TouchedMonitor>& gestureMonitors) const REQUIRES(mLock);

    void addWindowTargetLocked(const sp<InputWindowHandle>& windowHandle, int32_t targetFlags,
                               BitSet32 pointerIds, std::vector<InputTarget>& inputTargets)
            REQUIRES(mLock);
    void addMonitoringTargetLocked(const Monitor& monitor, float xOffset, float yOffset,
                                   std::vector<InputTarget>& inputTargets) REQUIRES(mLock);
    void addGlobalMonitoringTargetsLocked(std::vector<InputTarget>& inputTargets, int32_t displayId,
                                          float xOffset = 0, float yOffset = 0) REQUIRES(mLock);
    void pokeUserActivityLocked(const EventEntry& eventEntry) REQUIRES(mLock);
    bool checkInjectionPermission(const sp<InputWindowHandle>& windowHandle,
                                  const InjectionState* injectionState);
    // Enqueue a drag event if needed, and update the touch state.
    // Uses findTouchedWindowTargetsLocked to make the decision
    void addDragEventLocked(const MotionEntry& entry) REQUIRES(mLock);
    void finishDragAndDrop(int32_t displayId, float x, float y) REQUIRES(mLock);

    struct TouchOcclusionInfo {
        bool hasBlockingOcclusion;
        float obscuringOpacity;
        std::string obscuringPackage;
        int32_t obscuringUid;
        std::vector<std::string> debugInfo;
    };

    TouchOcclusionInfo computeTouchOcclusionInfoLocked(const sp<InputWindowHandle>& windowHandle,
                                                       int32_t x, int32_t y) const REQUIRES(mLock);
    bool isTouchTrustedLocked(const TouchOcclusionInfo& occlusionInfo) const REQUIRES(mLock);
    bool isWindowObscuredAtPointLocked(const sp<InputWindowHandle>& windowHandle, int32_t x,
                                       int32_t y) const REQUIRES(mLock);
    bool isWindowObscuredLocked(const sp<InputWindowHandle>& windowHandle) const REQUIRES(mLock);
    std::string dumpWindowForTouchOcclusion(const InputWindowInfo* info, bool isTouchWindow) const;
    std::string getApplicationWindowLabel(const InputApplicationHandle* applicationHandle,
                                          const sp<InputWindowHandle>& windowHandle);

    // Manage the dispatch cycle for a single connection.
    // These methods are deliberately not Interruptible because doing all of the work
    // with the mutex held makes it easier to ensure that connection invariants are maintained.
    // If needed, the methods post commands to run later once the critical bits are done.
    void prepareDispatchCycleLocked(nsecs_t currentTime, const sp<Connection>& connection,
                                    std::shared_ptr<EventEntry>, const InputTarget& inputTarget)
            REQUIRES(mLock);
    void enqueueDispatchEntriesLocked(nsecs_t currentTime, const sp<Connection>& connection,
                                      std::shared_ptr<EventEntry>, const InputTarget& inputTarget)
            REQUIRES(mLock);
    void enqueueDispatchEntryLocked(const sp<Connection>& connection, std::shared_ptr<EventEntry>,
                                    const InputTarget& inputTarget, int32_t dispatchMode)
            REQUIRES(mLock);
    void startDispatchCycleLocked(nsecs_t currentTime, const sp<Connection>& connection)
            REQUIRES(mLock);
    void finishDispatchCycleLocked(nsecs_t currentTime, const sp<Connection>& connection,
                                   uint32_t seq, bool handled, nsecs_t consumeTime) REQUIRES(mLock);
    void abortBrokenDispatchCycleLocked(nsecs_t currentTime, const sp<Connection>& connection,
                                        bool notify) REQUIRES(mLock);
    void drainDispatchQueue(std::deque<DispatchEntry*>& queue);
    void releaseDispatchEntry(DispatchEntry* dispatchEntry);
    int handleReceiveCallback(int events, sp<IBinder> connectionToken);
    // The action sent should only be of type AMOTION_EVENT_*
    void dispatchPointerDownOutsideFocus(uint32_t source, int32_t action,
                                         const sp<IBinder>& newToken) REQUIRES(mLock);

    void synthesizeCancelationEventsForAllConnectionsLocked(const CancelationOptions& options)
            REQUIRES(mLock);
    void synthesizeCancelationEventsForMonitorsLocked(const CancelationOptions& options)
            REQUIRES(mLock);
    void synthesizeCancelationEventsForMonitorsLocked(
            const CancelationOptions& options,
            std::unordered_map<int32_t, std::vector<Monitor>>& monitorsByDisplay) REQUIRES(mLock);
    void synthesizeCancelationEventsForInputChannelLocked(
            const std::shared_ptr<InputChannel>& channel, const CancelationOptions& options)
            REQUIRES(mLock);
    void synthesizeCancelationEventsForConnectionLocked(const sp<Connection>& connection,
                                                        const CancelationOptions& options)
            REQUIRES(mLock);

    void synthesizePointerDownEventsForConnectionLocked(const sp<Connection>& connection)
            REQUIRES(mLock);

    // Splitting motion events across windows.
    std::unique_ptr<MotionEntry> splitMotionEvent(const MotionEntry& originalMotionEntry,
                                                  BitSet32 pointerIds);

    // Reset and drop everything the dispatcher is doing.
    void resetAndDropEverythingLocked(const char* reason) REQUIRES(mLock);

    // Dump state.
    void dumpDispatchStateLocked(std::string& dump) REQUIRES(mLock);
    void dumpMonitors(std::string& dump, const std::vector<Monitor>& monitors);
    void logDispatchStateLocked() REQUIRES(mLock);
    std::string dumpPointerCaptureStateLocked() REQUIRES(mLock);

    // Registration.
    void removeMonitorChannelLocked(const sp<IBinder>& connectionToken) REQUIRES(mLock);
    void removeMonitorChannelLocked(
            const sp<IBinder>& connectionToken,
            std::unordered_map<int32_t, std::vector<Monitor>>& monitorsByDisplay) REQUIRES(mLock);
    status_t removeInputChannelLocked(const sp<IBinder>& connectionToken, bool notify)
            REQUIRES(mLock);

    // Interesting events that we might like to log or tell the framework about.
    void onDispatchCycleFinishedLocked(nsecs_t currentTime, const sp<Connection>& connection,
                                       uint32_t seq, bool handled, nsecs_t consumeTime)
            REQUIRES(mLock);
    void onDispatchCycleBrokenLocked(nsecs_t currentTime, const sp<Connection>& connection)
            REQUIRES(mLock);
    void onFocusChangedLocked(const FocusResolver::FocusChanges& changes) REQUIRES(mLock);
    void notifyFocusChangedLocked(const sp<IBinder>& oldFocus, const sp<IBinder>& newFocus)
            REQUIRES(mLock);
    void notifyDropWindowLocked(const sp<IBinder>& token, float x, float y) REQUIRES(mLock);
    void onAnrLocked(const sp<Connection>& connection) REQUIRES(mLock);
    void onAnrLocked(std::shared_ptr<InputApplicationHandle> application) REQUIRES(mLock);
    void onUntrustedTouchLocked(const std::string& obscuringPackage) REQUIRES(mLock);
    void updateLastAnrStateLocked(const sp<InputWindowHandle>& window, const std::string& reason)
            REQUIRES(mLock);
    void updateLastAnrStateLocked(const InputApplicationHandle& application,
                                  const std::string& reason) REQUIRES(mLock);
    void updateLastAnrStateLocked(const std::string& windowLabel, const std::string& reason)
            REQUIRES(mLock);

    // Outbound policy interactions.
    void doNotifyConfigurationChangedLockedInterruptible(CommandEntry* commandEntry)
            REQUIRES(mLock);
    void doNotifyInputChannelBrokenLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    void doNotifyFocusChangedLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    void doNotifyDropWindowLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);

    // ANR-related callbacks - start
    void doNotifyNoFocusedWindowAnrLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    void doNotifyWindowUnresponsiveLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    void doNotifyMonitorUnresponsiveLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    void doNotifyWindowResponsiveLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    void doNotifyMonitorResponsiveLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    // ANR-related callbacks - end
    void doNotifySensorLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    void doNotifyUntrustedTouchLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    void doInterceptKeyBeforeDispatchingLockedInterruptible(CommandEntry* commandEntry)
            REQUIRES(mLock);
    void doDispatchCycleFinishedLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    void doSetPointerCaptureLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    bool afterKeyEventLockedInterruptible(const sp<Connection>& connection,
                                          DispatchEntry* dispatchEntry, KeyEntry& keyEntry,
                                          bool handled) REQUIRES(mLock);
    bool afterMotionEventLockedInterruptible(const sp<Connection>& connection,
                                             DispatchEntry* dispatchEntry, MotionEntry& motionEntry,
                                             bool handled) REQUIRES(mLock);
    void doPokeUserActivityLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);
    void doOnPointerDownOutsideFocusLockedInterruptible(CommandEntry* commandEntry) REQUIRES(mLock);

    // Statistics gathering.
    LatencyAggregator mLatencyAggregator GUARDED_BY(mLock);
    LatencyTracker mLatencyTracker GUARDED_BY(mLock);
    void traceInboundQueueLengthLocked() REQUIRES(mLock);
    void traceOutboundQueueLength(const Connection& connection);
    void traceWaitQueueLength(const Connection& connection);

    sp<InputReporterInterface> mReporter;
    sp<com::android::internal::compat::IPlatformCompatNative> mCompatService;
};

} // namespace android::inputdispatcher

#endif // _UI_INPUT_DISPATCHER_H
