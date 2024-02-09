/*
 * Copyright (C) 2019 The Android Open Source Project
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

// clang-format off
#include "../Macros.h"
// clang-format on

#include "KeyboardInputMapper.h"

#include <ftl/enum.h>
#include <ui/Rotation.h>

namespace android {

// --- Static Definitions ---

static int32_t rotateKeyCode(int32_t keyCode, ui::Rotation orientation) {
    static constexpr int32_t KEYCODE_ROTATION_MAP[][4] = {
            // key codes enumerated counter-clockwise with the original (unrotated) key first
            // no rotation,        90 degree rotation,  180 degree rotation, 270 degree rotation
            {AKEYCODE_DPAD_DOWN, AKEYCODE_DPAD_RIGHT, AKEYCODE_DPAD_UP, AKEYCODE_DPAD_LEFT},
            {AKEYCODE_DPAD_RIGHT, AKEYCODE_DPAD_UP, AKEYCODE_DPAD_LEFT, AKEYCODE_DPAD_DOWN},
            {AKEYCODE_DPAD_UP, AKEYCODE_DPAD_LEFT, AKEYCODE_DPAD_DOWN, AKEYCODE_DPAD_RIGHT},
            {AKEYCODE_DPAD_LEFT, AKEYCODE_DPAD_DOWN, AKEYCODE_DPAD_RIGHT, AKEYCODE_DPAD_UP},
            {AKEYCODE_SYSTEM_NAVIGATION_DOWN, AKEYCODE_SYSTEM_NAVIGATION_RIGHT,
             AKEYCODE_SYSTEM_NAVIGATION_UP, AKEYCODE_SYSTEM_NAVIGATION_LEFT},
            {AKEYCODE_SYSTEM_NAVIGATION_RIGHT, AKEYCODE_SYSTEM_NAVIGATION_UP,
             AKEYCODE_SYSTEM_NAVIGATION_LEFT, AKEYCODE_SYSTEM_NAVIGATION_DOWN},
            {AKEYCODE_SYSTEM_NAVIGATION_UP, AKEYCODE_SYSTEM_NAVIGATION_LEFT,
             AKEYCODE_SYSTEM_NAVIGATION_DOWN, AKEYCODE_SYSTEM_NAVIGATION_RIGHT},
            {AKEYCODE_SYSTEM_NAVIGATION_LEFT, AKEYCODE_SYSTEM_NAVIGATION_DOWN,
             AKEYCODE_SYSTEM_NAVIGATION_RIGHT, AKEYCODE_SYSTEM_NAVIGATION_UP},
    };

    if (orientation != ui::ROTATION_0) {
        for (const auto& rotation : KEYCODE_ROTATION_MAP) {
            if (rotation[static_cast<size_t>(ui::ROTATION_0)] == keyCode) {
                return rotation[static_cast<size_t>(orientation)];
            }
        }
    }
    return keyCode;
}

static bool isSupportedScanCode(int32_t scanCode) {
    // KeyboardInputMapper handles keys from keyboards, gamepads, and styluses.
    return scanCode < BTN_MOUSE || (scanCode >= BTN_JOYSTICK && scanCode < BTN_DIGI) ||
            scanCode == BTN_STYLUS || scanCode == BTN_STYLUS2 || scanCode == BTN_STYLUS3 ||
            scanCode >= BTN_WHEEL;
}

static bool isMediaKey(int32_t keyCode) {
    switch (keyCode) {
        case AKEYCODE_MEDIA_PLAY:
        case AKEYCODE_MEDIA_PAUSE:
        case AKEYCODE_MEDIA_PLAY_PAUSE:
        case AKEYCODE_MUTE:
        case AKEYCODE_HEADSETHOOK:
        case AKEYCODE_MEDIA_STOP:
        case AKEYCODE_MEDIA_NEXT:
        case AKEYCODE_MEDIA_PREVIOUS:
        case AKEYCODE_MEDIA_REWIND:
        case AKEYCODE_MEDIA_RECORD:
        case AKEYCODE_MEDIA_FAST_FORWARD:
        case AKEYCODE_MEDIA_SKIP_FORWARD:
        case AKEYCODE_MEDIA_SKIP_BACKWARD:
        case AKEYCODE_MEDIA_STEP_FORWARD:
        case AKEYCODE_MEDIA_STEP_BACKWARD:
        case AKEYCODE_MEDIA_AUDIO_TRACK:
        case AKEYCODE_VOLUME_UP:
        case AKEYCODE_VOLUME_DOWN:
        case AKEYCODE_VOLUME_MUTE:
        case AKEYCODE_TV_AUDIO_DESCRIPTION:
        case AKEYCODE_TV_AUDIO_DESCRIPTION_MIX_UP:
        case AKEYCODE_TV_AUDIO_DESCRIPTION_MIX_DOWN:
            return true;
        default:
            return false;
    }
}

// --- KeyboardInputMapper ---

KeyboardInputMapper::KeyboardInputMapper(InputDeviceContext& deviceContext,
                                         const InputReaderConfiguration& readerConfig,
                                         uint32_t source, int32_t keyboardType)
      : InputMapper(deviceContext, readerConfig), mSource(source), mKeyboardType(keyboardType) {}

uint32_t KeyboardInputMapper::getSources() const {
    return mSource;
}

ui::Rotation KeyboardInputMapper::getOrientation() {
    if (mViewport) {
        return mViewport->orientation;
    }
    return ui::ROTATION_0;
}

int32_t KeyboardInputMapper::getDisplayId() {
    if (mViewport) {
        return mViewport->displayId;
    }
    return ADISPLAY_ID_NONE;
}

std::optional<KeyboardLayoutInfo> KeyboardInputMapper::getKeyboardLayoutInfo() const {
    if (mKeyboardLayoutInfo) {
        return mKeyboardLayoutInfo;
    }
    std::optional<RawLayoutInfo> layoutInfo = getDeviceContext().getRawLayoutInfo();
    if (!layoutInfo) {
        return std::nullopt;
    }
    return KeyboardLayoutInfo(layoutInfo->languageTag, layoutInfo->layoutType);
}

void KeyboardInputMapper::populateDeviceInfo(InputDeviceInfo& info) {
    InputMapper::populateDeviceInfo(info);

    info.setKeyboardType(mKeyboardType);
    info.setKeyCharacterMap(getDeviceContext().getKeyCharacterMap());

    std::optional keyboardLayoutInfo = getKeyboardLayoutInfo();
    if (keyboardLayoutInfo) {
        info.setKeyboardLayoutInfo(*keyboardLayoutInfo);
    }
}

void KeyboardInputMapper::dump(std::string& dump) {
    dump += INDENT2 "Keyboard Input Mapper:\n";
    dumpParameters(dump);
    dump += StringPrintf(INDENT3 "KeyboardType: %d\n", mKeyboardType);
    dump += StringPrintf(INDENT3 "Orientation: %s\n", ftl::enum_string(getOrientation()).c_str());
    dump += StringPrintf(INDENT3 "KeyDowns: %zu keys currently down\n", mKeyDowns.size());
    dump += StringPrintf(INDENT3 "MetaState: 0x%0x\n", mMetaState);
    dump += INDENT3 "KeyboardLayoutInfo: ";
    if (mKeyboardLayoutInfo) {
        dump += mKeyboardLayoutInfo->languageTag + ", " + mKeyboardLayoutInfo->layoutType + "\n";
    } else {
        dump += "<not set>\n";
    }
}

std::optional<DisplayViewport> KeyboardInputMapper::findViewport(
        const InputReaderConfiguration& readerConfig) {
    if (getDeviceContext().getAssociatedViewport()) {
        return getDeviceContext().getAssociatedViewport();
    }

    // No associated display defined, try to find default display if orientationAware.
    if (mParameters.orientationAware) {
        return readerConfig.getDisplayViewportByType(ViewportType::INTERNAL);
    }

    return std::nullopt;
}

std::list<NotifyArgs> KeyboardInputMapper::reconfigure(nsecs_t when,
                                                       const InputReaderConfiguration& config,
                                                       ConfigurationChanges changes) {
    std::list<NotifyArgs> out = InputMapper::reconfigure(when, config, changes);

    if (!changes.any()) { // first time only
        // Configure basic parameters.
        configureParameters();
    }

    if (!changes.any() || changes.test(InputReaderConfiguration::Change::DISPLAY_INFO)) {
        mViewport = findViewport(config);
    }

    if (!changes.any() ||
        changes.test(InputReaderConfiguration::Change::KEYBOARD_LAYOUT_ASSOCIATION)) {
        std::optional<KeyboardLayoutInfo> newKeyboardLayoutInfo =
                getValueByKey(config.keyboardLayoutAssociations, getDeviceContext().getLocation());
        if (mKeyboardLayoutInfo != newKeyboardLayoutInfo) {
            mKeyboardLayoutInfo = newKeyboardLayoutInfo;
            // Also update keyboard layout overlay as soon as we find the new layout info
            updateKeyboardLayoutOverlay();
            bumpGeneration();
        }
    }

    if (!changes.any() || changes.test(InputReaderConfiguration::Change::KEYBOARD_LAYOUTS)) {
        if (!getDeviceContext().getDeviceClasses().test(InputDeviceClass::VIRTUAL) &&
            updateKeyboardLayoutOverlay()) {
            bumpGeneration();
        }
    }
    return out;
}

bool KeyboardInputMapper::updateKeyboardLayoutOverlay() {
    std::shared_ptr<KeyCharacterMap> keyboardLayout =
            getDeviceContext()
                    .getContext()
                    ->getPolicy()
                    ->getKeyboardLayoutOverlay(getDeviceContext().getDeviceIdentifier(),
                                               getKeyboardLayoutInfo());
    return getDeviceContext().setKeyboardLayoutOverlay(keyboardLayout);
}

void KeyboardInputMapper::configureParameters() {
    const PropertyMap& config = getDeviceContext().getConfiguration();
    mParameters.orientationAware = config.getBool("keyboard.orientationAware").value_or(false);
    mParameters.handlesKeyRepeat = config.getBool("keyboard.handlesKeyRepeat").value_or(false);
    mParameters.doNotWakeByDefault = config.getBool("keyboard.doNotWakeByDefault").value_or(false);
}

void KeyboardInputMapper::dumpParameters(std::string& dump) const {
    dump += INDENT3 "Parameters:\n";
    dump += StringPrintf(INDENT4 "OrientationAware: %s\n", toString(mParameters.orientationAware));
    dump += StringPrintf(INDENT4 "HandlesKeyRepeat: %s\n", toString(mParameters.handlesKeyRepeat));
}

std::list<NotifyArgs> KeyboardInputMapper::reset(nsecs_t when) {
    std::list<NotifyArgs> out = cancelAllDownKeys(when);
    mHidUsageAccumulator.reset();

    resetLedState();

    out += InputMapper::reset(when);
    return out;
}

std::list<NotifyArgs> KeyboardInputMapper::process(const RawEvent* rawEvent) {
    std::list<NotifyArgs> out;
    mHidUsageAccumulator.process(*rawEvent);
    switch (rawEvent->type) {
        case EV_KEY: {
            int32_t scanCode = rawEvent->code;

            if (isSupportedScanCode(scanCode)) {
                out += processKey(rawEvent->when, rawEvent->readTime, rawEvent->value != 0,
                                  scanCode, mHidUsageAccumulator.consumeCurrentHidUsage());
            }
            break;
        }
    }
    return out;
}

std::list<NotifyArgs> KeyboardInputMapper::processKey(nsecs_t when, nsecs_t readTime, bool down,
                                                      int32_t scanCode, int32_t usageCode) {
    std::list<NotifyArgs> out;
    int32_t keyCode;
    int32_t keyMetaState;
    uint32_t policyFlags;
    int32_t flags = AKEY_EVENT_FLAG_FROM_SYSTEM;

    if (getDeviceContext().mapKey(scanCode, usageCode, mMetaState, &keyCode, &keyMetaState,
                                  &policyFlags)) {
        keyCode = AKEYCODE_UNKNOWN;
        keyMetaState = mMetaState;
        policyFlags = 0;
    }

    nsecs_t downTime = when;
    std::optional<size_t> keyDownIndex = findKeyDownIndex(scanCode);
    if (down) {
        // Rotate key codes according to orientation if needed.
        if (mParameters.orientationAware) {
            keyCode = rotateKeyCode(keyCode, getOrientation());
        }

        // Add key down.
        if (keyDownIndex) {
            // key repeat, be sure to use same keycode as before in case of rotation
            keyCode = mKeyDowns[*keyDownIndex].keyCode;
            downTime = mKeyDowns[*keyDownIndex].downTime;
            flags = mKeyDowns[*keyDownIndex].flags;
        } else {
            // key down
            if ((policyFlags & POLICY_FLAG_VIRTUAL) &&
                getContext()->shouldDropVirtualKey(when, keyCode, scanCode)) {
                return out;
            }
            if (policyFlags & POLICY_FLAG_GESTURE) {
                out += getDeviceContext().cancelTouch(when, readTime);
                flags |= AKEY_EVENT_FLAG_KEEP_TOUCH_MODE;
            }

            KeyDown keyDown;
            keyDown.keyCode = keyCode;
            keyDown.scanCode = scanCode;
            keyDown.downTime = when;
            keyDown.flags = flags;
            mKeyDowns.push_back(keyDown);
        }
        onKeyDownProcessed(downTime);
    } else {
        // Remove key down.
        if (keyDownIndex) {
            // key up, be sure to use same keycode as before in case of rotation
            keyCode = mKeyDowns[*keyDownIndex].keyCode;
            downTime = mKeyDowns[*keyDownIndex].downTime;
            flags = mKeyDowns[*keyDownIndex].flags;
            mKeyDowns.erase(mKeyDowns.begin() + *keyDownIndex);
        } else {
            // key was not actually down
            ALOGI("Dropping key up from device %s because the key was not down.  "
                  "keyCode=%d, scanCode=%d",
                  getDeviceName().c_str(), keyCode, scanCode);
            return out;
        }
    }

    if (updateMetaStateIfNeeded(keyCode, down)) {
        // If global meta state changed send it along with the key.
        // If it has not changed then we'll use what keymap gave us,
        // since key replacement logic might temporarily reset a few
        // meta bits for given key.
        keyMetaState = mMetaState;
    }

    // Any key down on an external keyboard should wake the device.
    // We don't do this for internal keyboards to prevent them from waking up in your pocket.
    // For internal keyboards and devices for which the default wake behavior is explicitly
    // prevented (e.g. TV remotes), the key layout file should specify the policy flags for each
    // wake key individually.
    if (down && getDeviceContext().isExternal() && !mParameters.doNotWakeByDefault &&
        !(mKeyboardType != AINPUT_KEYBOARD_TYPE_ALPHABETIC && isMediaKey(keyCode))) {
        policyFlags |= POLICY_FLAG_WAKE;
    }

    if (mParameters.handlesKeyRepeat) {
        policyFlags |= POLICY_FLAG_DISABLE_KEY_REPEAT;
    }

    out.emplace_back(NotifyKeyArgs(getContext()->getNextId(), when, readTime, getDeviceId(),
                                   mSource, getDisplayId(), policyFlags,
                                   down ? AKEY_EVENT_ACTION_DOWN : AKEY_EVENT_ACTION_UP, flags,
                                   keyCode, scanCode, keyMetaState, downTime));
    return out;
}

std::optional<size_t> KeyboardInputMapper::findKeyDownIndex(int32_t scanCode) {
    size_t n = mKeyDowns.size();
    for (size_t i = 0; i < n; i++) {
        if (mKeyDowns[i].scanCode == scanCode) {
            return i;
        }
    }
    return {};
}

int32_t KeyboardInputMapper::getKeyCodeState(uint32_t sourceMask, int32_t keyCode) {
    return getDeviceContext().getKeyCodeState(keyCode);
}

int32_t KeyboardInputMapper::getScanCodeState(uint32_t sourceMask, int32_t scanCode) {
    return getDeviceContext().getScanCodeState(scanCode);
}

int32_t KeyboardInputMapper::getKeyCodeForKeyLocation(int32_t locationKeyCode) const {
    return getDeviceContext().getKeyCodeForKeyLocation(locationKeyCode);
}

bool KeyboardInputMapper::markSupportedKeyCodes(uint32_t sourceMask,
                                                const std::vector<int32_t>& keyCodes,
                                                uint8_t* outFlags) {
    return getDeviceContext().markSupportedKeyCodes(keyCodes, outFlags);
}

int32_t KeyboardInputMapper::getMetaState() {
    return mMetaState;
}

bool KeyboardInputMapper::updateMetaState(int32_t keyCode) {
    if (!android::isMetaKey(keyCode) || !getDeviceContext().hasKeyCode(keyCode)) {
        return false;
    }

    updateMetaStateIfNeeded(keyCode, false);
    return true;
}

bool KeyboardInputMapper::updateMetaStateIfNeeded(int32_t keyCode, bool down) {
    int32_t oldMetaState = mMetaState;
    int32_t newMetaState = android::updateMetaState(keyCode, down, oldMetaState);
    int32_t metaStateChanged = oldMetaState ^ newMetaState;
    if (metaStateChanged) {
        mMetaState = newMetaState;
        constexpr int32_t allLedMetaState =
                AMETA_CAPS_LOCK_ON | AMETA_NUM_LOCK_ON | AMETA_SCROLL_LOCK_ON;
        if ((metaStateChanged & allLedMetaState) != 0) {
            getContext()->updateLedMetaState(newMetaState & allLedMetaState);
        }
        getContext()->updateGlobalMetaState();
    }

    return metaStateChanged;
}

void KeyboardInputMapper::resetLedState() {
    initializeLedState(mCapsLockLedState, ALED_CAPS_LOCK);
    initializeLedState(mNumLockLedState, ALED_NUM_LOCK);
    initializeLedState(mScrollLockLedState, ALED_SCROLL_LOCK);

    updateLedState(true);
}

void KeyboardInputMapper::initializeLedState(LedState& ledState, int32_t led) {
    ledState.avail = getDeviceContext().hasLed(led);
    ledState.on = false;
}

void KeyboardInputMapper::updateLedState(bool reset) {
    // Clear the local led state then union the global led state.
    mMetaState &= ~(AMETA_CAPS_LOCK_ON | AMETA_NUM_LOCK_ON | AMETA_SCROLL_LOCK_ON);
    mMetaState |= getContext()->getLedMetaState();

    constexpr int32_t META_NUM = 3;
    const std::vector<int32_t> keyCodes{AKEYCODE_CAPS_LOCK, AKEYCODE_NUM_LOCK,
                                        AKEYCODE_SCROLL_LOCK};
    const std::array<int32_t, META_NUM> metaCodes = {AMETA_CAPS_LOCK_ON, AMETA_NUM_LOCK_ON,
                                                     AMETA_SCROLL_LOCK_ON};
    std::array<uint8_t, META_NUM> flags = {0, 0, 0};
    bool hasKeyLayout = getDeviceContext().markSupportedKeyCodes(keyCodes, flags.data());
    // If the device doesn't have the physical meta key it shouldn't generate the corresponding
    // meta state.
    if (hasKeyLayout) {
        for (int i = 0; i < META_NUM; i++) {
            if (!flags[i]) {
                mMetaState &= ~metaCodes[i];
            }
        }
    }

    updateLedStateForModifier(mCapsLockLedState, ALED_CAPS_LOCK, AMETA_CAPS_LOCK_ON, reset);
    updateLedStateForModifier(mNumLockLedState, ALED_NUM_LOCK, AMETA_NUM_LOCK_ON, reset);
    updateLedStateForModifier(mScrollLockLedState, ALED_SCROLL_LOCK, AMETA_SCROLL_LOCK_ON, reset);
}

void KeyboardInputMapper::updateLedStateForModifier(LedState& ledState, int32_t led,
                                                    int32_t modifier, bool reset) {
    if (ledState.avail) {
        bool desiredState = (mMetaState & modifier) != 0;
        if (reset || ledState.on != desiredState) {
            getDeviceContext().setLedState(led, desiredState);
            ledState.on = desiredState;
        }
    }
}

std::optional<int32_t> KeyboardInputMapper::getAssociatedDisplayId() {
    if (mViewport) {
        return std::make_optional(mViewport->displayId);
    }
    return std::nullopt;
}

std::list<NotifyArgs> KeyboardInputMapper::cancelAllDownKeys(nsecs_t when) {
    std::list<NotifyArgs> out;
    size_t n = mKeyDowns.size();
    for (size_t i = 0; i < n; i++) {
        out.emplace_back(NotifyKeyArgs(getContext()->getNextId(), when,
                                       systemTime(SYSTEM_TIME_MONOTONIC), getDeviceId(), mSource,
                                       getDisplayId(), /*policyFlags=*/0, AKEY_EVENT_ACTION_UP,
                                       mKeyDowns[i].flags | AKEY_EVENT_FLAG_CANCELED,
                                       mKeyDowns[i].keyCode, mKeyDowns[i].scanCode, AMETA_NONE,
                                       mKeyDowns[i].downTime));
    }
    mKeyDowns.clear();
    mMetaState = AMETA_NONE;
    return out;
}

void KeyboardInputMapper::onKeyDownProcessed(nsecs_t downTime) {
    InputReaderContext& context = *getContext();
    context.setLastKeyDownTimestamp(downTime);
    if (context.isPreventingTouchpadTaps()) {
        // avoid pinging java service unnecessarily, just fade pointer again if it became visible
        context.fadePointer();
        return;
    }
    // Ignore meta keys or multiple simultaneous down keys as they are likely to be keyboard
    // shortcuts
    bool shouldHideCursor = mKeyDowns.size() == 1 && !isMetaKey(mKeyDowns[0].keyCode);
    if (shouldHideCursor && context.getPolicy()->isInputMethodConnectionActive()) {
        context.fadePointer();
        context.setPreventingTouchpadTaps(true);
    }
}

} // namespace android
