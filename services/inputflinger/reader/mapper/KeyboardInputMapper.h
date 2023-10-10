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

#pragma once

#include "HidUsageAccumulator.h"
#include "InputMapper.h"

namespace android {

class KeyboardInputMapper : public InputMapper {
public:
    template <class T, class... Args>
    friend std::unique_ptr<T> createInputMapper(InputDeviceContext& deviceContext,
                                                const InputReaderConfiguration& readerConfig,
                                                Args... args);
    ~KeyboardInputMapper() override = default;

    uint32_t getSources() const override;
    void populateDeviceInfo(InputDeviceInfo& deviceInfo) override;
    void dump(std::string& dump) override;
    [[nodiscard]] std::list<NotifyArgs> reconfigure(nsecs_t when,
                                                    const InputReaderConfiguration& config,
                                                    ConfigurationChanges changes) override;
    [[nodiscard]] std::list<NotifyArgs> reset(nsecs_t when) override;
    [[nodiscard]] std::list<NotifyArgs> process(const RawEvent* rawEvent) override;

    int32_t getKeyCodeState(uint32_t sourceMask, int32_t keyCode) override;
    int32_t getScanCodeState(uint32_t sourceMask, int32_t scanCode) override;
    bool markSupportedKeyCodes(uint32_t sourceMask, const std::vector<int32_t>& keyCodes,
                               uint8_t* outFlags) override;
    int32_t getKeyCodeForKeyLocation(int32_t locationKeyCode) const override;

    int32_t getMetaState() override;
    bool updateMetaState(int32_t keyCode) override;
    std::optional<int32_t> getAssociatedDisplayId() override;
    void updateLedState(bool reset) override;

private:
    // The current viewport.
    std::optional<DisplayViewport> mViewport{};

    struct KeyDown {
        nsecs_t downTime{};
        int32_t keyCode{};
        int32_t scanCode{};
        int32_t flags{};
    };

    uint32_t mSource{};
    int32_t mKeyboardType{};
    std::optional<KeyboardLayoutInfo> mKeyboardLayoutInfo;

    std::vector<KeyDown> mKeyDowns{}; // keys that are down
    int32_t mMetaState{};

    HidUsageAccumulator mHidUsageAccumulator;

    struct LedState {
        bool avail{}; // led is available
        bool on{};    // we think the led is currently on
    };
    LedState mCapsLockLedState{};
    LedState mNumLockLedState{};
    LedState mScrollLockLedState{};

    // Immutable configuration parameters.
    struct Parameters {
        bool orientationAware{};
        bool handlesKeyRepeat{};
        bool doNotWakeByDefault{};
    } mParameters{};

    KeyboardInputMapper(InputDeviceContext& deviceContext,
                        const InputReaderConfiguration& readerConfig, uint32_t source,
                        int32_t keyboardType);
    void configureParameters();
    void dumpParameters(std::string& dump) const;

    ui::Rotation getOrientation();
    int32_t getDisplayId();

    [[nodiscard]] std::list<NotifyArgs> processKey(nsecs_t when, nsecs_t readTime, bool down,
                                                   int32_t scanCode, int32_t usageCode);

    bool updateMetaStateIfNeeded(int32_t keyCode, bool down);

    std::optional<size_t> findKeyDownIndex(int32_t scanCode);
    std::optional<KeyboardLayoutInfo> getKeyboardLayoutInfo() const;
    bool updateKeyboardLayoutOverlay();

    void resetLedState();
    void initializeLedState(LedState& ledState, int32_t led);
    void updateLedStateForModifier(LedState& ledState, int32_t led, int32_t modifier, bool reset);
    std::optional<DisplayViewport> findViewport(const InputReaderConfiguration& readerConfig);
    [[nodiscard]] std::list<NotifyArgs> cancelAllDownKeys(nsecs_t when);
    void onKeyDownProcessed(nsecs_t downTime);
};

} // namespace android
