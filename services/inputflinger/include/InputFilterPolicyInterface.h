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

#pragma once

namespace android {

/**
 * The InputFilter policy interface.
 *
 * This is the interface that InputFilter uses to talk to Input Manager and other system components.
 */
class InputFilterPolicyInterface {
public:
    virtual ~InputFilterPolicyInterface() = default;

    /**
     * A callback to notify about sticky modifier state changes when Sticky keys feature is enabled.
     *
     * modifierState: Current sticky modifier state which will be sent with all subsequent
     * KeyEvents. This only includes modifiers that can be 'Sticky' which includes: Meta, Ctrl,
     * Shift, Alt and AltGr.
     *
     * lockedModifierState: Current locked modifier state representing modifiers that don't get
     * cleared after non-modifier key press. This only includes modifiers that can be 'Sticky' which
     * includes: Meta, Ctrl, Shift, Alt and AltGr.
     *
     * For more information {@see sticky_keys_filter.rs}
     */
    virtual void notifyStickyModifierStateChanged(uint32_t modifierState,
                                                  uint32_t lockedModifierState) = 0;
};

} // namespace android
