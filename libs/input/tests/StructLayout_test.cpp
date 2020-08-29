/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <input/InputTransport.h>
#include <input/Input.h>

namespace android {

#define CHECK_OFFSET(type, member, expected_offset) \
  static_assert((offsetof(type, member) == (expected_offset)), "")

struct Foo {
  uint32_t dummy;
  PointerCoords coords;
};

void TestPointerCoordsAlignment() {
  CHECK_OFFSET(Foo, coords, 8);
}

void TestInputMessageAlignment() {
  CHECK_OFFSET(InputMessage, body, 8);

  CHECK_OFFSET(InputMessage::Body::Key, seq, 0);
  CHECK_OFFSET(InputMessage::Body::Key, eventId, 4);
  CHECK_OFFSET(InputMessage::Body::Key, eventTime, 8);
  CHECK_OFFSET(InputMessage::Body::Key, deviceId, 16);
  CHECK_OFFSET(InputMessage::Body::Key, source, 20);
  CHECK_OFFSET(InputMessage::Body::Key, displayId, 24);
  CHECK_OFFSET(InputMessage::Body::Key, hmac, 28);
  CHECK_OFFSET(InputMessage::Body::Key, action, 60);
  CHECK_OFFSET(InputMessage::Body::Key, flags, 64);
  CHECK_OFFSET(InputMessage::Body::Key, keyCode, 68);
  CHECK_OFFSET(InputMessage::Body::Key, scanCode, 72);
  CHECK_OFFSET(InputMessage::Body::Key, metaState, 76);
  CHECK_OFFSET(InputMessage::Body::Key, repeatCount, 80);
  CHECK_OFFSET(InputMessage::Body::Key, downTime, 88);

  CHECK_OFFSET(InputMessage::Body::Motion, seq, 0);
  CHECK_OFFSET(InputMessage::Body::Motion, eventId, 4);
  CHECK_OFFSET(InputMessage::Body::Motion, eventTime, 8);
  CHECK_OFFSET(InputMessage::Body::Motion, deviceId, 16);
  CHECK_OFFSET(InputMessage::Body::Motion, source, 20);
  CHECK_OFFSET(InputMessage::Body::Motion, displayId, 24);
  CHECK_OFFSET(InputMessage::Body::Motion, hmac, 28);
  CHECK_OFFSET(InputMessage::Body::Motion, action, 60);
  CHECK_OFFSET(InputMessage::Body::Motion, actionButton, 64);
  CHECK_OFFSET(InputMessage::Body::Motion, flags, 68);
  CHECK_OFFSET(InputMessage::Body::Motion, metaState, 72);
  CHECK_OFFSET(InputMessage::Body::Motion, buttonState, 76);
  CHECK_OFFSET(InputMessage::Body::Motion, classification, 80);
  CHECK_OFFSET(InputMessage::Body::Motion, edgeFlags, 84);
  CHECK_OFFSET(InputMessage::Body::Motion, downTime, 88);
  CHECK_OFFSET(InputMessage::Body::Motion, xScale, 96);
  CHECK_OFFSET(InputMessage::Body::Motion, yScale, 100);
  CHECK_OFFSET(InputMessage::Body::Motion, xOffset, 104);
  CHECK_OFFSET(InputMessage::Body::Motion, yOffset, 108);
  CHECK_OFFSET(InputMessage::Body::Motion, xPrecision, 112);
  CHECK_OFFSET(InputMessage::Body::Motion, yPrecision, 116);
  CHECK_OFFSET(InputMessage::Body::Motion, xCursorPosition, 120);
  CHECK_OFFSET(InputMessage::Body::Motion, yCursorPosition, 124);
  CHECK_OFFSET(InputMessage::Body::Motion, pointerCount, 128);
  CHECK_OFFSET(InputMessage::Body::Motion, pointers, 136);

  CHECK_OFFSET(InputMessage::Body::Focus, seq, 0);
  CHECK_OFFSET(InputMessage::Body::Focus, eventId, 4);
  CHECK_OFFSET(InputMessage::Body::Focus, hasFocus, 12);
  CHECK_OFFSET(InputMessage::Body::Focus, inTouchMode, 14);

  CHECK_OFFSET(InputMessage::Body::Finished, seq, 0);
  CHECK_OFFSET(InputMessage::Body::Finished, handled, 4);
}

void TestHeaderSize() {
    static_assert(sizeof(InputMessage::Header) == 8);
}

/**
 * We cannot use the Body::size() method here because it is not static for
 * the Motion type, where "pointerCount" variable affects the size and can change at runtime.
 */
void TestBodySize() {
    static_assert(sizeof(InputMessage::Body::Key) == 96);
    static_assert(sizeof(InputMessage::Body::Motion) ==
                  offsetof(InputMessage::Body::Motion, pointers) +
                          sizeof(InputMessage::Body::Motion::Pointer) * MAX_POINTERS);
    static_assert(sizeof(InputMessage::Body::Finished) == 8);
    static_assert(sizeof(InputMessage::Body::Focus) == 16);
}

// --- VerifiedInputEvent ---
// Ensure that VerifiedInputEvent, VerifiedKeyEvent, VerifiedMotionEvent are packed.
// We will treat them as byte collections when signing them. There should not be any uninitialized
// data in-between fields. Otherwise, the padded data will affect the hmac value and verifications
// will fail.

void TestVerifiedEventSize() {
    // VerifiedInputEvent
    constexpr size_t VERIFIED_INPUT_EVENT_SIZE = sizeof(VerifiedInputEvent::type) +
            sizeof(VerifiedInputEvent::deviceId) + sizeof(VerifiedInputEvent::eventTimeNanos) +
            sizeof(VerifiedInputEvent::source) + sizeof(VerifiedInputEvent::displayId);
    static_assert(sizeof(VerifiedInputEvent) == VERIFIED_INPUT_EVENT_SIZE);

    // VerifiedKeyEvent
    constexpr size_t VERIFIED_KEY_EVENT_SIZE = VERIFIED_INPUT_EVENT_SIZE +
            sizeof(VerifiedKeyEvent::action) + sizeof(VerifiedKeyEvent::downTimeNanos) +
            sizeof(VerifiedKeyEvent::flags) + sizeof(VerifiedKeyEvent::keyCode) +
            sizeof(VerifiedKeyEvent::scanCode) + sizeof(VerifiedKeyEvent::metaState) +
            sizeof(VerifiedKeyEvent::repeatCount);
    static_assert(sizeof(VerifiedKeyEvent) == VERIFIED_KEY_EVENT_SIZE);

    // VerifiedMotionEvent
    constexpr size_t VERIFIED_MOTION_EVENT_SIZE = VERIFIED_INPUT_EVENT_SIZE +
            sizeof(VerifiedMotionEvent::rawX) + sizeof(VerifiedMotionEvent::rawY) +
            sizeof(VerifiedMotionEvent::actionMasked) + sizeof(VerifiedMotionEvent::downTimeNanos) +
            sizeof(VerifiedMotionEvent::flags) + sizeof(VerifiedMotionEvent::metaState) +
            sizeof(VerifiedMotionEvent::buttonState);
    static_assert(sizeof(VerifiedMotionEvent) == VERIFIED_MOTION_EVENT_SIZE);
}

} // namespace android
