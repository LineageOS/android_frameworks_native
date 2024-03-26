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

#define LOG_TAG "Input"
//#define LOG_NDEBUG 0

#include <attestation/HmacKeyManager.h>
#include <cutils/compiler.h>
#include <inttypes.h>
#include <string.h>
#include <optional>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <cutils/compiler.h>
#include <input/DisplayViewport.h>
#include <input/Input.h>
#include <input/InputDevice.h>
#include <input/InputEventLabels.h>

#include <binder/Parcel.h>
#if defined(__ANDROID__)
#include <sys/random.h>
#endif

using android::base::StringPrintf;

namespace android {

namespace {

bool shouldDisregardTransformation(uint32_t source) {
    // Do not apply any transformations to axes from joysticks, touchpads, or relative mice.
    return isFromSource(source, AINPUT_SOURCE_CLASS_JOYSTICK) ||
            isFromSource(source, AINPUT_SOURCE_CLASS_POSITION) ||
            isFromSource(source, AINPUT_SOURCE_MOUSE_RELATIVE);
}

bool shouldDisregardOffset(uint32_t source) {
    // Pointer events are the only type of events that refer to absolute coordinates on the display,
    // so we should apply the entire window transform. For other types of events, we should make
    // sure to not apply the window translation/offset.
    return !isFromSource(source, AINPUT_SOURCE_CLASS_POINTER);
}

int32_t resolveActionForSplitMotionEvent(
        int32_t action, int32_t flags, const std::vector<PointerProperties>& pointerProperties,
        const std::vector<PointerProperties>& splitPointerProperties) {
    LOG_ALWAYS_FATAL_IF(splitPointerProperties.empty());
    const auto maskedAction = MotionEvent::getActionMasked(action);
    if (maskedAction != AMOTION_EVENT_ACTION_POINTER_DOWN &&
        maskedAction != AMOTION_EVENT_ACTION_POINTER_UP) {
        // The action is unaffected by splitting this motion event.
        return action;
    }
    const auto actionIndex = MotionEvent::getActionIndex(action);
    if (CC_UNLIKELY(actionIndex >= pointerProperties.size())) {
        LOG(FATAL) << "Action index is out of bounds, index: " << actionIndex;
    }

    const auto affectedPointerId = pointerProperties[actionIndex].id;
    std::optional<uint32_t> splitActionIndex;
    for (uint32_t i = 0; i < splitPointerProperties.size(); i++) {
        if (affectedPointerId == splitPointerProperties[i].id) {
            splitActionIndex = i;
            break;
        }
    }
    if (!splitActionIndex.has_value()) {
        // The affected pointer is not part of the split motion event.
        return AMOTION_EVENT_ACTION_MOVE;
    }

    if (splitPointerProperties.size() > 1) {
        return maskedAction | (*splitActionIndex << AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT);
    }

    if (maskedAction == AMOTION_EVENT_ACTION_POINTER_UP) {
        return ((flags & AMOTION_EVENT_FLAG_CANCELED) != 0) ? AMOTION_EVENT_ACTION_CANCEL
                                                            : AMOTION_EVENT_ACTION_UP;
    }
    return AMOTION_EVENT_ACTION_DOWN;
}

float transformOrientation(const ui::Transform& transform, const PointerCoords& coords,
                           int32_t motionEventFlags) {
    if ((motionEventFlags & AMOTION_EVENT_PRIVATE_FLAG_SUPPORTS_ORIENTATION) == 0) {
        return 0;
    }

    const bool isDirectionalAngle =
            (motionEventFlags & AMOTION_EVENT_PRIVATE_FLAG_SUPPORTS_DIRECTIONAL_ORIENTATION) != 0;

    return transformAngle(transform, coords.getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION),
                          isDirectionalAngle);
}

} // namespace

const char* motionClassificationToString(MotionClassification classification) {
    switch (classification) {
        case MotionClassification::NONE:
            return "NONE";
        case MotionClassification::AMBIGUOUS_GESTURE:
            return "AMBIGUOUS_GESTURE";
        case MotionClassification::DEEP_PRESS:
            return "DEEP_PRESS";
        case MotionClassification::TWO_FINGER_SWIPE:
            return "TWO_FINGER_SWIPE";
        case MotionClassification::MULTI_FINGER_SWIPE:
            return "MULTI_FINGER_SWIPE";
        case MotionClassification::PINCH:
            return "PINCH";
    }
}

// --- IdGenerator ---
#if defined(__ANDROID__)
[[maybe_unused]]
#endif
static status_t
getRandomBytes(uint8_t* data, size_t size) {
    int ret = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (ret == -1) {
        return -errno;
    }

    base::unique_fd fd(ret);
    if (!base::ReadFully(fd, data, size)) {
        return -errno;
    }
    return OK;
}

IdGenerator::IdGenerator(Source source) : mSource(source) {}

int32_t IdGenerator::nextId() const {
    constexpr uint32_t SEQUENCE_NUMBER_MASK = ~SOURCE_MASK;
    int32_t id = 0;

#if defined(__ANDROID__)
    // On device, prefer 'getrandom' to '/dev/urandom' because it's faster.
    constexpr size_t BUF_LEN = sizeof(id);
    size_t totalBytes = 0;
    while (totalBytes < BUF_LEN) {
        ssize_t bytes = TEMP_FAILURE_RETRY(getrandom(&id, BUF_LEN, GRND_NONBLOCK));
        if (CC_UNLIKELY(bytes < 0)) {
            ALOGW("Failed to fill in random number for sequence number: %s.", strerror(errno));
            id = 0;
            break;
        }
        totalBytes += bytes;
    }
#else
#if defined(__linux__)
    // On host, <sys/random.h> / GRND_NONBLOCK is not available
    while (true) {
        status_t result = getRandomBytes(reinterpret_cast<uint8_t*>(&id), sizeof(id));
        if (result == OK) {
            break;
        }
    }
#endif // __linux__
#endif // __ANDROID__
    return (id & SEQUENCE_NUMBER_MASK) | static_cast<int32_t>(mSource);
}

// --- InputEvent ---

// Due to precision limitations when working with floating points, transforming - namely
// scaling - floating points can lead to minute errors. We round transformed values to approximately
// three decimal places so that values like 0.99997 show up as 1.0.
inline float roundTransformedCoords(float val) {
    // Use a power to two to approximate three decimal places to potentially reduce some cycles.
    // This should be at least as precise as MotionEvent::ROUNDING_PRECISION.
    return std::round(val * 1024.f) / 1024.f;
}

inline vec2 roundTransformedCoords(vec2 p) {
    return {roundTransformedCoords(p.x), roundTransformedCoords(p.y)};
}

vec2 transformWithoutTranslation(const ui::Transform& transform, const vec2& xy) {
    const vec2 transformedXy = transform.transform(xy);
    const vec2 transformedOrigin = transform.transform(0, 0);
    return roundTransformedCoords(transformedXy - transformedOrigin);
}

float transformAngle(const ui::Transform& transform, float angleRadians, bool isDirectional) {
    // Construct and transform a vector oriented at the specified clockwise angle from vertical.
    // Coordinate system: down is increasing Y, right is increasing X.
    float x = sinf(angleRadians);
    float y = -cosf(angleRadians);
    vec2 transformedPoint = transform.transform(x, y);

    // Determine how the origin is transformed by the matrix so that we
    // can transform orientation vectors.
    const vec2 origin = transform.transform(0, 0);

    transformedPoint.x -= origin.x;
    transformedPoint.y -= origin.y;

    if (!isDirectional && transformedPoint.y > 0) {
        // Limit the range of atan2f to [-pi/2, pi/2] by reversing the direction of the vector.
        transformedPoint *= -1;
    }

    // Derive the transformed vector's clockwise angle from vertical.
    // The return value of atan2f is in range [-pi, pi] which conforms to the orientation API.
    return atan2f(transformedPoint.x, -transformedPoint.y);
}

std::string inputEventSourceToString(int32_t source) {
    if (source == AINPUT_SOURCE_UNKNOWN) {
        return "UNKNOWN";
    }
    if (source == static_cast<int32_t>(AINPUT_SOURCE_ANY)) {
        return "ANY";
    }
    static const std::map<int32_t, const char*> SOURCES{
            {AINPUT_SOURCE_KEYBOARD, "KEYBOARD"},
            {AINPUT_SOURCE_DPAD, "DPAD"},
            {AINPUT_SOURCE_GAMEPAD, "GAMEPAD"},
            {AINPUT_SOURCE_TOUCHSCREEN, "TOUCHSCREEN"},
            {AINPUT_SOURCE_MOUSE, "MOUSE"},
            {AINPUT_SOURCE_STYLUS, "STYLUS"},
            {AINPUT_SOURCE_BLUETOOTH_STYLUS, "BLUETOOTH_STYLUS"},
            {AINPUT_SOURCE_TRACKBALL, "TRACKBALL"},
            {AINPUT_SOURCE_MOUSE_RELATIVE, "MOUSE_RELATIVE"},
            {AINPUT_SOURCE_TOUCHPAD, "TOUCHPAD"},
            {AINPUT_SOURCE_TOUCH_NAVIGATION, "TOUCH_NAVIGATION"},
            {AINPUT_SOURCE_JOYSTICK, "JOYSTICK"},
            {AINPUT_SOURCE_HDMI, "HDMI"},
            {AINPUT_SOURCE_SENSOR, "SENSOR"},
            {AINPUT_SOURCE_ROTARY_ENCODER, "ROTARY_ENCODER"},
    };
    std::string result;
    for (const auto& [source_entry, str] : SOURCES) {
        if ((source & source_entry) == source_entry) {
            if (!result.empty()) {
                result += " | ";
            }
            result += str;
        }
    }
    if (result.empty()) {
        result = StringPrintf("0x%08x", source);
    }
    return result;
}

bool isFromSource(uint32_t source, uint32_t test) {
    return (source & test) == test;
}

bool isStylusToolType(ToolType toolType) {
    return toolType == ToolType::STYLUS || toolType == ToolType::ERASER;
}

bool isStylusEvent(uint32_t source, const std::vector<PointerProperties>& properties) {
    if (!isFromSource(source, AINPUT_SOURCE_STYLUS)) {
        return false;
    }
    // Need at least one stylus pointer for this event to be considered a stylus event
    for (const PointerProperties& pointerProperties : properties) {
        if (isStylusToolType(pointerProperties.toolType)) {
            return true;
        }
    }
    return false;
}

VerifiedKeyEvent verifiedKeyEventFromKeyEvent(const KeyEvent& event) {
    return {{VerifiedInputEvent::Type::KEY, event.getDeviceId(), event.getEventTime(),
             event.getSource(), event.getDisplayId()},
            event.getAction(),
            event.getFlags() & VERIFIED_KEY_EVENT_FLAGS,
            event.getDownTime(),
            event.getKeyCode(),
            event.getScanCode(),
            event.getMetaState(),
            event.getRepeatCount()};
}

VerifiedMotionEvent verifiedMotionEventFromMotionEvent(const MotionEvent& event) {
    return {{VerifiedInputEvent::Type::MOTION, event.getDeviceId(), event.getEventTime(),
             event.getSource(), event.getDisplayId()},
            event.getRawX(0),
            event.getRawY(0),
            event.getActionMasked(),
            event.getFlags() & VERIFIED_MOTION_EVENT_FLAGS,
            event.getDownTime(),
            event.getMetaState(),
            event.getButtonState()};
}

void InputEvent::initialize(int32_t id, int32_t deviceId, uint32_t source,
                            ui::LogicalDisplayId displayId, std::array<uint8_t, 32> hmac) {
    mId = id;
    mDeviceId = deviceId;
    mSource = source;
    mDisplayId = displayId;
    mHmac = hmac;
}

void InputEvent::initialize(const InputEvent& from) {
    mId = from.mId;
    mDeviceId = from.mDeviceId;
    mSource = from.mSource;
    mDisplayId = from.mDisplayId;
    mHmac = from.mHmac;
}

int32_t InputEvent::nextId() {
    static IdGenerator idGen(IdGenerator::Source::OTHER);
    return idGen.nextId();
}

std::ostream& operator<<(std::ostream& out, const InputEvent& event) {
    switch (event.getType()) {
        case InputEventType::KEY: {
            const KeyEvent& keyEvent = static_cast<const KeyEvent&>(event);
            out << keyEvent;
            return out;
        }
        case InputEventType::MOTION: {
            const MotionEvent& motionEvent = static_cast<const MotionEvent&>(event);
            out << motionEvent;
            return out;
        }
        case InputEventType::FOCUS: {
            out << "FocusEvent";
            return out;
        }
        case InputEventType::CAPTURE: {
            out << "CaptureEvent";
            return out;
        }
        case InputEventType::DRAG: {
            out << "DragEvent";
            return out;
        }
        case InputEventType::TOUCH_MODE: {
            out << "TouchModeEvent";
            return out;
        }
    }
}

// --- KeyEvent ---

const char* KeyEvent::getLabel(int32_t keyCode) {
    return InputEventLookup::getLabelByKeyCode(keyCode);
}

std::optional<int> KeyEvent::getKeyCodeFromLabel(const char* label) {
    return InputEventLookup::getKeyCodeByLabel(label);
}

void KeyEvent::initialize(int32_t id, int32_t deviceId, uint32_t source,
                          ui::LogicalDisplayId displayId, std::array<uint8_t, 32> hmac,
                          int32_t action, int32_t flags, int32_t keyCode, int32_t scanCode,
                          int32_t metaState, int32_t repeatCount, nsecs_t downTime,
                          nsecs_t eventTime) {
    InputEvent::initialize(id, deviceId, source, displayId, hmac);
    mAction = action;
    mFlags = flags;
    mKeyCode = keyCode;
    mScanCode = scanCode;
    mMetaState = metaState;
    mRepeatCount = repeatCount;
    mDownTime = downTime;
    mEventTime = eventTime;
}

void KeyEvent::initialize(const KeyEvent& from) {
    InputEvent::initialize(from);
    mAction = from.mAction;
    mFlags = from.mFlags;
    mKeyCode = from.mKeyCode;
    mScanCode = from.mScanCode;
    mMetaState = from.mMetaState;
    mRepeatCount = from.mRepeatCount;
    mDownTime = from.mDownTime;
    mEventTime = from.mEventTime;
}

const char* KeyEvent::actionToString(int32_t action) {
    // Convert KeyEvent action to string
    switch (action) {
        case AKEY_EVENT_ACTION_DOWN:
            return "DOWN";
        case AKEY_EVENT_ACTION_UP:
            return "UP";
        case AKEY_EVENT_ACTION_MULTIPLE:
            return "MULTIPLE";
    }
    return "UNKNOWN";
}

std::ostream& operator<<(std::ostream& out, const KeyEvent& event) {
    out << "KeyEvent { action=" << KeyEvent::actionToString(event.getAction());

    out << ", keycode=" << event.getKeyCode() << "(" << KeyEvent::getLabel(event.getKeyCode())
        << ")";

    if (event.getMetaState() != 0) {
        out << ", metaState=" << event.getMetaState();
    }

    out << ", eventTime=" << event.getEventTime();
    out << ", downTime=" << event.getDownTime();
    out << ", flags=" << std::hex << event.getFlags() << std::dec;
    out << ", repeatCount=" << event.getRepeatCount();
    out << ", deviceId=" << event.getDeviceId();
    out << ", source=" << inputEventSourceToString(event.getSource());
    out << ", displayId=" << event.getDisplayId();
    out << ", eventId=0x" << std::hex << event.getId() << std::dec;
    out << "}";
    return out;
}

std::ostream& operator<<(std::ostream& out, const PointerProperties& properties) {
    out << "Pointer(id=" << properties.id << ", " << ftl::enum_string(properties.toolType) << ")";
    return out;
}

// --- PointerCoords ---

float PointerCoords::getAxisValue(int32_t axis) const {
    if (axis < 0 || axis > 63 || !BitSet64::hasBit(bits, axis)){
        return 0;
    }
    return values[BitSet64::getIndexOfBit(bits, axis)];
}

status_t PointerCoords::setAxisValue(int32_t axis, float value) {
    if (axis < 0 || axis > 63) {
        return NAME_NOT_FOUND;
    }

    uint32_t index = BitSet64::getIndexOfBit(bits, axis);
    if (!BitSet64::hasBit(bits, axis)) {
        if (value == 0) {
            return OK; // axes with value 0 do not need to be stored
        }

        uint32_t count = BitSet64::count(bits);
        if (count >= MAX_AXES) {
            tooManyAxes(axis);
            return NO_MEMORY;
        }
        BitSet64::markBit(bits, axis);
        for (uint32_t i = count; i > index; i--) {
            values[i] = values[i - 1];
        }
    }

    values[index] = value;
    return OK;
}

static inline void scaleAxisValue(PointerCoords& c, int axis, float scaleFactor) {
    float value = c.getAxisValue(axis);
    if (value != 0) {
        c.setAxisValue(axis, value * scaleFactor);
    }
}

void PointerCoords::scale(float globalScaleFactor, float windowXScale, float windowYScale) {
    // No need to scale pressure or size since they are normalized.
    // No need to scale orientation since it is meaningless to do so.

    // If there is a global scale factor, it is included in the windowX/YScale
    // so we don't need to apply it twice to the X/Y axes.
    // However we don't want to apply any windowXYScale not included in the global scale
    // to the TOUCH_MAJOR/MINOR coordinates.
    scaleAxisValue(*this, AMOTION_EVENT_AXIS_X, windowXScale);
    scaleAxisValue(*this, AMOTION_EVENT_AXIS_Y, windowYScale);
    scaleAxisValue(*this, AMOTION_EVENT_AXIS_TOUCH_MAJOR, globalScaleFactor);
    scaleAxisValue(*this, AMOTION_EVENT_AXIS_TOUCH_MINOR, globalScaleFactor);
    scaleAxisValue(*this, AMOTION_EVENT_AXIS_TOOL_MAJOR, globalScaleFactor);
    scaleAxisValue(*this, AMOTION_EVENT_AXIS_TOOL_MINOR, globalScaleFactor);
    scaleAxisValue(*this, AMOTION_EVENT_AXIS_RELATIVE_X, windowXScale);
    scaleAxisValue(*this, AMOTION_EVENT_AXIS_RELATIVE_Y, windowYScale);
}

status_t PointerCoords::readFromParcel(Parcel* parcel) {
    bits = parcel->readInt64();

    uint32_t count = BitSet64::count(bits);
    if (count > MAX_AXES) {
        return BAD_VALUE;
    }

    for (uint32_t i = 0; i < count; i++) {
        values[i] = parcel->readFloat();
    }

    isResampled = parcel->readBool();
    return OK;
}

status_t PointerCoords::writeToParcel(Parcel* parcel) const {
    parcel->writeInt64(bits);

    uint32_t count = BitSet64::count(bits);
    for (uint32_t i = 0; i < count; i++) {
        parcel->writeFloat(values[i]);
    }

    parcel->writeBool(isResampled);
    return OK;
}

void PointerCoords::tooManyAxes(int axis) {
    ALOGW("Could not set value for axis %d because the PointerCoords structure is full and "
            "cannot contain more than %d axis values.", axis, int(MAX_AXES));
}

bool PointerCoords::operator==(const PointerCoords& other) const {
    if (bits != other.bits) {
        return false;
    }
    uint32_t count = BitSet64::count(bits);
    for (uint32_t i = 0; i < count; i++) {
        if (values[i] != other.values[i]) {
            return false;
        }
    }
    if (isResampled != other.isResampled) {
        return false;
    }
    return true;
}

// --- PointerProperties ---

void PointerProperties::copyFrom(const PointerProperties& other) {
    id = other.id;
    toolType = other.toolType;
}

// --- MotionEvent ---

void MotionEvent::initialize(int32_t id, int32_t deviceId, uint32_t source,
                             ui::LogicalDisplayId displayId, std::array<uint8_t, 32> hmac,
                             int32_t action, int32_t actionButton, int32_t flags, int32_t edgeFlags,
                             int32_t metaState, int32_t buttonState,
                             MotionClassification classification, const ui::Transform& transform,
                             float xPrecision, float yPrecision, float rawXCursorPosition,
                             float rawYCursorPosition, const ui::Transform& rawTransform,
                             nsecs_t downTime, nsecs_t eventTime, size_t pointerCount,
                             const PointerProperties* pointerProperties,
                             const PointerCoords* pointerCoords) {
    InputEvent::initialize(id, deviceId, source, displayId, hmac);
    mAction = action;
    mActionButton = actionButton;
    mFlags = flags;
    mEdgeFlags = edgeFlags;
    mMetaState = metaState;
    mButtonState = buttonState;
    mClassification = classification;
    mTransform = transform;
    mXPrecision = xPrecision;
    mYPrecision = yPrecision;
    mRawXCursorPosition = rawXCursorPosition;
    mRawYCursorPosition = rawYCursorPosition;
    mRawTransform = rawTransform;
    mDownTime = downTime;
    mPointerProperties.clear();
    mPointerProperties.insert(mPointerProperties.end(), &pointerProperties[0],
                              &pointerProperties[pointerCount]);
    mSampleEventTimes.clear();
    mSamplePointerCoords.clear();
    addSample(eventTime, pointerCoords);
}

void MotionEvent::copyFrom(const MotionEvent* other, bool keepHistory) {
    InputEvent::initialize(other->mId, other->mDeviceId, other->mSource, other->mDisplayId,
                           other->mHmac);
    mAction = other->mAction;
    mActionButton = other->mActionButton;
    mFlags = other->mFlags;
    mEdgeFlags = other->mEdgeFlags;
    mMetaState = other->mMetaState;
    mButtonState = other->mButtonState;
    mClassification = other->mClassification;
    mTransform = other->mTransform;
    mXPrecision = other->mXPrecision;
    mYPrecision = other->mYPrecision;
    mRawXCursorPosition = other->mRawXCursorPosition;
    mRawYCursorPosition = other->mRawYCursorPosition;
    mRawTransform = other->mRawTransform;
    mDownTime = other->mDownTime;
    mPointerProperties = other->mPointerProperties;

    if (keepHistory) {
        mSampleEventTimes = other->mSampleEventTimes;
        mSamplePointerCoords = other->mSamplePointerCoords;
    } else {
        mSampleEventTimes.clear();
        mSampleEventTimes.push_back(other->getEventTime());
        mSamplePointerCoords.clear();
        size_t pointerCount = other->getPointerCount();
        size_t historySize = other->getHistorySize();
        mSamplePointerCoords
                .insert(mSamplePointerCoords.end(),
                        &other->mSamplePointerCoords[historySize * pointerCount],
                        &other->mSamplePointerCoords[historySize * pointerCount + pointerCount]);
    }
}

void MotionEvent::splitFrom(const android::MotionEvent& other,
                            std::bitset<MAX_POINTER_ID + 1> splitPointerIds, int32_t newEventId) {
    // TODO(b/327503168): The down time should be a parameter to the split function, because only
    //   the caller can know when the first event went down on the target.
    const nsecs_t splitDownTime = other.mDownTime;

    auto [action, pointerProperties, pointerCoords] =
            split(other.getAction(), other.getFlags(), other.getHistorySize(),
                  other.mPointerProperties, other.mSamplePointerCoords, splitPointerIds);

    // Initialize the event with zero pointers, and manually set the split pointers.
    initialize(newEventId, other.mDeviceId, other.mSource, other.mDisplayId, /*hmac=*/{}, action,
               other.mActionButton, other.mFlags, other.mEdgeFlags, other.mMetaState,
               other.mButtonState, other.mClassification, other.mTransform, other.mXPrecision,
               other.mYPrecision, other.mRawXCursorPosition, other.mRawYCursorPosition,
               other.mRawTransform, splitDownTime, other.getEventTime(), /*pointerCount=*/0,
               pointerProperties.data(), pointerCoords.data());
    mPointerProperties = std::move(pointerProperties);
    mSamplePointerCoords = std::move(pointerCoords);
    mSampleEventTimes = other.mSampleEventTimes;
}

void MotionEvent::addSample(
        int64_t eventTime,
        const PointerCoords* pointerCoords) {
    mSampleEventTimes.push_back(eventTime);
    mSamplePointerCoords.insert(mSamplePointerCoords.end(), &pointerCoords[0],
                                &pointerCoords[getPointerCount()]);
}

std::optional<ui::Rotation> MotionEvent::getSurfaceRotation() const {
    // The surface rotation is the rotation from the window's coordinate space to that of the
    // display. Since the event's transform takes display space coordinates to window space, the
    // returned surface rotation is the inverse of the rotation for the surface.
    switch (mTransform.getOrientation()) {
        case ui::Transform::ROT_0:
            return ui::ROTATION_0;
        case ui::Transform::ROT_90:
            return ui::ROTATION_270;
        case ui::Transform::ROT_180:
            return ui::ROTATION_180;
        case ui::Transform::ROT_270:
            return ui::ROTATION_90;
        default:
            return std::nullopt;
    }
}

float MotionEvent::getXCursorPosition() const {
    vec2 vals = mTransform.transform(getRawXCursorPosition(), getRawYCursorPosition());
    return roundTransformedCoords(vals.x);
}

float MotionEvent::getYCursorPosition() const {
    vec2 vals = mTransform.transform(getRawXCursorPosition(), getRawYCursorPosition());
    return roundTransformedCoords(vals.y);
}

void MotionEvent::setCursorPosition(float x, float y) {
    ui::Transform inverse = mTransform.inverse();
    vec2 vals = inverse.transform(x, y);
    mRawXCursorPosition = vals.x;
    mRawYCursorPosition = vals.y;
}

const PointerCoords* MotionEvent::getRawPointerCoords(size_t pointerIndex) const {
    if (CC_UNLIKELY(pointerIndex < 0 || pointerIndex >= getPointerCount())) {
        LOG(FATAL) << __func__ << ": Invalid pointer index " << pointerIndex << " for " << *this;
    }
    const size_t position = getHistorySize() * getPointerCount() + pointerIndex;
    if (CC_UNLIKELY(position < 0 || position >= mSamplePointerCoords.size())) {
        LOG(FATAL) << __func__ << ": Invalid array index " << position << " for " << *this;
    }
    return &mSamplePointerCoords[position];
}

float MotionEvent::getRawAxisValue(int32_t axis, size_t pointerIndex) const {
    return getHistoricalRawAxisValue(axis, pointerIndex, getHistorySize());
}

float MotionEvent::getAxisValue(int32_t axis, size_t pointerIndex) const {
    return getHistoricalAxisValue(axis, pointerIndex, getHistorySize());
}

const PointerCoords* MotionEvent::getHistoricalRawPointerCoords(
        size_t pointerIndex, size_t historicalIndex) const {
    if (CC_UNLIKELY(pointerIndex < 0 || pointerIndex >= getPointerCount())) {
        LOG(FATAL) << __func__ << ": Invalid pointer index " << pointerIndex << " for " << *this;
    }
    if (CC_UNLIKELY(historicalIndex < 0 || historicalIndex > getHistorySize())) {
        LOG(FATAL) << __func__ << ": Invalid historical index " << historicalIndex << " for "
                   << *this;
    }
    const size_t position = historicalIndex * getPointerCount() + pointerIndex;
    if (CC_UNLIKELY(position < 0 || position >= mSamplePointerCoords.size())) {
        LOG(FATAL) << __func__ << ": Invalid array index " << position << " for " << *this;
    }
    return &mSamplePointerCoords[position];
}

float MotionEvent::getHistoricalRawAxisValue(int32_t axis, size_t pointerIndex,
                                             size_t historicalIndex) const {
    const PointerCoords& coords = *getHistoricalRawPointerCoords(pointerIndex, historicalIndex);
    return calculateTransformedAxisValue(axis, mSource, mFlags, mRawTransform, coords);
}

float MotionEvent::getHistoricalAxisValue(int32_t axis, size_t pointerIndex,
                                          size_t historicalIndex) const {
    const PointerCoords& coords = *getHistoricalRawPointerCoords(pointerIndex, historicalIndex);
    return calculateTransformedAxisValue(axis, mSource, mFlags, mTransform, coords);
}

ssize_t MotionEvent::findPointerIndex(int32_t pointerId) const {
    size_t pointerCount = mPointerProperties.size();
    for (size_t i = 0; i < pointerCount; i++) {
        if (mPointerProperties[i].id == pointerId) {
            return i;
        }
    }
    return -1;
}

void MotionEvent::offsetLocation(float xOffset, float yOffset) {
    float currXOffset = mTransform.tx();
    float currYOffset = mTransform.ty();
    mTransform.set(currXOffset + xOffset, currYOffset + yOffset);
}

float MotionEvent::getRawXOffset() const {
    // This is equivalent to the x-coordinate of the point that the origin of the raw coordinate
    // space maps to.
    return (mTransform * mRawTransform.inverse()).tx();
}

float MotionEvent::getRawYOffset() const {
    // This is equivalent to the y-coordinate of the point that the origin of the raw coordinate
    // space maps to.
    return (mTransform * mRawTransform.inverse()).ty();
}

void MotionEvent::scale(float globalScaleFactor) {
    mTransform.set(mTransform.tx() * globalScaleFactor, mTransform.ty() * globalScaleFactor);
    mRawTransform.set(mRawTransform.tx() * globalScaleFactor,
                      mRawTransform.ty() * globalScaleFactor);
    mXPrecision *= globalScaleFactor;
    mYPrecision *= globalScaleFactor;

    size_t numSamples = mSamplePointerCoords.size();
    for (size_t i = 0; i < numSamples; i++) {
        mSamplePointerCoords[i].scale(globalScaleFactor, globalScaleFactor, globalScaleFactor);
    }
}

void MotionEvent::transform(const std::array<float, 9>& matrix) {
    // We want to preserve the raw axes values stored in the PointerCoords, so we just update the
    // transform using the values passed in.
    ui::Transform newTransform;
    newTransform.set(matrix);
    mTransform = newTransform * mTransform;
}

void MotionEvent::applyTransform(const std::array<float, 9>& matrix) {
    ui::Transform transform;
    transform.set(matrix);

    // Apply the transformation to all samples.
    std::for_each(mSamplePointerCoords.begin(), mSamplePointerCoords.end(), [&](PointerCoords& c) {
        calculateTransformedCoordsInPlace(c, mSource, mFlags, transform);
    });

    if (mRawXCursorPosition != AMOTION_EVENT_INVALID_CURSOR_POSITION &&
        mRawYCursorPosition != AMOTION_EVENT_INVALID_CURSOR_POSITION) {
        const vec2 cursor = transform.transform(mRawXCursorPosition, mRawYCursorPosition);
        mRawXCursorPosition = cursor.x;
        mRawYCursorPosition = cursor.y;
    }
}

static status_t readFromParcel(ui::Transform& transform, const Parcel& parcel) {
    float dsdx, dtdx, tx, dtdy, dsdy, ty;
    status_t status = parcel.readFloat(&dsdx);
    status |= parcel.readFloat(&dtdx);
    status |= parcel.readFloat(&tx);
    status |= parcel.readFloat(&dtdy);
    status |= parcel.readFloat(&dsdy);
    status |= parcel.readFloat(&ty);

    transform.set({dsdx, dtdx, tx, dtdy, dsdy, ty, 0, 0, 1});
    return status;
}

static status_t writeToParcel(const ui::Transform& transform, Parcel& parcel) {
    status_t status = parcel.writeFloat(transform.dsdx());
    status |= parcel.writeFloat(transform.dtdx());
    status |= parcel.writeFloat(transform.tx());
    status |= parcel.writeFloat(transform.dtdy());
    status |= parcel.writeFloat(transform.dsdy());
    status |= parcel.writeFloat(transform.ty());
    return status;
}

status_t MotionEvent::readFromParcel(Parcel* parcel) {
    size_t pointerCount = parcel->readInt32();
    size_t sampleCount = parcel->readInt32();
    if (pointerCount == 0 || pointerCount > MAX_POINTERS ||
            sampleCount == 0 || sampleCount > MAX_SAMPLES) {
        return BAD_VALUE;
    }

    mId = parcel->readInt32();
    mDeviceId = parcel->readInt32();
    mSource = parcel->readUint32();
    mDisplayId = ui::LogicalDisplayId{parcel->readInt32()};
    std::vector<uint8_t> hmac;
    status_t result = parcel->readByteVector(&hmac);
    if (result != OK || hmac.size() != 32) {
        return BAD_VALUE;
    }
    std::move(hmac.begin(), hmac.begin() + hmac.size(), mHmac.begin());
    mAction = parcel->readInt32();
    mActionButton = parcel->readInt32();
    mFlags = parcel->readInt32();
    mEdgeFlags = parcel->readInt32();
    mMetaState = parcel->readInt32();
    mButtonState = parcel->readInt32();
    mClassification = static_cast<MotionClassification>(parcel->readByte());

    result = android::readFromParcel(mTransform, *parcel);
    if (result != OK) {
        return result;
    }
    mXPrecision = parcel->readFloat();
    mYPrecision = parcel->readFloat();
    mRawXCursorPosition = parcel->readFloat();
    mRawYCursorPosition = parcel->readFloat();

    result = android::readFromParcel(mRawTransform, *parcel);
    if (result != OK) {
        return result;
    }
    mDownTime = parcel->readInt64();

    mPointerProperties.clear();
    mPointerProperties.reserve(pointerCount);
    mSampleEventTimes.clear();
    mSampleEventTimes.reserve(sampleCount);
    mSamplePointerCoords.clear();
    mSamplePointerCoords.reserve(sampleCount * pointerCount);

    for (size_t i = 0; i < pointerCount; i++) {
        mPointerProperties.push_back({});
        PointerProperties& properties = mPointerProperties.back();
        properties.id = parcel->readInt32();
        properties.toolType = static_cast<ToolType>(parcel->readInt32());
    }

    while (sampleCount > 0) {
        sampleCount--;
        mSampleEventTimes.push_back(parcel->readInt64());
        for (size_t i = 0; i < pointerCount; i++) {
            mSamplePointerCoords.push_back({});
            status_t status = mSamplePointerCoords.back().readFromParcel(parcel);
            if (status) {
                return status;
            }
        }
    }
    return OK;
}

status_t MotionEvent::writeToParcel(Parcel* parcel) const {
    size_t pointerCount = mPointerProperties.size();
    size_t sampleCount = mSampleEventTimes.size();

    parcel->writeInt32(pointerCount);
    parcel->writeInt32(sampleCount);

    parcel->writeInt32(mId);
    parcel->writeInt32(mDeviceId);
    parcel->writeUint32(mSource);
    parcel->writeInt32(mDisplayId.val());
    std::vector<uint8_t> hmac(mHmac.begin(), mHmac.end());
    parcel->writeByteVector(hmac);
    parcel->writeInt32(mAction);
    parcel->writeInt32(mActionButton);
    parcel->writeInt32(mFlags);
    parcel->writeInt32(mEdgeFlags);
    parcel->writeInt32(mMetaState);
    parcel->writeInt32(mButtonState);
    parcel->writeByte(static_cast<int8_t>(mClassification));

    status_t result = android::writeToParcel(mTransform, *parcel);
    if (result != OK) {
        return result;
    }
    parcel->writeFloat(mXPrecision);
    parcel->writeFloat(mYPrecision);
    parcel->writeFloat(mRawXCursorPosition);
    parcel->writeFloat(mRawYCursorPosition);

    result = android::writeToParcel(mRawTransform, *parcel);
    if (result != OK) {
        return result;
    }
    parcel->writeInt64(mDownTime);

    for (size_t i = 0; i < pointerCount; i++) {
        const PointerProperties& properties = mPointerProperties[i];
        parcel->writeInt32(properties.id);
        parcel->writeInt32(static_cast<int32_t>(properties.toolType));
    }

    const PointerCoords* pc = mSamplePointerCoords.data();
    for (size_t h = 0; h < sampleCount; h++) {
        parcel->writeInt64(mSampleEventTimes[h]);
        for (size_t i = 0; i < pointerCount; i++) {
            status_t status = (pc++)->writeToParcel(parcel);
            if (status) {
                return status;
            }
        }
    }
    return OK;
}

bool MotionEvent::isTouchEvent(uint32_t source, int32_t action) {
    if (isFromSource(source, AINPUT_SOURCE_CLASS_POINTER)) {
        // Specifically excludes HOVER_MOVE and SCROLL.
        switch (action & AMOTION_EVENT_ACTION_MASK) {
        case AMOTION_EVENT_ACTION_DOWN:
        case AMOTION_EVENT_ACTION_MOVE:
        case AMOTION_EVENT_ACTION_UP:
        case AMOTION_EVENT_ACTION_POINTER_DOWN:
        case AMOTION_EVENT_ACTION_POINTER_UP:
        case AMOTION_EVENT_ACTION_CANCEL:
        case AMOTION_EVENT_ACTION_OUTSIDE:
            return true;
        }
    }
    return false;
}

const char* MotionEvent::getLabel(int32_t axis) {
    return InputEventLookup::getAxisLabel(axis);
}

std::optional<int> MotionEvent::getAxisFromLabel(const char* label) {
    return InputEventLookup::getAxisByLabel(label);
}

std::string MotionEvent::actionToString(int32_t action) {
    // Convert MotionEvent action to string
    switch (action & AMOTION_EVENT_ACTION_MASK) {
        case AMOTION_EVENT_ACTION_DOWN:
            return "DOWN";
        case AMOTION_EVENT_ACTION_UP:
            return "UP";
        case AMOTION_EVENT_ACTION_MOVE:
            return "MOVE";
        case AMOTION_EVENT_ACTION_CANCEL:
            return "CANCEL";
        case AMOTION_EVENT_ACTION_OUTSIDE:
            return "OUTSIDE";
        case AMOTION_EVENT_ACTION_POINTER_DOWN:
            return StringPrintf("POINTER_DOWN(%" PRId32 ")", MotionEvent::getActionIndex(action));
        case AMOTION_EVENT_ACTION_POINTER_UP:
            return StringPrintf("POINTER_UP(%" PRId32 ")", MotionEvent::getActionIndex(action));
        case AMOTION_EVENT_ACTION_HOVER_MOVE:
            return "HOVER_MOVE";
        case AMOTION_EVENT_ACTION_SCROLL:
            return "SCROLL";
        case AMOTION_EVENT_ACTION_HOVER_ENTER:
            return "HOVER_ENTER";
        case AMOTION_EVENT_ACTION_HOVER_EXIT:
            return "HOVER_EXIT";
        case AMOTION_EVENT_ACTION_BUTTON_PRESS:
            return "BUTTON_PRESS";
        case AMOTION_EVENT_ACTION_BUTTON_RELEASE:
            return "BUTTON_RELEASE";
    }
    return android::base::StringPrintf("%" PRId32, action);
}

std::tuple<int32_t, std::vector<PointerProperties>, std::vector<PointerCoords>> MotionEvent::split(
        int32_t action, int32_t flags, int32_t historySize,
        const std::vector<PointerProperties>& pointerProperties,
        const std::vector<PointerCoords>& pointerCoords,
        std::bitset<MAX_POINTER_ID + 1> splitPointerIds) {
    LOG_ALWAYS_FATAL_IF(!splitPointerIds.any());
    const auto pointerCount = pointerProperties.size();
    LOG_ALWAYS_FATAL_IF(pointerCoords.size() != (pointerCount * (historySize + 1)));
    const auto splitCount = splitPointerIds.count();

    std::vector<PointerProperties> splitPointerProperties;
    std::vector<PointerCoords> splitPointerCoords;

    for (uint32_t i = 0; i < pointerCount; i++) {
        if (splitPointerIds.test(pointerProperties[i].id)) {
            splitPointerProperties.emplace_back(pointerProperties[i]);
        }
    }
    for (uint32_t i = 0; i < pointerCoords.size(); i++) {
        if (splitPointerIds.test(pointerProperties[i % pointerCount].id)) {
            splitPointerCoords.emplace_back(pointerCoords[i]);
        }
    }
    LOG_ALWAYS_FATAL_IF(splitPointerCoords.size() !=
                        (splitPointerProperties.size() * (historySize + 1)));

    if (CC_UNLIKELY(splitPointerProperties.size() != splitCount)) {
        // TODO(b/329107108): Promote this to a fatal check once bugs in the caller are resolved.
        LOG(ERROR) << "Cannot split MotionEvent: Requested splitting " << splitCount
                   << " pointers from the original event, but the original event only contained "
                   << splitPointerProperties.size() << " of those pointers.";
    }

    // TODO(b/327503168): Verify the splitDownTime here once it is used correctly.

    const auto splitAction = resolveActionForSplitMotionEvent(action, flags, pointerProperties,
                                                              splitPointerProperties);
    return {splitAction, splitPointerProperties, splitPointerCoords};
}

// Apply the given transformation to the point without checking whether the entire transform
// should be disregarded altogether for the provided source.
static inline vec2 calculateTransformedXYUnchecked(uint32_t source, const ui::Transform& transform,
                                                   const vec2& xy) {
    return shouldDisregardOffset(source) ? transformWithoutTranslation(transform, xy)
                                         : roundTransformedCoords(transform.transform(xy));
}

vec2 MotionEvent::calculateTransformedXY(uint32_t source, const ui::Transform& transform,
                                         const vec2& xy) {
    if (shouldDisregardTransformation(source)) {
        return xy;
    }
    return calculateTransformedXYUnchecked(source, transform, xy);
}

// Keep in sync with calculateTransformedCoords.
float MotionEvent::calculateTransformedAxisValue(int32_t axis, uint32_t source, int32_t flags,
                                                 const ui::Transform& transform,
                                                 const PointerCoords& coords) {
    if (shouldDisregardTransformation(source)) {
        return coords.getAxisValue(axis);
    }

    if (axis == AMOTION_EVENT_AXIS_X || axis == AMOTION_EVENT_AXIS_Y) {
        const vec2 xy = calculateTransformedXYUnchecked(source, transform, coords.getXYValue());
        static_assert(AMOTION_EVENT_AXIS_X == 0 && AMOTION_EVENT_AXIS_Y == 1);
        return xy[axis];
    }

    if (axis == AMOTION_EVENT_AXIS_RELATIVE_X || axis == AMOTION_EVENT_AXIS_RELATIVE_Y) {
        const vec2 relativeXy =
                transformWithoutTranslation(transform,
                                            {coords.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X),
                                             coords.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y)});
        return axis == AMOTION_EVENT_AXIS_RELATIVE_X ? relativeXy.x : relativeXy.y;
    }

    if (axis == AMOTION_EVENT_AXIS_ORIENTATION) {
        return transformOrientation(transform, coords, flags);
    }

    return coords.getAxisValue(axis);
}

// Keep in sync with calculateTransformedAxisValue. This is an optimization of
// calculateTransformedAxisValue for all PointerCoords axes.
void MotionEvent::calculateTransformedCoordsInPlace(PointerCoords& coords, uint32_t source,
                                                    int32_t flags, const ui::Transform& transform) {
    if (shouldDisregardTransformation(source)) {
        return;
    }

    const vec2 xy = calculateTransformedXYUnchecked(source, transform, coords.getXYValue());
    coords.setAxisValue(AMOTION_EVENT_AXIS_X, xy.x);
    coords.setAxisValue(AMOTION_EVENT_AXIS_Y, xy.y);

    const vec2 relativeXy =
            transformWithoutTranslation(transform,
                                        {coords.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X),
                                         coords.getAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y)});
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_X, relativeXy.x);
    coords.setAxisValue(AMOTION_EVENT_AXIS_RELATIVE_Y, relativeXy.y);

    coords.setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION,
                        transformOrientation(transform, coords, flags));
}

PointerCoords MotionEvent::calculateTransformedCoords(uint32_t source, int32_t flags,
                                                      const ui::Transform& transform,
                                                      const PointerCoords& coords) {
    PointerCoords out = coords;
    calculateTransformedCoordsInPlace(out, source, flags, transform);
    return out;
}

bool MotionEvent::operator==(const android::MotionEvent& o) const {
    // We use NaN values to represent invalid cursor positions. Since NaN values are not equal
    // to themselves according to IEEE 754, we cannot use the default equality operator to compare
    // MotionEvents. Therefore we define a custom equality operator with special handling for NaNs.
    // clang-format off
    return InputEvent::operator==(static_cast<const InputEvent&>(o)) &&
            mAction == o.mAction &&
            mActionButton == o.mActionButton &&
            mFlags == o.mFlags &&
            mEdgeFlags == o.mEdgeFlags &&
            mMetaState == o.mMetaState &&
            mButtonState == o.mButtonState &&
            mClassification == o.mClassification &&
            mTransform == o.mTransform &&
            mXPrecision == o.mXPrecision &&
            mYPrecision == o.mYPrecision &&
            ((std::isnan(mRawXCursorPosition) && std::isnan(o.mRawXCursorPosition)) ||
                mRawXCursorPosition == o.mRawXCursorPosition) &&
            ((std::isnan(mRawYCursorPosition) && std::isnan(o.mRawYCursorPosition)) ||
                mRawYCursorPosition == o.mRawYCursorPosition) &&
            mRawTransform == o.mRawTransform && mDownTime == o.mDownTime &&
            mPointerProperties == o.mPointerProperties &&
            mSampleEventTimes == o.mSampleEventTimes &&
            mSamplePointerCoords == o.mSamplePointerCoords;
    // clang-format on
}

std::ostream& operator<<(std::ostream& out, const MotionEvent& event) {
    out << "MotionEvent { action=" << MotionEvent::actionToString(event.getAction());
    if (event.getActionButton() != 0) {
        out << ", actionButton=" << std::to_string(event.getActionButton());
    }
    const size_t pointerCount = event.getPointerCount();
    LOG_ALWAYS_FATAL_IF(pointerCount > MAX_POINTERS, "Too many pointers : pointerCount = %zu",
                        pointerCount);
    for (size_t i = 0; i < pointerCount; i++) {
        out << ", id[" << i << "]=" << event.getPointerId(i);
        float x = event.getX(i);
        float y = event.getY(i);
        if (x != 0 || y != 0) {
            out << ", x[" << i << "]=" << x;
            out << ", y[" << i << "]=" << y;
        }
        ToolType toolType = event.getToolType(i);
        if (toolType != ToolType::FINGER) {
            out << ", toolType[" << i << "]=" << ftl::enum_string(toolType);
        }
    }
    if (event.getButtonState() != 0) {
        out << ", buttonState=" << event.getButtonState();
    }
    if (event.getClassification() != MotionClassification::NONE) {
        out << ", classification=" << motionClassificationToString(event.getClassification());
    }
    if (event.getMetaState() != 0) {
        out << ", metaState=" << event.getMetaState();
    }
    if (event.getFlags() != 0) {
        out << ", flags=0x" << std::hex << event.getFlags() << std::dec;
    }
    if (event.getEdgeFlags() != 0) {
        out << ", edgeFlags=" << event.getEdgeFlags();
    }
    if (pointerCount != 1) {
        out << ", pointerCount=" << pointerCount;
    }
    if (event.getHistorySize() != 0) {
        out << ", historySize=" << event.getHistorySize();
    }
    out << ", eventTime=" << event.getEventTime();
    out << ", downTime=" << event.getDownTime();
    out << ", deviceId=" << event.getDeviceId();
    out << ", source=" << inputEventSourceToString(event.getSource());
    out << ", displayId=" << event.getDisplayId();
    out << ", eventId=0x" << std::hex << event.getId() << std::dec;
    out << "}";
    return out;
}

// --- FocusEvent ---

void FocusEvent::initialize(int32_t id, bool hasFocus) {
    InputEvent::initialize(id, ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID, AINPUT_SOURCE_UNKNOWN,
                           ui::LogicalDisplayId::INVALID, INVALID_HMAC);
    mHasFocus = hasFocus;
}

void FocusEvent::initialize(const FocusEvent& from) {
    InputEvent::initialize(from);
    mHasFocus = from.mHasFocus;
}

// --- CaptureEvent ---

void CaptureEvent::initialize(int32_t id, bool pointerCaptureEnabled) {
    InputEvent::initialize(id, ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID, AINPUT_SOURCE_UNKNOWN,
                           ui::LogicalDisplayId::INVALID, INVALID_HMAC);
    mPointerCaptureEnabled = pointerCaptureEnabled;
}

void CaptureEvent::initialize(const CaptureEvent& from) {
    InputEvent::initialize(from);
    mPointerCaptureEnabled = from.mPointerCaptureEnabled;
}

// --- DragEvent ---

void DragEvent::initialize(int32_t id, float x, float y, bool isExiting) {
    InputEvent::initialize(id, ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID, AINPUT_SOURCE_UNKNOWN,
                           ui::LogicalDisplayId::INVALID, INVALID_HMAC);
    mIsExiting = isExiting;
    mX = x;
    mY = y;
}

void DragEvent::initialize(const DragEvent& from) {
    InputEvent::initialize(from);
    mIsExiting = from.mIsExiting;
    mX = from.mX;
    mY = from.mY;
}

// --- TouchModeEvent ---

void TouchModeEvent::initialize(int32_t id, bool isInTouchMode) {
    InputEvent::initialize(id, ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID, AINPUT_SOURCE_UNKNOWN,
                           ui::LogicalDisplayId::INVALID, INVALID_HMAC);
    mIsInTouchMode = isInTouchMode;
}

void TouchModeEvent::initialize(const TouchModeEvent& from) {
    InputEvent::initialize(from);
    mIsInTouchMode = from.mIsInTouchMode;
}

// --- PooledInputEventFactory ---

PooledInputEventFactory::PooledInputEventFactory(size_t maxPoolSize) :
        mMaxPoolSize(maxPoolSize) {
}

PooledInputEventFactory::~PooledInputEventFactory() {
}

KeyEvent* PooledInputEventFactory::createKeyEvent() {
    if (mKeyEventPool.empty()) {
        return new KeyEvent();
    }
    KeyEvent* event = mKeyEventPool.front().release();
    mKeyEventPool.pop();
    return event;
}

MotionEvent* PooledInputEventFactory::createMotionEvent() {
    if (mMotionEventPool.empty()) {
        return new MotionEvent();
    }
    MotionEvent* event = mMotionEventPool.front().release();
    mMotionEventPool.pop();
    return event;
}

FocusEvent* PooledInputEventFactory::createFocusEvent() {
    if (mFocusEventPool.empty()) {
        return new FocusEvent();
    }
    FocusEvent* event = mFocusEventPool.front().release();
    mFocusEventPool.pop();
    return event;
}

CaptureEvent* PooledInputEventFactory::createCaptureEvent() {
    if (mCaptureEventPool.empty()) {
        return new CaptureEvent();
    }
    CaptureEvent* event = mCaptureEventPool.front().release();
    mCaptureEventPool.pop();
    return event;
}

DragEvent* PooledInputEventFactory::createDragEvent() {
    if (mDragEventPool.empty()) {
        return new DragEvent();
    }
    DragEvent* event = mDragEventPool.front().release();
    mDragEventPool.pop();
    return event;
}

TouchModeEvent* PooledInputEventFactory::createTouchModeEvent() {
    if (mTouchModeEventPool.empty()) {
        return new TouchModeEvent();
    }
    TouchModeEvent* event = mTouchModeEventPool.front().release();
    mTouchModeEventPool.pop();
    return event;
}

void PooledInputEventFactory::recycle(InputEvent* event) {
    switch (event->getType()) {
        case InputEventType::KEY: {
            if (mKeyEventPool.size() < mMaxPoolSize) {
                mKeyEventPool.push(std::unique_ptr<KeyEvent>(static_cast<KeyEvent*>(event)));
                return;
            }
            break;
        }
        case InputEventType::MOTION: {
            if (mMotionEventPool.size() < mMaxPoolSize) {
                mMotionEventPool.push(
                        std::unique_ptr<MotionEvent>(static_cast<MotionEvent*>(event)));
                return;
            }
            break;
        }
        case InputEventType::FOCUS: {
            if (mFocusEventPool.size() < mMaxPoolSize) {
                mFocusEventPool.push(std::unique_ptr<FocusEvent>(static_cast<FocusEvent*>(event)));
                return;
            }
            break;
        }
        case InputEventType::CAPTURE: {
            if (mCaptureEventPool.size() < mMaxPoolSize) {
                mCaptureEventPool.push(
                        std::unique_ptr<CaptureEvent>(static_cast<CaptureEvent*>(event)));
                return;
            }
            break;
        }
        case InputEventType::DRAG: {
            if (mDragEventPool.size() < mMaxPoolSize) {
                mDragEventPool.push(std::unique_ptr<DragEvent>(static_cast<DragEvent*>(event)));
                return;
            }
            break;
        }
        case InputEventType::TOUCH_MODE: {
            if (mTouchModeEventPool.size() < mMaxPoolSize) {
                mTouchModeEventPool.push(
                        std::unique_ptr<TouchModeEvent>(static_cast<TouchModeEvent*>(event)));
                return;
            }
            break;
        }
    }
    delete event;
}

} // namespace android
