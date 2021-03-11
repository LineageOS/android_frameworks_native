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
#include <limits.h>
#include <string.h>

#include <android-base/stringprintf.h>
#include <input/Input.h>
#include <input/InputDevice.h>
#include <input/InputEventLabels.h>

#ifdef __linux__
#include <binder/Parcel.h>
#endif
#ifdef __ANDROID__
#include <sys/random.h>
#endif

using android::base::StringPrintf;

namespace android {

const char* motionClassificationToString(MotionClassification classification) {
    switch (classification) {
        case MotionClassification::NONE:
            return "NONE";
        case MotionClassification::AMBIGUOUS_GESTURE:
            return "AMBIGUOUS_GESTURE";
        case MotionClassification::DEEP_PRESS:
            return "DEEP_PRESS";
    }
}

// --- IdGenerator ---
IdGenerator::IdGenerator(Source source) : mSource(source) {}

int32_t IdGenerator::nextId() const {
    constexpr uint32_t SEQUENCE_NUMBER_MASK = ~SOURCE_MASK;
    int32_t id = 0;

// Avoid building against syscall getrandom(2) on host, which will fail build on Mac. Host doesn't
// use sequence number so just always return mSource.
#ifdef __ANDROID__
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
#endif // __ANDROID__

    return (id & SEQUENCE_NUMBER_MASK) | static_cast<int32_t>(mSource);
}

// --- InputEvent ---

const char* inputEventTypeToString(int32_t type) {
    switch (type) {
        case AINPUT_EVENT_TYPE_KEY: {
            return "KEY";
        }
        case AINPUT_EVENT_TYPE_MOTION: {
            return "MOTION";
        }
        case AINPUT_EVENT_TYPE_FOCUS: {
            return "FOCUS";
        }
        case AINPUT_EVENT_TYPE_CAPTURE: {
            return "CAPTURE";
        }
        case AINPUT_EVENT_TYPE_DRAG: {
            return "DRAG";
        }
    }
    return "UNKNOWN";
}

VerifiedKeyEvent verifiedKeyEventFromKeyEvent(const KeyEvent& event) {
    return {{VerifiedInputEvent::Type::KEY, event.getDeviceId(), event.getEventTime(),
             event.getSource(), event.getDisplayId()},
            event.getAction(),
            event.getDownTime(),
            event.getFlags() & VERIFIED_KEY_EVENT_FLAGS,
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
            event.getDownTime(),
            event.getFlags() & VERIFIED_MOTION_EVENT_FLAGS,
            event.getMetaState(),
            event.getButtonState()};
}

void InputEvent::initialize(int32_t id, int32_t deviceId, uint32_t source, int32_t displayId,
                            std::array<uint8_t, 32> hmac) {
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

// --- KeyEvent ---

const char* KeyEvent::getLabel(int32_t keyCode) {
    return InputEventLookup::getLabelByKeyCode(keyCode);
}

int32_t KeyEvent::getKeyCodeFromLabel(const char* label) {
    return InputEventLookup::getKeyCodeByLabel(label);
}

void KeyEvent::initialize(int32_t id, int32_t deviceId, uint32_t source, int32_t displayId,
                          std::array<uint8_t, 32> hmac, int32_t action, int32_t flags,
                          int32_t keyCode, int32_t scanCode, int32_t metaState, int32_t repeatCount,
                          nsecs_t downTime, nsecs_t eventTime) {
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
}

void PointerCoords::applyOffset(float xOffset, float yOffset) {
    setAxisValue(AMOTION_EVENT_AXIS_X, getX() + xOffset);
    setAxisValue(AMOTION_EVENT_AXIS_Y, getY() + yOffset);
}

#ifdef __linux__
status_t PointerCoords::readFromParcel(Parcel* parcel) {
    bits = parcel->readInt64();

    uint32_t count = BitSet64::count(bits);
    if (count > MAX_AXES) {
        return BAD_VALUE;
    }

    for (uint32_t i = 0; i < count; i++) {
        values[i] = parcel->readFloat();
    }
    return OK;
}

status_t PointerCoords::writeToParcel(Parcel* parcel) const {
    parcel->writeInt64(bits);

    uint32_t count = BitSet64::count(bits);
    for (uint32_t i = 0; i < count; i++) {
        parcel->writeFloat(values[i]);
    }
    return OK;
}
#endif

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
    return true;
}

void PointerCoords::copyFrom(const PointerCoords& other) {
    bits = other.bits;
    uint32_t count = BitSet64::count(bits);
    for (uint32_t i = 0; i < count; i++) {
        values[i] = other.values[i];
    }
}

void PointerCoords::transform(const ui::Transform& transform) {
    vec2 newCoords = transform.transform(getX(), getY());
    setAxisValue(AMOTION_EVENT_AXIS_X, newCoords.x);
    setAxisValue(AMOTION_EVENT_AXIS_Y, newCoords.y);
}

// --- PointerProperties ---

bool PointerProperties::operator==(const PointerProperties& other) const {
    return id == other.id
            && toolType == other.toolType;
}

void PointerProperties::copyFrom(const PointerProperties& other) {
    id = other.id;
    toolType = other.toolType;
}


// --- MotionEvent ---

void MotionEvent::initialize(int32_t id, int32_t deviceId, uint32_t source, int32_t displayId,
                             std::array<uint8_t, 32> hmac, int32_t action, int32_t actionButton,
                             int32_t flags, int32_t edgeFlags, int32_t metaState,
                             int32_t buttonState, MotionClassification classification,
                             const ui::Transform& transform, float xPrecision, float yPrecision,
                             float rawXCursorPosition, float rawYCursorPosition, nsecs_t downTime,
                             nsecs_t eventTime, size_t pointerCount,
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
    mDownTime = downTime;
    mPointerProperties.clear();
    mPointerProperties.appendArray(pointerProperties, pointerCount);
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
        mSamplePointerCoords.appendArray(other->mSamplePointerCoords.array()
                + (historySize * pointerCount), pointerCount);
    }
}

void MotionEvent::addSample(
        int64_t eventTime,
        const PointerCoords* pointerCoords) {
    mSampleEventTimes.push_back(eventTime);
    mSamplePointerCoords.appendArray(pointerCoords, getPointerCount());
}

float MotionEvent::getXCursorPosition() const {
    vec2 vals = mTransform.transform(getRawXCursorPosition(), getRawYCursorPosition());
    return vals.x;
}

float MotionEvent::getYCursorPosition() const {
    vec2 vals = mTransform.transform(getRawXCursorPosition(), getRawYCursorPosition());
    return vals.y;
}

void MotionEvent::setCursorPosition(float x, float y) {
    ui::Transform inverse = mTransform.inverse();
    vec2 vals = inverse.transform(x, y);
    mRawXCursorPosition = vals.x;
    mRawYCursorPosition = vals.y;
}

const PointerCoords* MotionEvent::getRawPointerCoords(size_t pointerIndex) const {
    return &mSamplePointerCoords[getHistorySize() * getPointerCount() + pointerIndex];
}

float MotionEvent::getRawAxisValue(int32_t axis, size_t pointerIndex) const {
    return getRawPointerCoords(pointerIndex)->getAxisValue(axis);
}

float MotionEvent::getAxisValue(int32_t axis, size_t pointerIndex) const {
    return getHistoricalAxisValue(axis, pointerIndex, getHistorySize());
}

const PointerCoords* MotionEvent::getHistoricalRawPointerCoords(
        size_t pointerIndex, size_t historicalIndex) const {
    return &mSamplePointerCoords[historicalIndex * getPointerCount() + pointerIndex];
}

float MotionEvent::getHistoricalRawAxisValue(int32_t axis, size_t pointerIndex,
        size_t historicalIndex) const {
    return getHistoricalRawPointerCoords(pointerIndex, historicalIndex)->getAxisValue(axis);
}

float MotionEvent::getHistoricalAxisValue(int32_t axis, size_t pointerIndex,
        size_t historicalIndex) const {
    if (axis != AMOTION_EVENT_AXIS_X && axis != AMOTION_EVENT_AXIS_Y) {
        return getHistoricalRawPointerCoords(pointerIndex, historicalIndex)->getAxisValue(axis);
    }

    float rawX = getHistoricalRawPointerCoords(pointerIndex, historicalIndex)->getX();
    float rawY = getHistoricalRawPointerCoords(pointerIndex, historicalIndex)->getY();
    vec2 vals = mTransform.transform(rawX, rawY);

    switch (axis) {
    case AMOTION_EVENT_AXIS_X:
        return vals.x;
    case AMOTION_EVENT_AXIS_Y:
        return vals.y;
    }

    // This should never happen
    return 0;
}

ssize_t MotionEvent::findPointerIndex(int32_t pointerId) const {
    size_t pointerCount = mPointerProperties.size();
    for (size_t i = 0; i < pointerCount; i++) {
        if (mPointerProperties.itemAt(i).id == pointerId) {
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

void MotionEvent::scale(float globalScaleFactor) {
    mTransform.set(mTransform.tx() * globalScaleFactor, mTransform.ty() * globalScaleFactor);
    mXPrecision *= globalScaleFactor;
    mYPrecision *= globalScaleFactor;

    size_t numSamples = mSamplePointerCoords.size();
    for (size_t i = 0; i < numSamples; i++) {
        mSamplePointerCoords.editItemAt(i).scale(globalScaleFactor, globalScaleFactor,
                                                 globalScaleFactor);
    }
}

static vec2 transformPoint(const std::array<float, 9>& matrix, float x, float y) {
    // Apply perspective transform like Skia.
    float newX = matrix[0] * x + matrix[1] * y + matrix[2];
    float newY = matrix[3] * x + matrix[4] * y + matrix[5];
    float newZ = matrix[6] * x + matrix[7] * y + matrix[8];
    if (newZ) {
        newZ = 1.0f / newZ;
    }
    vec2 transformedPoint;
    transformedPoint.x = newX * newZ;
    transformedPoint.y = newY * newZ;
    return transformedPoint;
}

static float transformAngle(const std::array<float, 9>& matrix, float angleRadians, float originX,
                            float originY) {
    // Construct and transform a vector oriented at the specified clockwise angle from vertical.
    // Coordinate system: down is increasing Y, right is increasing X.
    float x = sinf(angleRadians);
    float y = -cosf(angleRadians);
    vec2 transformedPoint = transformPoint(matrix, x, y);

    transformedPoint.x -= originX;
    transformedPoint.y -= originY;

    // Derive the transformed vector's clockwise angle from vertical.
    float result = atan2f(transformedPoint.x, -transformedPoint.y);
    if (result < - M_PI_2) {
        result += M_PI;
    } else if (result > M_PI_2) {
        result -= M_PI;
    }
    return result;
}

void MotionEvent::transform(const std::array<float, 9>& matrix) {
    // We want to preserve the rawX and rawY so we just update the transform
    // using the values of the transform passed in
    ui::Transform newTransform;
    newTransform.set(matrix);
    mTransform = newTransform * mTransform;

    // Determine how the origin is transformed by the matrix so that we
    // can transform orientation vectors.
    vec2 origin = transformPoint(matrix, 0, 0);

    // Apply the transformation to all samples.
    size_t numSamples = mSamplePointerCoords.size();
    for (size_t i = 0; i < numSamples; i++) {
        PointerCoords& c = mSamplePointerCoords.editItemAt(i);
        float orientation = c.getAxisValue(AMOTION_EVENT_AXIS_ORIENTATION);
        c.setAxisValue(AMOTION_EVENT_AXIS_ORIENTATION,
                       transformAngle(matrix, orientation, origin.x, origin.y));
    }
}

#ifdef __linux__
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
    mDisplayId = parcel->readInt32();
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
    mDownTime = parcel->readInt64();

    mPointerProperties.clear();
    mPointerProperties.setCapacity(pointerCount);
    mSampleEventTimes.clear();
    mSampleEventTimes.reserve(sampleCount);
    mSamplePointerCoords.clear();
    mSamplePointerCoords.setCapacity(sampleCount * pointerCount);

    for (size_t i = 0; i < pointerCount; i++) {
        mPointerProperties.push();
        PointerProperties& properties = mPointerProperties.editTop();
        properties.id = parcel->readInt32();
        properties.toolType = parcel->readInt32();
    }

    while (sampleCount > 0) {
        sampleCount--;
        mSampleEventTimes.push_back(parcel->readInt64());
        for (size_t i = 0; i < pointerCount; i++) {
            mSamplePointerCoords.push();
            status_t status = mSamplePointerCoords.editTop().readFromParcel(parcel);
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
    parcel->writeInt32(mDisplayId);
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
    parcel->writeInt64(mDownTime);

    for (size_t i = 0; i < pointerCount; i++) {
        const PointerProperties& properties = mPointerProperties.itemAt(i);
        parcel->writeInt32(properties.id);
        parcel->writeInt32(properties.toolType);
    }

    const PointerCoords* pc = mSamplePointerCoords.array();
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
#endif

bool MotionEvent::isTouchEvent(uint32_t source, int32_t action) {
    if (source & AINPUT_SOURCE_CLASS_POINTER) {
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

int32_t MotionEvent::getAxisFromLabel(const char* label) {
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
            return "POINTER_DOWN";
        case AMOTION_EVENT_ACTION_POINTER_UP:
            return "POINTER_UP";
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

// --- FocusEvent ---

void FocusEvent::initialize(int32_t id, bool hasFocus, bool inTouchMode) {
    InputEvent::initialize(id, ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID, AINPUT_SOURCE_UNKNOWN,
                           ADISPLAY_ID_NONE, INVALID_HMAC);
    mHasFocus = hasFocus;
    mInTouchMode = inTouchMode;
}

void FocusEvent::initialize(const FocusEvent& from) {
    InputEvent::initialize(from);
    mHasFocus = from.mHasFocus;
    mInTouchMode = from.mInTouchMode;
}

// --- CaptureEvent ---

void CaptureEvent::initialize(int32_t id, bool pointerCaptureEnabled) {
    InputEvent::initialize(id, ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID, AINPUT_SOURCE_UNKNOWN,
                           ADISPLAY_ID_NONE, INVALID_HMAC);
    mPointerCaptureEnabled = pointerCaptureEnabled;
}

void CaptureEvent::initialize(const CaptureEvent& from) {
    InputEvent::initialize(from);
    mPointerCaptureEnabled = from.mPointerCaptureEnabled;
}

// --- DragEvent ---

void DragEvent::initialize(int32_t id, float x, float y, bool isExiting) {
    InputEvent::initialize(id, ReservedInputDeviceId::VIRTUAL_KEYBOARD_ID, AINPUT_SOURCE_UNKNOWN,
                           ADISPLAY_ID_NONE, INVALID_HMAC);
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

void PooledInputEventFactory::recycle(InputEvent* event) {
    switch (event->getType()) {
    case AINPUT_EVENT_TYPE_KEY:
        if (mKeyEventPool.size() < mMaxPoolSize) {
            mKeyEventPool.push(std::unique_ptr<KeyEvent>(static_cast<KeyEvent*>(event)));
            return;
        }
        break;
    case AINPUT_EVENT_TYPE_MOTION:
        if (mMotionEventPool.size() < mMaxPoolSize) {
            mMotionEventPool.push(std::unique_ptr<MotionEvent>(static_cast<MotionEvent*>(event)));
            return;
        }
        break;
    case AINPUT_EVENT_TYPE_FOCUS:
        if (mFocusEventPool.size() < mMaxPoolSize) {
            mFocusEventPool.push(std::unique_ptr<FocusEvent>(static_cast<FocusEvent*>(event)));
            return;
        }
        break;
    case AINPUT_EVENT_TYPE_CAPTURE:
        if (mCaptureEventPool.size() < mMaxPoolSize) {
            mCaptureEventPool.push(
                    std::unique_ptr<CaptureEvent>(static_cast<CaptureEvent*>(event)));
            return;
        }
        break;
    case AINPUT_EVENT_TYPE_DRAG:
        if (mDragEventPool.size() < mMaxPoolSize) {
            mDragEventPool.push(std::unique_ptr<DragEvent>(static_cast<DragEvent*>(event)));
            return;
        }
        break;
    }
    delete event;
}

} // namespace android
