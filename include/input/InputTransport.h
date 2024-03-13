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

#pragma once

#pragma GCC system_header

/**
 * Native input transport.
 *
 * The InputChannel provides a mechanism for exchanging InputMessage structures across processes.
 *
 * The InputPublisher and InputConsumer each handle one end-point of an input channel.
 * The InputPublisher is used by the input dispatcher to send events to the application.
 * The InputConsumer is used by the application to receive events from the input dispatcher.
 */

#include <string>
#include <unordered_map>

#include <android-base/chrono_utils.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>

#include <android/os/InputChannelCore.h>
#include <binder/IBinder.h>
#include <input/Input.h>
#include <input/InputVerifier.h>
#include <sys/stat.h>
#include <ui/Transform.h>
#include <utils/BitSet.h>
#include <utils/Errors.h>
#include <utils/Timers.h>

namespace android {
class Parcel;

/*
 * Intermediate representation used to send input events and related signals.
 *
 * Note that this structure is used for IPCs so its layout must be identical
 * on 64 and 32 bit processes. This is tested in StructLayout_test.cpp.
 *
 * Since the struct must be aligned to an 8-byte boundary, there could be uninitialized bytes
 * in-between the defined fields. This padding data should be explicitly accounted for by adding
 * "empty" fields into the struct. This data is memset to zero before sending the struct across
 * the socket. Adding the explicit fields ensures that the memset is not optimized away by the
 * compiler. When a new field is added to the struct, the corresponding change
 * in StructLayout_test should be made.
 */
struct InputMessage {
    enum class Type : uint32_t {
        KEY,
        MOTION,
        FINISHED,
        FOCUS,
        CAPTURE,
        DRAG,
        TIMELINE,
        TOUCH_MODE,

        ftl_last = TOUCH_MODE
    };

    struct Header {
        Type type; // 4 bytes
        uint32_t seq;
    } header;

    // For keys and motions, rely on the fact that std::array takes up exactly as much space
    // as the underlying data. This is not guaranteed by C++, but it simplifies the conversions.
    static_assert(sizeof(std::array<uint8_t, 32>) == 32);

    // For bool values, rely on the fact that they take up exactly one byte. This is not guaranteed
    // by C++ and is implementation-dependent, but it simplifies the conversions.
    static_assert(sizeof(bool) == 1);

    // Body *must* be 8 byte aligned.
    union Body {
        struct Key {
            int32_t eventId;
            uint32_t empty1;
            nsecs_t eventTime __attribute__((aligned(8)));
            int32_t deviceId;
            int32_t source;
            int32_t displayId;
            std::array<uint8_t, 32> hmac;
            int32_t action;
            int32_t flags;
            int32_t keyCode;
            int32_t scanCode;
            int32_t metaState;
            int32_t repeatCount;
            uint32_t empty2;
            nsecs_t downTime __attribute__((aligned(8)));

            inline size_t size() const { return sizeof(Key); }
        } key;

        struct Motion {
            int32_t eventId;
            uint32_t pointerCount;
            nsecs_t eventTime __attribute__((aligned(8)));
            int32_t deviceId;
            int32_t source;
            int32_t displayId;
            std::array<uint8_t, 32> hmac;
            int32_t action;
            int32_t actionButton;
            int32_t flags;
            int32_t metaState;
            int32_t buttonState;
            MotionClassification classification; // base type: uint8_t
            uint8_t empty2[3];                   // 3 bytes to fill gap created by classification
            int32_t edgeFlags;
            nsecs_t downTime __attribute__((aligned(8)));
            float dsdx; // Begin window transform
            float dtdx; //
            float dtdy; //
            float dsdy; //
            float tx;   //
            float ty;   // End window transform
            float xPrecision;
            float yPrecision;
            float xCursorPosition;
            float yCursorPosition;
            float dsdxRaw; // Begin raw transform
            float dtdxRaw; //
            float dtdyRaw; //
            float dsdyRaw; //
            float txRaw;   //
            float tyRaw;   // End raw transform
            /**
             * The "pointers" field must be the last field of the struct InputMessage.
             * When we send the struct InputMessage across the socket, we are not
             * writing the entire "pointers" array, but only the pointerCount portion
             * of it as an optimization. Adding a field after "pointers" would break this.
             */
            struct Pointer {
                PointerProperties properties;
                PointerCoords coords;
            } pointers[MAX_POINTERS] __attribute__((aligned(8)));

            int32_t getActionId() const {
                uint32_t index = (action & AMOTION_EVENT_ACTION_POINTER_INDEX_MASK)
                        >> AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
                return pointers[index].properties.id;
            }

            inline size_t size() const {
                return sizeof(Motion) - sizeof(Pointer) * MAX_POINTERS
                        + sizeof(Pointer) * pointerCount;
            }
        } motion;

        struct Finished {
            bool handled;
            uint8_t empty[7];
            nsecs_t consumeTime; // The time when the event was consumed by the receiving end

            inline size_t size() const { return sizeof(Finished); }
        } finished;

        struct Focus {
            int32_t eventId;
            // The following 2 fields take up 4 bytes total
            bool hasFocus;
            uint8_t empty[3];

            inline size_t size() const { return sizeof(Focus); }
        } focus;

        struct Capture {
            int32_t eventId;
            bool pointerCaptureEnabled;
            uint8_t empty[3];

            inline size_t size() const { return sizeof(Capture); }
        } capture;

        struct Drag {
            int32_t eventId;
            float x;
            float y;
            bool isExiting;
            uint8_t empty[3];

            inline size_t size() const { return sizeof(Drag); }
        } drag;

        struct Timeline {
            int32_t eventId;
            uint32_t empty;
            std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline;

            inline size_t size() const { return sizeof(Timeline); }
        } timeline;

        struct TouchMode {
            int32_t eventId;
            // The following 2 fields take up 4 bytes total
            bool isInTouchMode;
            uint8_t empty[3];

            inline size_t size() const { return sizeof(TouchMode); }
        } touchMode;
    } __attribute__((aligned(8))) body;

    bool isValid(size_t actualSize) const;
    size_t size() const;
    void getSanitizedCopy(InputMessage* msg) const;
};

/*
 * An input channel consists of a local unix domain socket used to send and receive
 * input messages across processes.  Each channel has a descriptive name for debugging purposes.
 *
 * Each endpoint has its own InputChannel object that specifies its file descriptor.
 * For parceling, this relies on android::os::InputChannelCore, defined in aidl.
 *
 * The input channel is closed when all references to it are released.
 */
class InputChannel : private android::os::InputChannelCore {
public:
    static std::unique_ptr<InputChannel> create(android::os::InputChannelCore&& parceledChannel);
    ~InputChannel();

    /**
     * Create a pair of input channels.
     * The two returned input channels are equivalent, and are labeled as "server" and "client"
     * for convenience. The two input channels share the same token.
     *
     * Return OK on success.
     */
    static status_t openInputChannelPair(const std::string& name,
                                         std::unique_ptr<InputChannel>& outServerChannel,
                                         std::unique_ptr<InputChannel>& outClientChannel);

    inline std::string getName() const { return name; }
    inline int getFd() const { return fd.get(); }

    /* Send a message to the other endpoint.
     *
     * If the channel is full then the message is guaranteed not to have been sent at all.
     * Try again after the consumer has sent a finished signal indicating that it has
     * consumed some of the pending messages from the channel.
     *
     * Return OK on success.
     * Return WOULD_BLOCK if the channel is full.
     * Return DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t sendMessage(const InputMessage* msg);

    /* Receive a message sent by the other endpoint.
     *
     * If there is no message present, try again after poll() indicates that the fd
     * is readable.
     *
     * Return OK on success.
     * Return WOULD_BLOCK if there is no message present.
     * Return DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t receiveMessage(InputMessage* msg);

    /* Tells whether there is a message in the channel available to be received.
     *
     * This is only a performance hint and may return false negative results. Clients should not
     * rely on availability of the message based on the return value.
     */
    bool probablyHasInput() const;

    /* Wait until there is a message in the channel.
     *
     * The |timeout| specifies how long to block waiting for an input event to appear. Negative
     * values are not allowed.
     *
     * In some cases returning before timeout expiration can happen without a message available.
     * This could happen after the channel was closed on the other side. Another possible reason
     * is incorrect setup of the channel.
     */
    void waitForMessage(std::chrono::milliseconds timeout) const;

    /* Return a new object that has a duplicate of this channel's fd. */
    std::unique_ptr<InputChannel> dup() const;

    void copyTo(android::os::InputChannelCore& outChannel) const;

    /**
     * Similar to "copyTo", but it takes ownership of the provided InputChannel (and after this is
     * called, it destroys it).
     * @param from the InputChannel that should be converted to InputChannelCore
     * @param outChannel the pre-allocated InputChannelCore to which to transfer the 'from' channel
     */
    static void moveChannel(std::unique_ptr<InputChannel> from,
                            android::os::InputChannelCore& outChannel);

    /**
     * The connection token is used to identify the input connection, i.e.
     * the pair of input channels that were created simultaneously. Input channels
     * are always created in pairs, and the token can be used to find the server-side
     * input channel from the client-side input channel, and vice versa.
     *
     * Do not use connection token to check equality of a specific input channel object
     * to another, because two different (client and server) input channels will share the
     * same connection token.
     *
     * Return the token that identifies this connection.
     */
    sp<IBinder> getConnectionToken() const;

private:
    static std::unique_ptr<InputChannel> create(const std::string& name,
                                                android::base::unique_fd fd, sp<IBinder> token);

    InputChannel(const std::string name, android::base::unique_fd fd, sp<IBinder> token);
};

/*
 * Publishes input events to an input channel.
 */
class InputPublisher {
public:
    /* Creates a publisher associated with an input channel. */
    explicit InputPublisher(const std::shared_ptr<InputChannel>& channel);

    /* Destroys the publisher and releases its input channel. */
    ~InputPublisher();

    /* Gets the underlying input channel. */
    inline InputChannel& getChannel() const { return *mChannel; }

    /* Publishes a key event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Returns BAD_VALUE if seq is 0.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishKeyEvent(uint32_t seq, int32_t eventId, int32_t deviceId, int32_t source,
                             int32_t displayId, std::array<uint8_t, 32> hmac, int32_t action,
                             int32_t flags, int32_t keyCode, int32_t scanCode, int32_t metaState,
                             int32_t repeatCount, nsecs_t downTime, nsecs_t eventTime);

    /* Publishes a motion event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Returns BAD_VALUE if seq is 0 or if pointerCount is less than 1 or greater than MAX_POINTERS.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishMotionEvent(uint32_t seq, int32_t eventId, int32_t deviceId, int32_t source,
                                int32_t displayId, std::array<uint8_t, 32> hmac, int32_t action,
                                int32_t actionButton, int32_t flags, int32_t edgeFlags,
                                int32_t metaState, int32_t buttonState,
                                MotionClassification classification, const ui::Transform& transform,
                                float xPrecision, float yPrecision, float xCursorPosition,
                                float yCursorPosition, const ui::Transform& rawTransform,
                                nsecs_t downTime, nsecs_t eventTime, uint32_t pointerCount,
                                const PointerProperties* pointerProperties,
                                const PointerCoords* pointerCoords);

    /* Publishes a focus event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishFocusEvent(uint32_t seq, int32_t eventId, bool hasFocus);

    /* Publishes a capture event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishCaptureEvent(uint32_t seq, int32_t eventId, bool pointerCaptureEnabled);

    /* Publishes a drag event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishDragEvent(uint32_t seq, int32_t eventId, float x, float y, bool isExiting);

    /* Publishes a touch mode event to the input channel.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if the channel is full.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Other errors probably indicate that the channel is broken.
     */
    status_t publishTouchModeEvent(uint32_t seq, int32_t eventId, bool isInTouchMode);

    struct Finished {
        uint32_t seq;
        bool handled;
        nsecs_t consumeTime;
    };

    struct Timeline {
        int32_t inputEventId;
        std::array<nsecs_t, GraphicsTimeline::SIZE> graphicsTimeline;
    };

    typedef std::variant<Finished, Timeline> ConsumerResponse;
    /* Receive a signal from the consumer in reply to the original dispatch signal.
     * If a signal was received, returns a Finished or a Timeline object.
     * The InputConsumer should return a Finished object for every InputMessage that it is sent
     * to confirm that it has been processed and that the InputConsumer is responsive.
     * If several InputMessages are sent to InputConsumer, it's possible to receive Finished
     * events out of order for those messages.
     *
     * The Timeline object is returned whenever the receiving end has processed a graphical frame
     * and is returning the timeline of the frame. Not all input events will cause a Timeline
     * object to be returned, and there is not guarantee about when it will arrive.
     *
     * If an object of Finished is returned, the returned sequence number is never 0 unless the
     * operation failed.
     *
     * Returned error codes:
     *         OK on success.
     *         WOULD_BLOCK if there is no signal present.
     *         DEAD_OBJECT if the channel's peer has been closed.
     *         Other errors probably indicate that the channel is broken.
     */
    android::base::Result<ConsumerResponse> receiveConsumerResponse();

private:
    std::shared_ptr<InputChannel> mChannel;
    InputVerifier mInputVerifier;
};

} // namespace android
