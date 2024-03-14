//
// Copyright 2010 The Android Open Source Project
//
// Provides a shared memory transport for input events.
//
#define LOG_TAG "InputTransport"
#define ATRACE_TAG ATRACE_TAG_INPUT

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <binder/Parcel.h>
#include <cutils/properties.h>
#include <ftl/enum.h>
#include <log/log.h>
#include <utils/Trace.h>

#include <com_android_input_flags.h>
#include <input/InputTransport.h>
#include <input/PrintTools.h>
#include <input/TraceTools.h>

namespace input_flags = com::android::input::flags;

namespace android {

namespace {

/**
 * Log debug messages about channel messages (send message, receive message).
 * Enable this via "adb shell setprop log.tag.InputTransportMessages DEBUG"
 * (requires restart)
 */
const bool DEBUG_CHANNEL_MESSAGES =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Messages", ANDROID_LOG_INFO);

/**
 * Log debug messages whenever InputChannel objects are created/destroyed.
 * Enable this via "adb shell setprop log.tag.InputTransportLifecycle DEBUG"
 * (requires restart)
 */
const bool DEBUG_CHANNEL_LIFECYCLE =
        __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Lifecycle", ANDROID_LOG_INFO);

const bool IS_DEBUGGABLE_BUILD =
#if defined(__ANDROID__)
        android::base::GetBoolProperty("ro.debuggable", false);
#else
        true;
#endif

/**
 * Log debug messages relating to the producer end of the transport channel.
 * Enable this via "adb shell setprop log.tag.InputTransportPublisher DEBUG".
 * This requires a restart on non-debuggable (e.g. user) builds, but should take effect immediately
 * on debuggable builds (e.g. userdebug).
 */
bool debugTransportPublisher() {
    if (!IS_DEBUGGABLE_BUILD) {
        static const bool DEBUG_TRANSPORT_PUBLISHER =
                __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Publisher", ANDROID_LOG_INFO);
        return DEBUG_TRANSPORT_PUBLISHER;
    }
    return __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "Publisher", ANDROID_LOG_INFO);
}

android::base::unique_fd dupChannelFd(int fd) {
    android::base::unique_fd newFd(::dup(fd));
    if (!newFd.ok()) {
        ALOGE("Could not duplicate fd %i : %s", fd, strerror(errno));
        const bool hitFdLimit = errno == EMFILE || errno == ENFILE;
        // If this process is out of file descriptors, then throwing that might end up exploding
        // on the other side of a binder call, which isn't really helpful.
        // Better to just crash here and hope that the FD leak is slow.
        // Other failures could be client errors, so we still propagate those back to the caller.
        LOG_ALWAYS_FATAL_IF(hitFdLimit, "Too many open files, could not duplicate input channel");
        return {};
    }
    return newFd;
}

// Socket buffer size.  The default is typically about 128KB, which is much larger than
// we really need.  So we make it smaller.  It just needs to be big enough to hold
// a few dozen large multi-finger motion events in the case where an application gets
// behind processing touches.
constexpr size_t SOCKET_BUFFER_SIZE = 32 * 1024;

/**
 * Crash if the events that are getting sent to the InputPublisher are inconsistent.
 * Enable this via "adb shell setprop log.tag.InputTransportVerifyEvents DEBUG"
 */
bool verifyEvents() {
    return input_flags::enable_outbound_event_verification() ||
            __android_log_is_loggable(ANDROID_LOG_DEBUG, LOG_TAG "VerifyEvents", ANDROID_LOG_INFO);
}

} // namespace

using android::base::Result;
using android::base::StringPrintf;

// --- InputMessage ---

bool InputMessage::isValid(size_t actualSize) const {
    if (size() != actualSize) {
        ALOGE("Received message of incorrect size %zu (expected %zu)", actualSize, size());
        return false;
    }

    switch (header.type) {
        case Type::KEY:
            return true;
        case Type::MOTION: {
            const bool valid =
                    body.motion.pointerCount > 0 && body.motion.pointerCount <= MAX_POINTERS;
            if (!valid) {
                ALOGE("Received invalid MOTION: pointerCount = %" PRIu32, body.motion.pointerCount);
            }
            return valid;
        }
        case Type::FINISHED:
        case Type::FOCUS:
        case Type::CAPTURE:
        case Type::DRAG:
        case Type::TOUCH_MODE:
            return true;
        case Type::TIMELINE: {
            const nsecs_t gpuCompletedTime =
                    body.timeline.graphicsTimeline[GraphicsTimeline::GPU_COMPLETED_TIME];
            const nsecs_t presentTime =
                    body.timeline.graphicsTimeline[GraphicsTimeline::PRESENT_TIME];
            const bool valid = presentTime > gpuCompletedTime;
            if (!valid) {
                ALOGE("Received invalid TIMELINE: gpuCompletedTime = %" PRId64
                      " presentTime = %" PRId64,
                      gpuCompletedTime, presentTime);
            }
            return valid;
        }
    }
    ALOGE("Invalid message type: %s", ftl::enum_string(header.type).c_str());
    return false;
}

size_t InputMessage::size() const {
    switch (header.type) {
        case Type::KEY:
            return sizeof(Header) + body.key.size();
        case Type::MOTION:
            return sizeof(Header) + body.motion.size();
        case Type::FINISHED:
            return sizeof(Header) + body.finished.size();
        case Type::FOCUS:
            return sizeof(Header) + body.focus.size();
        case Type::CAPTURE:
            return sizeof(Header) + body.capture.size();
        case Type::DRAG:
            return sizeof(Header) + body.drag.size();
        case Type::TIMELINE:
            return sizeof(Header) + body.timeline.size();
        case Type::TOUCH_MODE:
            return sizeof(Header) + body.touchMode.size();
    }
    return sizeof(Header);
}

/**
 * There could be non-zero bytes in-between InputMessage fields. Force-initialize the entire
 * memory to zero, then only copy the valid bytes on a per-field basis.
 */
void InputMessage::getSanitizedCopy(InputMessage* msg) const {
    memset(msg, 0, sizeof(*msg));

    // Write the header
    msg->header.type = header.type;
    msg->header.seq = header.seq;

    // Write the body
    switch(header.type) {
        case InputMessage::Type::KEY: {
            // int32_t eventId
            msg->body.key.eventId = body.key.eventId;
            // nsecs_t eventTime
            msg->body.key.eventTime = body.key.eventTime;
            // int32_t deviceId
            msg->body.key.deviceId = body.key.deviceId;
            // int32_t source
            msg->body.key.source = body.key.source;
            // int32_t displayId
            msg->body.key.displayId = body.key.displayId;
            // std::array<uint8_t, 32> hmac
            msg->body.key.hmac = body.key.hmac;
            // int32_t action
            msg->body.key.action = body.key.action;
            // int32_t flags
            msg->body.key.flags = body.key.flags;
            // int32_t keyCode
            msg->body.key.keyCode = body.key.keyCode;
            // int32_t scanCode
            msg->body.key.scanCode = body.key.scanCode;
            // int32_t metaState
            msg->body.key.metaState = body.key.metaState;
            // int32_t repeatCount
            msg->body.key.repeatCount = body.key.repeatCount;
            // nsecs_t downTime
            msg->body.key.downTime = body.key.downTime;
            break;
        }
        case InputMessage::Type::MOTION: {
            // int32_t eventId
            msg->body.motion.eventId = body.motion.eventId;
            // uint32_t pointerCount
            msg->body.motion.pointerCount = body.motion.pointerCount;
            // nsecs_t eventTime
            msg->body.motion.eventTime = body.motion.eventTime;
            // int32_t deviceId
            msg->body.motion.deviceId = body.motion.deviceId;
            // int32_t source
            msg->body.motion.source = body.motion.source;
            // int32_t displayId
            msg->body.motion.displayId = body.motion.displayId;
            // std::array<uint8_t, 32> hmac
            msg->body.motion.hmac = body.motion.hmac;
            // int32_t action
            msg->body.motion.action = body.motion.action;
            // int32_t actionButton
            msg->body.motion.actionButton = body.motion.actionButton;
            // int32_t flags
            msg->body.motion.flags = body.motion.flags;
            // int32_t metaState
            msg->body.motion.metaState = body.motion.metaState;
            // int32_t buttonState
            msg->body.motion.buttonState = body.motion.buttonState;
            // MotionClassification classification
            msg->body.motion.classification = body.motion.classification;
            // int32_t edgeFlags
            msg->body.motion.edgeFlags = body.motion.edgeFlags;
            // nsecs_t downTime
            msg->body.motion.downTime = body.motion.downTime;

            msg->body.motion.dsdx = body.motion.dsdx;
            msg->body.motion.dtdx = body.motion.dtdx;
            msg->body.motion.dtdy = body.motion.dtdy;
            msg->body.motion.dsdy = body.motion.dsdy;
            msg->body.motion.tx = body.motion.tx;
            msg->body.motion.ty = body.motion.ty;

            // float xPrecision
            msg->body.motion.xPrecision = body.motion.xPrecision;
            // float yPrecision
            msg->body.motion.yPrecision = body.motion.yPrecision;
            // float xCursorPosition
            msg->body.motion.xCursorPosition = body.motion.xCursorPosition;
            // float yCursorPosition
            msg->body.motion.yCursorPosition = body.motion.yCursorPosition;

            msg->body.motion.dsdxRaw = body.motion.dsdxRaw;
            msg->body.motion.dtdxRaw = body.motion.dtdxRaw;
            msg->body.motion.dtdyRaw = body.motion.dtdyRaw;
            msg->body.motion.dsdyRaw = body.motion.dsdyRaw;
            msg->body.motion.txRaw = body.motion.txRaw;
            msg->body.motion.tyRaw = body.motion.tyRaw;

            //struct Pointer pointers[MAX_POINTERS]
            for (size_t i = 0; i < body.motion.pointerCount; i++) {
                // PointerProperties properties
                msg->body.motion.pointers[i].properties.id = body.motion.pointers[i].properties.id;
                msg->body.motion.pointers[i].properties.toolType =
                        body.motion.pointers[i].properties.toolType,
                // PointerCoords coords
                msg->body.motion.pointers[i].coords.bits = body.motion.pointers[i].coords.bits;
                const uint32_t count = BitSet64::count(body.motion.pointers[i].coords.bits);
                memcpy(&msg->body.motion.pointers[i].coords.values[0],
                        &body.motion.pointers[i].coords.values[0],
                        count * (sizeof(body.motion.pointers[i].coords.values[0])));
                msg->body.motion.pointers[i].coords.isResampled =
                        body.motion.pointers[i].coords.isResampled;
            }
            break;
        }
        case InputMessage::Type::FINISHED: {
            msg->body.finished.handled = body.finished.handled;
            msg->body.finished.consumeTime = body.finished.consumeTime;
            break;
        }
        case InputMessage::Type::FOCUS: {
            msg->body.focus.eventId = body.focus.eventId;
            msg->body.focus.hasFocus = body.focus.hasFocus;
            break;
        }
        case InputMessage::Type::CAPTURE: {
            msg->body.capture.eventId = body.capture.eventId;
            msg->body.capture.pointerCaptureEnabled = body.capture.pointerCaptureEnabled;
            break;
        }
        case InputMessage::Type::DRAG: {
            msg->body.drag.eventId = body.drag.eventId;
            msg->body.drag.x = body.drag.x;
            msg->body.drag.y = body.drag.y;
            msg->body.drag.isExiting = body.drag.isExiting;
            break;
        }
        case InputMessage::Type::TIMELINE: {
            msg->body.timeline.eventId = body.timeline.eventId;
            msg->body.timeline.graphicsTimeline = body.timeline.graphicsTimeline;
            break;
        }
        case InputMessage::Type::TOUCH_MODE: {
            msg->body.touchMode.eventId = body.touchMode.eventId;
            msg->body.touchMode.isInTouchMode = body.touchMode.isInTouchMode;
        }
    }
}

// --- InputChannel ---

std::unique_ptr<InputChannel> InputChannel::create(const std::string& name,
                                                   android::base::unique_fd fd, sp<IBinder> token) {
    const int result = fcntl(fd, F_SETFL, O_NONBLOCK);
    if (result != 0) {
        LOG_ALWAYS_FATAL("channel '%s' ~ Could not make socket non-blocking: %s", name.c_str(),
                         strerror(errno));
        return nullptr;
    }
    // using 'new' to access a non-public constructor
    return std::unique_ptr<InputChannel>(new InputChannel(name, std::move(fd), token));
}

std::unique_ptr<InputChannel> InputChannel::create(
        android::os::InputChannelCore&& parceledChannel) {
    return InputChannel::create(parceledChannel.name, parceledChannel.fd.release(),
                                parceledChannel.token);
}

InputChannel::InputChannel(const std::string name, android::base::unique_fd fd, sp<IBinder> token) {
    this->name = std::move(name);
    this->fd.reset(std::move(fd));
    this->token = std::move(token);
    ALOGD_IF(DEBUG_CHANNEL_LIFECYCLE, "Input channel constructed: name='%s', fd=%d",
             getName().c_str(), getFd());
}

InputChannel::~InputChannel() {
    ALOGD_IF(DEBUG_CHANNEL_LIFECYCLE, "Input channel destroyed: name='%s', fd=%d",
             getName().c_str(), getFd());
}

status_t InputChannel::openInputChannelPair(const std::string& name,
                                            std::unique_ptr<InputChannel>& outServerChannel,
                                            std::unique_ptr<InputChannel>& outClientChannel) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets)) {
        status_t result = -errno;
        ALOGE("channel '%s' ~ Could not create socket pair.  errno=%s(%d)", name.c_str(),
              strerror(errno), errno);
        outServerChannel.reset();
        outClientChannel.reset();
        return result;
    }

    int bufferSize = SOCKET_BUFFER_SIZE;
    setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(sockets[0], SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(sockets[1], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(sockets[1], SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));

    sp<IBinder> token = sp<BBinder>::make();

    std::string serverChannelName = name + " (server)";
    android::base::unique_fd serverFd(sockets[0]);
    outServerChannel = InputChannel::create(serverChannelName, std::move(serverFd), token);

    std::string clientChannelName = name + " (client)";
    android::base::unique_fd clientFd(sockets[1]);
    outClientChannel = InputChannel::create(clientChannelName, std::move(clientFd), token);
    return OK;
}

status_t InputChannel::sendMessage(const InputMessage* msg) {
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("sendMessage(inputChannel=%s, seq=0x%" PRIx32 ", type=0x%" PRIx32
                                ")",
                                name.c_str(), msg->header.seq, msg->header.type));
    const size_t msgLength = msg->size();
    InputMessage cleanMsg;
    msg->getSanitizedCopy(&cleanMsg);
    ssize_t nWrite;
    do {
        nWrite = ::send(getFd(), &cleanMsg, msgLength, MSG_DONTWAIT | MSG_NOSIGNAL);
    } while (nWrite == -1 && errno == EINTR);

    if (nWrite < 0) {
        int error = errno;
        ALOGD_IF(DEBUG_CHANNEL_MESSAGES, "channel '%s' ~ error sending message of type %s, %s",
                 name.c_str(), ftl::enum_string(msg->header.type).c_str(), strerror(error));
        if (error == EAGAIN || error == EWOULDBLOCK) {
            return WOULD_BLOCK;
        }
        if (error == EPIPE || error == ENOTCONN || error == ECONNREFUSED || error == ECONNRESET) {
            return DEAD_OBJECT;
        }
        return -error;
    }

    if (size_t(nWrite) != msgLength) {
        ALOGD_IF(DEBUG_CHANNEL_MESSAGES,
                 "channel '%s' ~ error sending message type %s, send was incomplete", name.c_str(),
                 ftl::enum_string(msg->header.type).c_str());
        return DEAD_OBJECT;
    }

    ALOGD_IF(DEBUG_CHANNEL_MESSAGES, "channel '%s' ~ sent message of type %s", name.c_str(),
             ftl::enum_string(msg->header.type).c_str());

    return OK;
}

status_t InputChannel::receiveMessage(InputMessage* msg) {
    ssize_t nRead;
    do {
        nRead = ::recv(getFd(), msg, sizeof(InputMessage), MSG_DONTWAIT);
    } while (nRead == -1 && errno == EINTR);

    if (nRead < 0) {
        int error = errno;
        ALOGD_IF(DEBUG_CHANNEL_MESSAGES, "channel '%s' ~ receive message failed, errno=%d",
                 name.c_str(), errno);
        if (error == EAGAIN || error == EWOULDBLOCK) {
            return WOULD_BLOCK;
        }
        if (error == EPIPE || error == ENOTCONN || error == ECONNREFUSED) {
            return DEAD_OBJECT;
        }
        return -error;
    }

    if (nRead == 0) { // check for EOF
        ALOGD_IF(DEBUG_CHANNEL_MESSAGES,
                 "channel '%s' ~ receive message failed because peer was closed", name.c_str());
        return DEAD_OBJECT;
    }

    if (!msg->isValid(nRead)) {
        ALOGE("channel '%s' ~ received invalid message of size %zd", name.c_str(), nRead);
        return BAD_VALUE;
    }

    ALOGD_IF(DEBUG_CHANNEL_MESSAGES, "channel '%s' ~ received message of type %s", name.c_str(),
             ftl::enum_string(msg->header.type).c_str());
    if (ATRACE_ENABLED()) {
        // Add an additional trace point to include data about the received message.
        std::string message = StringPrintf("receiveMessage(inputChannel=%s, seq=0x%" PRIx32
                                           ", type=0x%" PRIx32 ")",
                                           name.c_str(), msg->header.seq, msg->header.type);
        ATRACE_NAME(message.c_str());
    }
    return OK;
}

bool InputChannel::probablyHasInput() const {
    struct pollfd pfds = {.fd = fd.get(), .events = POLLIN};
    if (::poll(&pfds, /*nfds=*/1, /*timeout=*/0) <= 0) {
        // This can be a false negative because EINTR and ENOMEM are not handled. The latter should
        // be extremely rare. The EINTR is also unlikely because it happens only when the signal
        // arrives while the syscall is executed, and the syscall is quick. Hitting EINTR too often
        // would be a sign of having too many signals, which is a bigger performance problem. A
        // common tradition is to repeat the syscall on each EINTR, but it is not necessary here.
        // In other words, the missing one liner is replaced by a multiline explanation.
        return false;
    }
    // From poll(2): The bits returned in |revents| can include any of those specified in |events|,
    // or one of the values POLLERR, POLLHUP, or POLLNVAL.
    return (pfds.revents & POLLIN) != 0;
}

void InputChannel::waitForMessage(std::chrono::milliseconds timeout) const {
    if (timeout < 0ms) {
        LOG(FATAL) << "Timeout cannot be negative, received " << timeout.count();
    }
    struct pollfd pfds = {.fd = fd.get(), .events = POLLIN};
    int ret;
    std::chrono::time_point<std::chrono::steady_clock> stopTime =
            std::chrono::steady_clock::now() + timeout;
    std::chrono::milliseconds remaining = timeout;
    do {
        ret = ::poll(&pfds, /*nfds=*/1, /*timeout=*/remaining.count());
        remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                stopTime - std::chrono::steady_clock::now());
    } while (ret == -1 && errno == EINTR && remaining > 0ms);
}

std::unique_ptr<InputChannel> InputChannel::dup() const {
    base::unique_fd newFd(dupChannelFd(fd.get()));
    return InputChannel::create(getName(), std::move(newFd), getConnectionToken());
}

void InputChannel::copyTo(android::os::InputChannelCore& outChannel) const {
    outChannel.name = getName();
    outChannel.fd.reset(dupChannelFd(fd.get()));
    outChannel.token = getConnectionToken();
}

void InputChannel::moveChannel(std::unique_ptr<InputChannel> from,
                               android::os::InputChannelCore& outChannel) {
    outChannel.name = from->getName();
    outChannel.fd = android::os::ParcelFileDescriptor(std::move(from->fd));
    outChannel.token = from->getConnectionToken();
}

sp<IBinder> InputChannel::getConnectionToken() const {
    return token;
}

// --- InputPublisher ---

InputPublisher::InputPublisher(const std::shared_ptr<InputChannel>& channel)
      : mChannel(channel), mInputVerifier(mChannel->getName()) {}

InputPublisher::~InputPublisher() {
}

status_t InputPublisher::publishKeyEvent(uint32_t seq, int32_t eventId, int32_t deviceId,
                                         int32_t source, int32_t displayId,
                                         std::array<uint8_t, 32> hmac, int32_t action,
                                         int32_t flags, int32_t keyCode, int32_t scanCode,
                                         int32_t metaState, int32_t repeatCount, nsecs_t downTime,
                                         nsecs_t eventTime) {
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("publishKeyEvent(inputChannel=%s, action=%s, keyCode=%s)",
                                mChannel->getName().c_str(), KeyEvent::actionToString(action),
                                KeyEvent::getLabel(keyCode)));
    ALOGD_IF(debugTransportPublisher(),
             "channel '%s' publisher ~ %s: seq=%u, id=%d, deviceId=%d, source=%s, "
             "action=%s, flags=0x%x, keyCode=%s, scanCode=%d, metaState=0x%x, repeatCount=%d,"
             "downTime=%" PRId64 ", eventTime=%" PRId64,
             mChannel->getName().c_str(), __func__, seq, eventId, deviceId,
             inputEventSourceToString(source).c_str(), KeyEvent::actionToString(action), flags,
             KeyEvent::getLabel(keyCode), scanCode, metaState, repeatCount, downTime, eventTime);

    if (!seq) {
        ALOGE("Attempted to publish a key event with sequence number 0.");
        return BAD_VALUE;
    }

    InputMessage msg;
    msg.header.type = InputMessage::Type::KEY;
    msg.header.seq = seq;
    msg.body.key.eventId = eventId;
    msg.body.key.deviceId = deviceId;
    msg.body.key.source = source;
    msg.body.key.displayId = displayId;
    msg.body.key.hmac = std::move(hmac);
    msg.body.key.action = action;
    msg.body.key.flags = flags;
    msg.body.key.keyCode = keyCode;
    msg.body.key.scanCode = scanCode;
    msg.body.key.metaState = metaState;
    msg.body.key.repeatCount = repeatCount;
    msg.body.key.downTime = downTime;
    msg.body.key.eventTime = eventTime;
    return mChannel->sendMessage(&msg);
}

status_t InputPublisher::publishMotionEvent(
        uint32_t seq, int32_t eventId, int32_t deviceId, int32_t source, int32_t displayId,
        std::array<uint8_t, 32> hmac, int32_t action, int32_t actionButton, int32_t flags,
        int32_t edgeFlags, int32_t metaState, int32_t buttonState,
        MotionClassification classification, const ui::Transform& transform, float xPrecision,
        float yPrecision, float xCursorPosition, float yCursorPosition,
        const ui::Transform& rawTransform, nsecs_t downTime, nsecs_t eventTime,
        uint32_t pointerCount, const PointerProperties* pointerProperties,
        const PointerCoords* pointerCoords) {
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("publishMotionEvent(inputChannel=%s, action=%s)",
                                mChannel->getName().c_str(),
                                MotionEvent::actionToString(action).c_str()));
    if (verifyEvents()) {
        Result<void> result =
                mInputVerifier.processMovement(deviceId, source, action, pointerCount,
                                               pointerProperties, pointerCoords, flags);
        if (!result.ok()) {
            LOG(FATAL) << "Bad stream: " << result.error();
        }
    }
    if (debugTransportPublisher()) {
        std::string transformString;
        transform.dump(transformString, "transform", "        ");
        ALOGD("channel '%s' publisher ~ %s: seq=%u, id=%d, deviceId=%d, source=%s, "
              "displayId=%" PRId32 ", "
              "action=%s, actionButton=0x%08x, flags=0x%x, edgeFlags=0x%x, "
              "metaState=0x%x, buttonState=0x%x, classification=%s,"
              "xPrecision=%f, yPrecision=%f, downTime=%" PRId64 ", eventTime=%" PRId64 ", "
              "pointerCount=%" PRIu32 "\n%s",
              mChannel->getName().c_str(), __func__, seq, eventId, deviceId,
              inputEventSourceToString(source).c_str(), displayId,
              MotionEvent::actionToString(action).c_str(), actionButton, flags, edgeFlags,
              metaState, buttonState, motionClassificationToString(classification), xPrecision,
              yPrecision, downTime, eventTime, pointerCount, transformString.c_str());
    }

    if (!seq) {
        ALOGE("Attempted to publish a motion event with sequence number 0.");
        return BAD_VALUE;
    }

    if (pointerCount > MAX_POINTERS || pointerCount < 1) {
        ALOGE("channel '%s' publisher ~ Invalid number of pointers provided: %" PRIu32 ".",
                mChannel->getName().c_str(), pointerCount);
        return BAD_VALUE;
    }

    InputMessage msg;
    msg.header.type = InputMessage::Type::MOTION;
    msg.header.seq = seq;
    msg.body.motion.eventId = eventId;
    msg.body.motion.deviceId = deviceId;
    msg.body.motion.source = source;
    msg.body.motion.displayId = displayId;
    msg.body.motion.hmac = std::move(hmac);
    msg.body.motion.action = action;
    msg.body.motion.actionButton = actionButton;
    msg.body.motion.flags = flags;
    msg.body.motion.edgeFlags = edgeFlags;
    msg.body.motion.metaState = metaState;
    msg.body.motion.buttonState = buttonState;
    msg.body.motion.classification = classification;
    msg.body.motion.dsdx = transform.dsdx();
    msg.body.motion.dtdx = transform.dtdx();
    msg.body.motion.dtdy = transform.dtdy();
    msg.body.motion.dsdy = transform.dsdy();
    msg.body.motion.tx = transform.tx();
    msg.body.motion.ty = transform.ty();
    msg.body.motion.xPrecision = xPrecision;
    msg.body.motion.yPrecision = yPrecision;
    msg.body.motion.xCursorPosition = xCursorPosition;
    msg.body.motion.yCursorPosition = yCursorPosition;
    msg.body.motion.dsdxRaw = rawTransform.dsdx();
    msg.body.motion.dtdxRaw = rawTransform.dtdx();
    msg.body.motion.dtdyRaw = rawTransform.dtdy();
    msg.body.motion.dsdyRaw = rawTransform.dsdy();
    msg.body.motion.txRaw = rawTransform.tx();
    msg.body.motion.tyRaw = rawTransform.ty();
    msg.body.motion.downTime = downTime;
    msg.body.motion.eventTime = eventTime;
    msg.body.motion.pointerCount = pointerCount;
    for (uint32_t i = 0; i < pointerCount; i++) {
        msg.body.motion.pointers[i].properties = pointerProperties[i];
        msg.body.motion.pointers[i].coords = pointerCoords[i];
    }

    return mChannel->sendMessage(&msg);
}

status_t InputPublisher::publishFocusEvent(uint32_t seq, int32_t eventId, bool hasFocus) {
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("publishFocusEvent(inputChannel=%s, hasFocus=%s)",
                                mChannel->getName().c_str(), toString(hasFocus)));
    ALOGD_IF(debugTransportPublisher(), "channel '%s' publisher ~ %s: seq=%u, id=%d, hasFocus=%s",
             mChannel->getName().c_str(), __func__, seq, eventId, toString(hasFocus));

    InputMessage msg;
    msg.header.type = InputMessage::Type::FOCUS;
    msg.header.seq = seq;
    msg.body.focus.eventId = eventId;
    msg.body.focus.hasFocus = hasFocus;
    return mChannel->sendMessage(&msg);
}

status_t InputPublisher::publishCaptureEvent(uint32_t seq, int32_t eventId,
                                             bool pointerCaptureEnabled) {
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("publishCaptureEvent(inputChannel=%s, pointerCaptureEnabled=%s)",
                                mChannel->getName().c_str(), toString(pointerCaptureEnabled)));
    ALOGD_IF(debugTransportPublisher(),
             "channel '%s' publisher ~ %s: seq=%u, id=%d, pointerCaptureEnabled=%s",
             mChannel->getName().c_str(), __func__, seq, eventId, toString(pointerCaptureEnabled));

    InputMessage msg;
    msg.header.type = InputMessage::Type::CAPTURE;
    msg.header.seq = seq;
    msg.body.capture.eventId = eventId;
    msg.body.capture.pointerCaptureEnabled = pointerCaptureEnabled;
    return mChannel->sendMessage(&msg);
}

status_t InputPublisher::publishDragEvent(uint32_t seq, int32_t eventId, float x, float y,
                                          bool isExiting) {
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("publishDragEvent(inputChannel=%s, x=%f, y=%f, isExiting=%s)",
                                mChannel->getName().c_str(), x, y, toString(isExiting)));
    ALOGD_IF(debugTransportPublisher(),
             "channel '%s' publisher ~ %s: seq=%u, id=%d, x=%f, y=%f, isExiting=%s",
             mChannel->getName().c_str(), __func__, seq, eventId, x, y, toString(isExiting));

    InputMessage msg;
    msg.header.type = InputMessage::Type::DRAG;
    msg.header.seq = seq;
    msg.body.drag.eventId = eventId;
    msg.body.drag.isExiting = isExiting;
    msg.body.drag.x = x;
    msg.body.drag.y = y;
    return mChannel->sendMessage(&msg);
}

status_t InputPublisher::publishTouchModeEvent(uint32_t seq, int32_t eventId, bool isInTouchMode) {
    ATRACE_NAME_IF(ATRACE_ENABLED(),
                   StringPrintf("publishTouchModeEvent(inputChannel=%s, isInTouchMode=%s)",
                                mChannel->getName().c_str(), toString(isInTouchMode)));
    ALOGD_IF(debugTransportPublisher(),
             "channel '%s' publisher ~ %s: seq=%u, id=%d, isInTouchMode=%s",
             mChannel->getName().c_str(), __func__, seq, eventId, toString(isInTouchMode));

    InputMessage msg;
    msg.header.type = InputMessage::Type::TOUCH_MODE;
    msg.header.seq = seq;
    msg.body.touchMode.eventId = eventId;
    msg.body.touchMode.isInTouchMode = isInTouchMode;
    return mChannel->sendMessage(&msg);
}

android::base::Result<InputPublisher::ConsumerResponse> InputPublisher::receiveConsumerResponse() {
    InputMessage msg;
    status_t result = mChannel->receiveMessage(&msg);
    if (result) {
        if (debugTransportPublisher() && result != WOULD_BLOCK) {
            LOG(INFO) << "channel '" << mChannel->getName() << "' publisher ~ " << __func__ << ": "
                      << strerror(result);
        }
        return android::base::Error(result);
    }
    if (msg.header.type == InputMessage::Type::FINISHED) {
        ALOGD_IF(debugTransportPublisher(),
                 "channel '%s' publisher ~ %s: finished: seq=%u, handled=%s",
                 mChannel->getName().c_str(), __func__, msg.header.seq,
                 toString(msg.body.finished.handled));
        return Finished{
                .seq = msg.header.seq,
                .handled = msg.body.finished.handled,
                .consumeTime = msg.body.finished.consumeTime,
        };
    }

    if (msg.header.type == InputMessage::Type::TIMELINE) {
        ALOGD_IF(debugTransportPublisher(), "channel '%s' publisher ~ %s: timeline: id=%d",
                 mChannel->getName().c_str(), __func__, msg.body.timeline.eventId);
        return Timeline{
                .inputEventId = msg.body.timeline.eventId,
                .graphicsTimeline = msg.body.timeline.graphicsTimeline,
        };
    }

    ALOGE("channel '%s' publisher ~ Received unexpected %s message from consumer",
          mChannel->getName().c_str(), ftl::enum_string(msg.header.type).c_str());
    return android::base::Error(UNKNOWN_ERROR);
}

} // namespace android
