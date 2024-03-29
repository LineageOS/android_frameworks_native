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

/*
 * Native input transport.
 *
 * The InputConsumer is used by the application to receive events from the input dispatcher.
 */

#include "InputTransport.h"

namespace android {

/*
 * Consumes input events from an input channel.
 */
class InputConsumer {
public:
    /* Create a consumer associated with an input channel. */
    explicit InputConsumer(const std::shared_ptr<InputChannel>& channel);
    /* Create a consumer associated with an input channel, override resampling system property */
    explicit InputConsumer(const std::shared_ptr<InputChannel>& channel,
                           bool enableTouchResampling);

    /* Destroys the consumer and releases its input channel. */
    ~InputConsumer();

    /* Gets the underlying input channel. */
    inline std::shared_ptr<InputChannel> getChannel() { return mChannel; }

    /* Consumes an input event from the input channel and copies its contents into
     * an InputEvent object created using the specified factory.
     *
     * Tries to combine a series of move events into larger batches whenever possible.
     *
     * If consumeBatches is false, then defers consuming pending batched events if it
     * is possible for additional samples to be added to them later.  Call hasPendingBatch()
     * to determine whether a pending batch is available to be consumed.
     *
     * If consumeBatches is true, then events are still batched but they are consumed
     * immediately as soon as the input channel is exhausted.
     *
     * The frameTime parameter specifies the time when the current display frame started
     * rendering in the CLOCK_MONOTONIC time base, or -1 if unknown.
     *
     * The returned sequence number is never 0 unless the operation failed.
     *
     * Returns OK on success.
     * Returns WOULD_BLOCK if there is no event present.
     * Returns DEAD_OBJECT if the channel's peer has been closed.
     * Returns NO_MEMORY if the event could not be created.
     * Other errors probably indicate that the channel is broken.
     */
    status_t consume(InputEventFactoryInterface* factory, bool consumeBatches, nsecs_t frameTime,
                     uint32_t* outSeq, InputEvent** outEvent);

    /* Sends a finished signal to the publisher to inform it that the message
     * with the specified sequence number has finished being process and whether
     * the message was handled by the consumer.
     *
     * Returns OK on success.
     * Returns BAD_VALUE if seq is 0.
     * Other errors probably indicate that the channel is broken.
     */
    status_t sendFinishedSignal(uint32_t seq, bool handled);

    status_t sendTimeline(int32_t inputEventId,
                          std::array<nsecs_t, GraphicsTimeline::SIZE> timeline);

    /* Returns true if there is a pending batch.
     *
     * Should be called after calling consume() with consumeBatches == false to determine
     * whether consume() should be called again later on with consumeBatches == true.
     */
    bool hasPendingBatch() const;

    /* Returns the source of first pending batch if exist.
     *
     * Should be called after calling consume() with consumeBatches == false to determine
     * whether consume() should be called again later on with consumeBatches == true.
     */
    int32_t getPendingBatchSource() const;

    /* Returns true when there is *likely* a pending batch or a pending event in the channel.
     *
     * This is only a performance hint and may return false negative results. Clients should not
     * rely on availability of the message based on the return value.
     */
    bool probablyHasInput() const;

    std::string dump() const;

private:
    // True if touch resampling is enabled.
    const bool mResampleTouch;

    std::shared_ptr<InputChannel> mChannel;

    // TODO(b/311142655): delete this temporary tracing after the ANR bug is fixed
    const std::string mProcessingTraceTag;
    const std::string mLifetimeTraceTag;
    const int32_t mLifetimeTraceCookie;

    // The current input message.
    InputMessage mMsg;

    // True if mMsg contains a valid input message that was deferred from the previous
    // call to consume and that still needs to be handled.
    bool mMsgDeferred;

    // Batched motion events per device and source.
    struct Batch {
        std::vector<InputMessage> samples;
    };
    std::vector<Batch> mBatches;

    // Touch state per device and source, only for sources of class pointer.
    struct History {
        nsecs_t eventTime;
        BitSet32 idBits;
        int32_t idToIndex[MAX_POINTER_ID + 1];
        PointerCoords pointers[MAX_POINTERS];

        void initializeFrom(const InputMessage& msg) {
            eventTime = msg.body.motion.eventTime;
            idBits.clear();
            for (uint32_t i = 0; i < msg.body.motion.pointerCount; i++) {
                uint32_t id = msg.body.motion.pointers[i].properties.id;
                idBits.markBit(id);
                idToIndex[id] = i;
                pointers[i].copyFrom(msg.body.motion.pointers[i].coords);
            }
        }

        void initializeFrom(const History& other) {
            eventTime = other.eventTime;
            idBits = other.idBits; // temporary copy
            for (size_t i = 0; i < other.idBits.count(); i++) {
                uint32_t id = idBits.clearFirstMarkedBit();
                int32_t index = other.idToIndex[id];
                idToIndex[id] = index;
                pointers[index].copyFrom(other.pointers[index]);
            }
            idBits = other.idBits; // final copy
        }

        const PointerCoords& getPointerById(uint32_t id) const { return pointers[idToIndex[id]]; }

        bool hasPointerId(uint32_t id) const { return idBits.hasBit(id); }
    };
    struct TouchState {
        int32_t deviceId;
        int32_t source;
        size_t historyCurrent;
        size_t historySize;
        History history[2];
        History lastResample;

        void initialize(int32_t incomingDeviceId, int32_t incomingSource) {
            deviceId = incomingDeviceId;
            source = incomingSource;
            historyCurrent = 0;
            historySize = 0;
            lastResample.eventTime = 0;
            lastResample.idBits.clear();
        }

        void addHistory(const InputMessage& msg) {
            historyCurrent ^= 1;
            if (historySize < 2) {
                historySize += 1;
            }
            history[historyCurrent].initializeFrom(msg);
        }

        const History* getHistory(size_t index) const {
            return &history[(historyCurrent + index) & 1];
        }

        bool recentCoordinatesAreIdentical(uint32_t id) const {
            // Return true if the two most recently received "raw" coordinates are identical
            if (historySize < 2) {
                return false;
            }
            if (!getHistory(0)->hasPointerId(id) || !getHistory(1)->hasPointerId(id)) {
                return false;
            }
            float currentX = getHistory(0)->getPointerById(id).getX();
            float currentY = getHistory(0)->getPointerById(id).getY();
            float previousX = getHistory(1)->getPointerById(id).getX();
            float previousY = getHistory(1)->getPointerById(id).getY();
            if (currentX == previousX && currentY == previousY) {
                return true;
            }
            return false;
        }
    };
    std::vector<TouchState> mTouchStates;

    // Chain of batched sequence numbers.  When multiple input messages are combined into
    // a batch, we append a record here that associates the last sequence number in the
    // batch with the previous one.  When the finished signal is sent, we traverse the
    // chain to individually finish all input messages that were part of the batch.
    struct SeqChain {
        uint32_t seq;   // sequence number of batched input message
        uint32_t chain; // sequence number of previous batched input message
    };
    std::vector<SeqChain> mSeqChains;

    // The time at which each event with the sequence number 'seq' was consumed.
    // This data is provided in 'finishInputEvent' so that the receiving end can measure the latency
    // This collection is populated when the event is received, and the entries are erased when the
    // events are finished. It should not grow infinitely because if an event is not ack'd, ANR
    // will be raised for that connection, and no further events will be posted to that channel.
    std::unordered_map<uint32_t /*seq*/, nsecs_t /*consumeTime*/> mConsumeTimes;

    status_t consumeBatch(InputEventFactoryInterface* factory, nsecs_t frameTime, uint32_t* outSeq,
                          InputEvent** outEvent);
    status_t consumeSamples(InputEventFactoryInterface* factory, Batch& batch, size_t count,
                            uint32_t* outSeq, InputEvent** outEvent);

    void updateTouchState(InputMessage& msg);
    void resampleTouchState(nsecs_t frameTime, MotionEvent* event, const InputMessage* next);

    ssize_t findBatch(int32_t deviceId, int32_t source) const;
    ssize_t findTouchState(int32_t deviceId, int32_t source) const;

    nsecs_t getConsumeTime(uint32_t seq) const;
    void popConsumeTime(uint32_t seq);
    status_t sendUnchainedFinishedSignal(uint32_t seq, bool handled);

    static void rewriteMessage(TouchState& state, InputMessage& msg);
    static bool canAddSample(const Batch& batch, const InputMessage* msg);
    static ssize_t findSampleNoLaterThan(const Batch& batch, nsecs_t time);

    static bool isTouchResamplingEnabled();
};

} // namespace android
