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

#include <array>

#include "TestHelpers.h"

#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <binder/Binder.h>
#include <binder/Parcel.h>
#include <gtest/gtest.h>
#include <input/InputTransport.h>
#include <utils/StopWatch.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

namespace android {

namespace {
bool operator==(const InputChannel& left, const InputChannel& right) {
    struct stat lhs, rhs;
    if (fstat(left.getFd(), &lhs) != 0) {
        return false;
    }
    if (fstat(right.getFd(), &rhs) != 0) {
        return false;
    }
    // If file descriptors are pointing to same inode they are duplicated fds.
    return left.getName() == right.getName() &&
            left.getConnectionToken() == right.getConnectionToken() && lhs.st_ino == rhs.st_ino;
}
} // namespace

class InputChannelTest : public testing::Test {
};

TEST_F(InputChannelTest, ClientAndServerTokensMatch) {
    std::unique_ptr<InputChannel> serverChannel, clientChannel;

    status_t result =
            InputChannel::openInputChannelPair("channel name", serverChannel, clientChannel);
    ASSERT_EQ(OK, result) << "should have successfully opened a channel pair";
    EXPECT_EQ(serverChannel->getConnectionToken(), clientChannel->getConnectionToken());
}

TEST_F(InputChannelTest, OpenInputChannelPair_ReturnsAPairOfConnectedChannels) {
    std::unique_ptr<InputChannel> serverChannel, clientChannel;

    status_t result = InputChannel::openInputChannelPair("channel name",
            serverChannel, clientChannel);

    ASSERT_EQ(OK, result) << "should have successfully opened a channel pair";

    // Name
    EXPECT_STREQ("channel name (server)", serverChannel->getName().c_str())
            << "server channel should have suffixed name";
    EXPECT_STREQ("channel name (client)", clientChannel->getName().c_str())
            << "client channel should have suffixed name";

    // Server->Client communication
    InputMessage serverMsg = {};
    serverMsg.header.type = InputMessage::Type::KEY;
    serverMsg.body.key.action = AKEY_EVENT_ACTION_DOWN;
    EXPECT_EQ(OK, serverChannel->sendMessage(&serverMsg))
            << "server channel should be able to send message to client channel";

    InputMessage clientMsg;
    EXPECT_EQ(OK, clientChannel->receiveMessage(&clientMsg))
            << "client channel should be able to receive message from server channel";
    EXPECT_EQ(serverMsg.header.type, clientMsg.header.type)
            << "client channel should receive the correct message from server channel";
    EXPECT_EQ(serverMsg.body.key.action, clientMsg.body.key.action)
            << "client channel should receive the correct message from server channel";

    // Client->Server communication
    InputMessage clientReply = {};
    clientReply.header.type = InputMessage::Type::FINISHED;
    clientReply.header.seq = 0x11223344;
    clientReply.body.finished.handled = true;
    EXPECT_EQ(OK, clientChannel->sendMessage(&clientReply))
            << "client channel should be able to send message to server channel";

    InputMessage serverReply;
    EXPECT_EQ(OK, serverChannel->receiveMessage(&serverReply))
            << "server channel should be able to receive message from client channel";
    EXPECT_EQ(clientReply.header.type, serverReply.header.type)
            << "server channel should receive the correct message from client channel";
    EXPECT_EQ(clientReply.header.seq, serverReply.header.seq)
            << "server channel should receive the correct message from client channel";
    EXPECT_EQ(clientReply.body.finished.handled, serverReply.body.finished.handled)
            << "server channel should receive the correct message from client channel";
}

TEST_F(InputChannelTest, ProbablyHasInput) {
    std::unique_ptr<InputChannel> senderChannel, receiverChannel;

    // Open a pair of channels.
    status_t result =
            InputChannel::openInputChannelPair("channel name", senderChannel, receiverChannel);
    ASSERT_EQ(OK, result) << "should have successfully opened a channel pair";

    ASSERT_FALSE(receiverChannel->probablyHasInput());

    // Send one message.
    InputMessage serverMsg = {};
    serverMsg.header.type = InputMessage::Type::KEY;
    serverMsg.body.key.action = AKEY_EVENT_ACTION_DOWN;
    EXPECT_EQ(OK, senderChannel->sendMessage(&serverMsg))
            << "server channel should be able to send message to client channel";

    // Verify input is available.
    bool hasInput = false;
    do {
        // The probablyHasInput() can return false positive under rare circumstances uncontrollable
        // by the tests. Re-request the availability in this case. Returning |false| for a long
        // time is not intended, and would cause a test timeout.
        hasInput = receiverChannel->probablyHasInput();
    } while (!hasInput);
    EXPECT_TRUE(hasInput)
            << "client channel should observe that message is available before receiving it";

    // Receive (consume) the message.
    InputMessage clientMsg;
    EXPECT_EQ(OK, receiverChannel->receiveMessage(&clientMsg))
            << "client channel should be able to receive message from server channel";
    EXPECT_EQ(serverMsg.header.type, clientMsg.header.type)
            << "client channel should receive the correct message from server channel";
    EXPECT_EQ(serverMsg.body.key.action, clientMsg.body.key.action)
            << "client channel should receive the correct message from server channel";

    // Verify input is not available.
    EXPECT_FALSE(receiverChannel->probablyHasInput())
            << "client should not observe any more messages after receiving the single one";
}

TEST_F(InputChannelTest, ReceiveSignal_WhenNoSignalPresent_ReturnsAnError) {
    std::unique_ptr<InputChannel> serverChannel, clientChannel;

    status_t result = InputChannel::openInputChannelPair("channel name",
            serverChannel, clientChannel);

    ASSERT_EQ(OK, result)
            << "should have successfully opened a channel pair";

    InputMessage msg;
    EXPECT_EQ(WOULD_BLOCK, clientChannel->receiveMessage(&msg))
            << "receiveMessage should have returned WOULD_BLOCK";
}

TEST_F(InputChannelTest, ReceiveSignal_WhenPeerClosed_ReturnsAnError) {
    std::unique_ptr<InputChannel> serverChannel, clientChannel;

    status_t result = InputChannel::openInputChannelPair("channel name",
            serverChannel, clientChannel);

    ASSERT_EQ(OK, result)
            << "should have successfully opened a channel pair";

    serverChannel.reset(); // close server channel

    InputMessage msg;
    EXPECT_EQ(DEAD_OBJECT, clientChannel->receiveMessage(&msg))
            << "receiveMessage should have returned DEAD_OBJECT";
}

TEST_F(InputChannelTest, SendSignal_WhenPeerClosed_ReturnsAnError) {
    std::unique_ptr<InputChannel> serverChannel, clientChannel;

    status_t result = InputChannel::openInputChannelPair("channel name",
            serverChannel, clientChannel);

    ASSERT_EQ(OK, result)
            << "should have successfully opened a channel pair";

    serverChannel.reset(); // close server channel

    InputMessage msg;
    msg.header.type = InputMessage::Type::KEY;
    EXPECT_EQ(DEAD_OBJECT, clientChannel->sendMessage(&msg))
            << "sendMessage should have returned DEAD_OBJECT";
}

TEST_F(InputChannelTest, SendAndReceive_MotionClassification) {
    std::unique_ptr<InputChannel> serverChannel, clientChannel;
    status_t result = InputChannel::openInputChannelPair("channel name",
            serverChannel, clientChannel);
    ASSERT_EQ(OK, result)
            << "should have successfully opened a channel pair";

    std::array<MotionClassification, 3> classifications = {
        MotionClassification::NONE,
        MotionClassification::AMBIGUOUS_GESTURE,
        MotionClassification::DEEP_PRESS,
    };

    InputMessage serverMsg = {}, clientMsg;
    serverMsg.header.type = InputMessage::Type::MOTION;
    serverMsg.header.seq = 1;
    serverMsg.body.motion.pointerCount = 1;

    for (MotionClassification classification : classifications) {
        // Send and receive a message with classification
        serverMsg.body.motion.classification = classification;
        EXPECT_EQ(OK, serverChannel->sendMessage(&serverMsg))
                << "server channel should be able to send message to client channel";

        EXPECT_EQ(OK, clientChannel->receiveMessage(&clientMsg))
                << "client channel should be able to receive message from server channel";
        EXPECT_EQ(serverMsg.header.type, clientMsg.header.type);
        EXPECT_EQ(classification, clientMsg.body.motion.classification) <<
                "Expected to receive " << motionClassificationToString(classification);
    }
}

TEST_F(InputChannelTest, DuplicateChannelAndAssertEqual) {
    std::unique_ptr<InputChannel> serverChannel, clientChannel;

    status_t result =
            InputChannel::openInputChannelPair("channel dup", serverChannel, clientChannel);

    ASSERT_EQ(OK, result) << "should have successfully opened a channel pair";

    std::unique_ptr<InputChannel> dupChan = serverChannel->dup();

    EXPECT_EQ(*serverChannel == *dupChan, true) << "inputchannel should be equal after duplication";
}

} // namespace android
