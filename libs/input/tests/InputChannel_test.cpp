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
#include <gtest/gtest.h>
#include <input/InputTransport.h>
#include <utils/StopWatch.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

namespace android {

class InputChannelTest : public testing::Test {
protected:
    virtual void SetUp() { }
    virtual void TearDown() { }
};


TEST_F(InputChannelTest, ConstructorAndDestructor_TakesOwnershipOfFileDescriptors) {
    // Our purpose here is to verify that the input channel destructor closes the
    // file descriptor provided to it.  One easy way is to provide it with one end
    // of a pipe and to check for EPIPE on the other end after the channel is destroyed.
    Pipe pipe;

    android::base::unique_fd sendFd(pipe.sendFd);

    sp<InputChannel> inputChannel =
            InputChannel::create("channel name", std::move(sendFd), new BBinder());

    EXPECT_NE(inputChannel, nullptr) << "channel should be successfully created";
    EXPECT_STREQ("channel name", inputChannel->getName().c_str())
            << "channel should have provided name";
    EXPECT_NE(-1, inputChannel->getFd()) << "channel should have valid fd";

    // InputChannel should be the owner of the file descriptor now
    ASSERT_FALSE(sendFd.ok());
}

TEST_F(InputChannelTest, SetAndGetToken) {
    Pipe pipe;
    sp<IBinder> token = new BBinder();
    sp<InputChannel> channel =
            InputChannel::create("test channel", android::base::unique_fd(pipe.sendFd), token);

    EXPECT_EQ(token, channel->getConnectionToken());
}

TEST_F(InputChannelTest, OpenInputChannelPair_ReturnsAPairOfConnectedChannels) {
    sp<InputChannel> serverChannel, clientChannel;

    status_t result = InputChannel::openInputChannelPair("channel name",
            serverChannel, clientChannel);

    ASSERT_EQ(OK, result)
            << "should have successfully opened a channel pair";

    // Name
    EXPECT_STREQ("channel name (server)", serverChannel->getName().c_str())
            << "server channel should have suffixed name";
    EXPECT_STREQ("channel name (client)", clientChannel->getName().c_str())
            << "client channel should have suffixed name";

    // Server->Client communication
    InputMessage serverMsg;
    memset(&serverMsg, 0, sizeof(InputMessage));
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
    InputMessage clientReply;
    memset(&clientReply, 0, sizeof(InputMessage));
    clientReply.header.type = InputMessage::Type::FINISHED;
    clientReply.body.finished.seq = 0x11223344;
    clientReply.body.finished.handled = true;
    EXPECT_EQ(OK, clientChannel->sendMessage(&clientReply))
            << "client channel should be able to send message to server channel";

    InputMessage serverReply;
    EXPECT_EQ(OK, serverChannel->receiveMessage(&serverReply))
            << "server channel should be able to receive message from client channel";
    EXPECT_EQ(clientReply.header.type, serverReply.header.type)
            << "server channel should receive the correct message from client channel";
    EXPECT_EQ(clientReply.body.finished.seq, serverReply.body.finished.seq)
            << "server channel should receive the correct message from client channel";
    EXPECT_EQ(clientReply.body.finished.handled, serverReply.body.finished.handled)
            << "server channel should receive the correct message from client channel";
}

TEST_F(InputChannelTest, ReceiveSignal_WhenNoSignalPresent_ReturnsAnError) {
    sp<InputChannel> serverChannel, clientChannel;

    status_t result = InputChannel::openInputChannelPair("channel name",
            serverChannel, clientChannel);

    ASSERT_EQ(OK, result)
            << "should have successfully opened a channel pair";

    InputMessage msg;
    EXPECT_EQ(WOULD_BLOCK, clientChannel->receiveMessage(&msg))
            << "receiveMessage should have returned WOULD_BLOCK";
}

TEST_F(InputChannelTest, ReceiveSignal_WhenPeerClosed_ReturnsAnError) {
    sp<InputChannel> serverChannel, clientChannel;

    status_t result = InputChannel::openInputChannelPair("channel name",
            serverChannel, clientChannel);

    ASSERT_EQ(OK, result)
            << "should have successfully opened a channel pair";

    serverChannel.clear(); // close server channel

    InputMessage msg;
    EXPECT_EQ(DEAD_OBJECT, clientChannel->receiveMessage(&msg))
            << "receiveMessage should have returned DEAD_OBJECT";
}

TEST_F(InputChannelTest, SendSignal_WhenPeerClosed_ReturnsAnError) {
    sp<InputChannel> serverChannel, clientChannel;

    status_t result = InputChannel::openInputChannelPair("channel name",
            serverChannel, clientChannel);

    ASSERT_EQ(OK, result)
            << "should have successfully opened a channel pair";

    serverChannel.clear(); // close server channel

    InputMessage msg;
    msg.header.type = InputMessage::Type::KEY;
    EXPECT_EQ(DEAD_OBJECT, clientChannel->sendMessage(&msg))
            << "sendMessage should have returned DEAD_OBJECT";
}

TEST_F(InputChannelTest, SendAndReceive_MotionClassification) {
    sp<InputChannel> serverChannel, clientChannel;
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
    serverMsg.body.motion.seq = 1;
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


} // namespace android
