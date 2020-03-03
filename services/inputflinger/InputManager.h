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

#ifndef _UI_INPUT_MANAGER_H
#define _UI_INPUT_MANAGER_H

/**
 * Native input manager.
 */

#include "EventHub.h"
#include "InputReaderBase.h"
#include "InputClassifier.h"
#include "InputDispatcher.h"
#include "InputReader.h"

#include <input/Input.h>
#include <input/InputTransport.h>
#include <input/ISetInputWindowsListener.h>

#include <input/IInputFlinger.h>
#include <utils/Errors.h>
#include <utils/Vector.h>
#include <utils/Timers.h>
#include <utils/RefBase.h>

namespace android {
class InputChannel;

/*
 * The input manager is the core of the system event processing.
 *
 * The input manager uses two threads.
 *
 * 1. The InputReaderThread (called "InputReader") reads and preprocesses raw input events,
 *    applies policy, and posts messages to a queue managed by the DispatcherThread.
 * 2. The InputDispatcherThread (called "InputDispatcher") thread waits for new events on the
 *    queue and asynchronously dispatches them to applications.
 *
 * By design, the InputReaderThread class and InputDispatcherThread class do not share any
 * internal state.  Moreover, all communication is done one way from the InputReaderThread
 * into the InputDispatcherThread and never the reverse.  Both classes may interact with the
 * InputDispatchPolicy, however.
 *
 * The InputManager class never makes any calls into Java itself.  Instead, the
 * InputDispatchPolicy is responsible for performing all external interactions with the
 * system, including calling DVM services.
 */
class InputManagerInterface : public virtual RefBase {
protected:
    InputManagerInterface() { }
    virtual ~InputManagerInterface() { }

public:
    /* Starts the input manager threads. */
    virtual status_t start() = 0;

    /* Stops the input manager threads and waits for them to exit. */
    virtual status_t stop() = 0;

    /* Gets the input reader. */
    virtual sp<InputReaderInterface> getReader() = 0;

    /* Gets the input dispatcher. */
    virtual sp<InputDispatcherInterface> getDispatcher() = 0;
};

class InputManager : public InputManagerInterface, public BnInputFlinger {
protected:
    virtual ~InputManager();

public:
    InputManager(
            const sp<InputReaderPolicyInterface>& readerPolicy,
            const sp<InputDispatcherPolicyInterface>& dispatcherPolicy);

    virtual status_t start();
    virtual status_t stop();

    virtual sp<InputReaderInterface> getReader();
    virtual sp<InputClassifierInterface> getClassifier();
    virtual sp<InputDispatcherInterface> getDispatcher();

    virtual void setInputWindows(const std::vector<InputWindowInfo>& handles,
            const sp<ISetInputWindowsListener>& setInputWindowsListener);

    virtual void registerInputChannel(const sp<InputChannel>& channel);
    virtual void unregisterInputChannel(const sp<InputChannel>& channel);

private:
    sp<InputReaderInterface> mReader;
    sp<InputReaderThread> mReaderThread;

    sp<InputClassifierInterface> mClassifier;

    sp<InputDispatcherInterface> mDispatcher;
    sp<InputDispatcherThread> mDispatcherThread;

    void initialize();
};

} // namespace android

#endif // _UI_INPUT_MANAGER_H
