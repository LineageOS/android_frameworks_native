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

package com.android.server.inputflinger;

/** Interface to handle and run things on an InputThread
  * Exposes main functionality of InputThread.h to rust which internally used system/core/libutils
  * infrastructure.
  *
  * <p>
  * NOTE: Tried using rust provided threading infrastructure but that uses std::thread which doesn't
  * have JNI support and can't call into Java policy that we use currently. libutils provided
  * Thread.h also recommends against using std::thread and using the provided infrastructure that
  * already provides way of attaching JniEnv to the created thread. So, we are using this interface
  * to expose the InputThread infrastructure to rust.
  * </p>
  * TODO(b/321769871): Implement the threading infrastructure with JniEnv support in rust
  */
interface IInputThread {
    /** Finish input thread (if not running, this call does nothing) */
    void finish();

    /** Callbacks from C++ to call into inputflinger rust components */
    interface IInputThreadCallback {
        /**
          * The created thread will keep looping and calling this function.
          * It's the responsibility of RUST component to appropriately put the thread to sleep and
          * wake according to the use case.
          */
        void loopOnce();
    }
}