/*
 * Copyright 2022 The Android Open Source Project
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

#include <scheduler/FrameRateMode.h>

// Use a C style macro to keep the line numbers printed in gtest
#define EXPECT_FRAME_RATE_MODE(_modePtr, _fps, _mode)                                      \
    EXPECT_EQ((scheduler::FrameRateMode{(_fps), (_modePtr)}), (_mode))                     \
            << "Expected " << (_fps) << " (" << (_modePtr)->getVsyncRate() << ") but was " \
            << (_mode).fps << " (" << (_mode).modePtr->getVsyncRate() << ")"
