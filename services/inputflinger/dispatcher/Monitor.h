/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <gui/PidUid.h>
#include "Connection.h"

namespace android::inputdispatcher {

struct Monitor {
    std::shared_ptr<Connection> connection; // never null

    gui::Pid pid;

    explicit Monitor(const std::shared_ptr<Connection>& connection, gui::Pid pid);
};

} // namespace android::inputdispatcher
