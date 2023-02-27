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

// Uncomment to trace layer updates for a single layer
// #define LOG_LAYER 1

#ifdef LOG_LAYER
#define LLOGV(LAYER_ID, x, ...) \
    ALOGV_IF(((LAYER_ID) == LOG_LAYER), "[%d] %s " x, LOG_LAYER, __func__, ##__VA_ARGS__);
#else
#define LLOGV(LAYER_ID, x, ...) ALOGV("[%d] %s " x, (LAYER_ID), __func__, ##__VA_ARGS__);
#endif

#define LLOGD(LAYER_ID, x, ...) ALOGD("[%d] %s " x, (LAYER_ID), __func__, ##__VA_ARGS__);
