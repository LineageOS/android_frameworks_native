/*
 * Copyright 2020 The LineageOS Project
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

#include <stdint.h>

#ifndef __FOD_EXTENSION__H__
#define __FOD_EXTENSION__H__

#define FOD_LAYER_NAME "Fingerprint on display#0"
#define FOD_TOUCHED_LAYER_NAME "Fingerprint on display.touched#0"

extern uint32_t getFodZOrder(uint32_t z, bool touched);
extern uint64_t getFodUsageBits(uint64_t usageBits, bool touched);

#endif /* __FOD_EXTENSION__H__ */
