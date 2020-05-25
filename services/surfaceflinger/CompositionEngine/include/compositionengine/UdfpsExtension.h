/*
 * Copyright 2021-2022 The LineageOS Project
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

#ifndef __UDFPS_EXTENSION__H__
#define __UDFPS_EXTENSION__H__

#define UDFPS_BIOMETRIC_PROMPT_LAYER_NAME "BiometricPrompt"
#define UDFPS_LAYER_NAME "UdfpsControllerOverlay"
#define UDFPS_TOUCHED_LAYER_NAME "SurfaceView[UdfpsControllerOverlay](BLAST)"

extern uint32_t getUdfpsZOrder(uint32_t z, bool touched);
extern uint64_t getUdfpsUsageBits(uint64_t usageBits, bool touched);

#endif /* __UDFPS_EXTENSION__H__ */
