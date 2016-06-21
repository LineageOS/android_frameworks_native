/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
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

#ifndef ANDROID_BLUR_H
#define ANDROID_BLUR_H

extern "C" {
    extern int _ZN7qtiblur13initBlurTokenEv();
    extern void _ZN7qtiblur16releaseBlurTokenEPv(int);
    extern int _ZN7qtiblur4blurEPvijjjjPjS1_(int, int, int, int, int, uint32_t, size_t *, size_t *);
}

#endif // ANDROID_BLUR_H
