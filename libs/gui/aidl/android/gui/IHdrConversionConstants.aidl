/*
 * Copyright 2023 The Android Open Source Project
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

package android.gui;

/** @hide */
interface IHdrConversionConstants
{
    /** HDR Conversion Mode when there is no conversion being done */
    const int HdrConversionModePassthrough = 1;

    /** HDR Conversion Mode when HDR conversion is decided by the system or implementation */
    const int HdrConversionModeAuto = 2;

    /** HDR Conversion Mode when the output HDR types is selected by the user or framework */
    const int HdrConversionModeForce = 3;
}