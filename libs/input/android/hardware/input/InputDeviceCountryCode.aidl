/*
 * Copyright (C) 2022 The Android Open Source Project
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

package android.hardware.input;

/**
 * Constant for HID country code declared by a HID device. These constants are declared as AIDL to
 * be used by java and native input code.
 *
 * @hide
 */
@Backing(type="int")
enum InputDeviceCountryCode {
    /**
     * Used as default value where country code is not set in the device HID descriptor
     */
    INVALID = -1,

    /**
     * Used as default value when country code is not supported by the HID device. The HID
     * descriptor sets "00" as the country code in this case.
     */
    NOT_SUPPORTED = 0,

    /**
     * Arabic
     */
    ARABIC = 1,

    /**
     * Belgian
     */
    BELGIAN = 2,

    /**
     * Canadian (Bilingual)
     */
    CANADIAN_BILINGUAL = 3,

    /**
     * Canadian (French)
     */
    CANADIAN_FRENCH = 4,

    /**
     * Czech Republic
     */
    CZECH_REPUBLIC = 5,

    /**
     * Danish
     */
    DANISH = 6,

    /**
     * Finnish
     */
    FINNISH = 7,

    /**
     * French
     */
    FRENCH = 8,

    /**
     * German
     */
    GERMAN = 9,

    /**
     * Greek
     */
    GREEK = 10,

    /**
     * Hebrew
     */
    HEBREW = 11,

    /**
     * Hungary
     */
    HUNGARY = 12,

    /**
     * International (ISO)
     */
    INTERNATIONAL = 13,

    /**
     * Italian
     */
    ITALIAN = 14,

    /**
     * Japan (Katakana)
     */
    JAPAN = 15,

    /**
     * Korean
     */
    KOREAN = 16,

    /**
     * Latin American
     */
    LATIN_AMERICAN = 17,

    /**
     * Netherlands (Dutch)
     */
    DUTCH = 18,

    /**
     * Norwegian
     */
    NORWEGIAN = 19,

    /**
     * Persian
     */
    PERSIAN = 20,

    /**
     * Poland
     */
    POLAND = 21,

    /**
     * Portuguese
     */
    PORTUGUESE = 22,

    /**
     * Russia
     */
    RUSSIA = 23,

    /**
     * Slovakia
     */
    SLOVAKIA = 24,

    /**
     * Spanish
     */
    SPANISH = 25,

    /**
     * Swedish
     */
    SWEDISH = 26,

    /**
     * Swiss (French)
     */
    SWISS_FRENCH = 27,

    /**
     * Swiss (German)
     */
    SWISS_GERMAN = 28,

    /**
     * Switzerland
     */
    SWITZERLAND = 29,

    /**
     * Taiwan
     */
    TAIWAN = 30,

    /**
     * Turkish_Q
     */
    TURKISH_Q = 31,

    /**
     * UK
     */
    UK = 32,

    /**
     * US
     */
    US = 33,

    /**
     * Yugoslavia
     */
    YUGOSLAVIA = 34,

    /**
     * Turkish_F
     */
    TURKISH_F = 35,
}