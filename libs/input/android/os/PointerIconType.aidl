/**
 * Copyright (c) 2024, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.os;

/**
 * Represents an icon that can be used as a mouse pointer.
 * Please look at frameworks/base/core/java/android/view/PointerIcon.java for the detailed
 * explanation of each constant.
 * @hide
 */
@Backing(type="int")
enum PointerIconType {
    CUSTOM                  = -1,
    TYPE_NULL               = 0,
    NOT_SPECIFIED           = 1,
    ARROW                   = 1000,
    CONTEXT_MENU            = 1001,
    HAND                    = 1002,
    HELP                    = 1003,
    WAIT                    = 1004,
    CELL                    = 1006,
    CROSSHAIR               = 1007,
    TEXT                    = 1008,
    VERTICAL_TEXT           = 1009,
    ALIAS                   = 1010,
    COPY                    = 1011,
    NO_DROP                 = 1012,
    ALL_SCROLL              = 1013,
    HORIZONTAL_DOUBLE_ARROW = 1014,
    VERTICAL_DOUBLE_ARROW   = 1015,
    TOP_RIGHT_DOUBLE_ARROW  = 1016,
    TOP_LEFT_DOUBLE_ARROW   = 1017,
    ZOOM_IN                 = 1018,
    ZOOM_OUT                = 1019,
    GRAB                    = 1020,
    GRABBING                = 1021,
    HANDWRITING             = 1022,

    SPOT_HOVER              = 2000,
    SPOT_TOUCH              = 2001,
    SPOT_ANCHOR             = 2002,
}
