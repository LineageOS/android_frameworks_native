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

package android.gui;

// Product-specific information about the display or the directly connected device on the
// display chain. For example, if the display is transitively connected, this field may contain
// product information about the intermediate device.

/** @hide */
parcelable DeviceProductInfo {
    parcelable ModelYear {
        int year;
    }

    parcelable ManufactureYear {
        ModelYear modelYear;
    }

    parcelable ManufactureWeekAndYear {
        ManufactureYear manufactureYear;

        // 1-base week number. Week numbering may not be consistent between manufacturers.
        int week;
    }

    union ManufactureOrModelDate {
        ModelYear modelYear;
        ManufactureYear manufactureYear;
        ManufactureWeekAndYear manufactureWeekAndYear;
    }

    // Display name.
    @utf8InCpp String name;

    // NULL-terminated Manufacturer plug and play ID.
    byte[] manufacturerPnpId;

    // Manufacturer product ID.
    @utf8InCpp String productId;

    ManufactureOrModelDate manufactureOrModelDate;

    byte[] relativeAddress;
}
