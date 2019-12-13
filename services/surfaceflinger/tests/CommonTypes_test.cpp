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
#include <aidl/android/hardware/graphics/common/BlendMode.h>
#include <aidl/android/hardware/graphics/common/Dataspace.h>

#include <android/data_space.h>
#include <android/hardware/graphics/common/1.2/types.h>
#include <android/hardware/graphics/composer/2.1/IComposerClient.h>

using AidlBlendMode = aidl::android::hardware::graphics::common::BlendMode;
using AidlDataspace = aidl::android::hardware::graphics::common::Dataspace;

using HidlBlendMode = android::hardware::graphics::composer::V2_1::IComposerClient::BlendMode;
using HidlDataspace = android::hardware::graphics::common::V1_2::Dataspace;

static_assert(static_cast<uint32_t>(AidlBlendMode::INVALID) ==
              static_cast<uint32_t>(HidlBlendMode::INVALID));
static_assert(static_cast<uint32_t>(AidlBlendMode::NONE) ==
              static_cast<uint32_t>(HidlBlendMode::NONE));
static_assert(static_cast<uint32_t>(AidlBlendMode::PREMULTIPLIED) ==
              static_cast<uint32_t>(HidlBlendMode::PREMULTIPLIED));
static_assert(static_cast<uint32_t>(AidlBlendMode::COVERAGE) ==
              static_cast<uint32_t>(HidlBlendMode::COVERAGE));

static_assert(static_cast<uint32_t>(ADATASPACE_UNKNOWN) ==
              static_cast<uint32_t>(AidlDataspace::UNKNOWN));
static_assert(static_cast<uint32_t>(ADATASPACE_SCRGB_LINEAR) ==
              static_cast<uint32_t>(AidlDataspace::SCRGB_LINEAR));
static_assert(static_cast<uint32_t>(ADATASPACE_SRGB) == static_cast<uint32_t>(AidlDataspace::SRGB));
static_assert(static_cast<uint32_t>(ADATASPACE_SCRGB) ==
              static_cast<uint32_t>(AidlDataspace::SCRGB));
static_assert(static_cast<uint32_t>(ADATASPACE_DISPLAY_P3) ==
              static_cast<uint32_t>(AidlDataspace::DISPLAY_P3));
static_assert(static_cast<uint32_t>(ADATASPACE_BT2020_PQ) ==
              static_cast<uint32_t>(AidlDataspace::BT2020_PQ));
static_assert(static_cast<uint32_t>(ADATASPACE_ADOBE_RGB) ==
              static_cast<uint32_t>(AidlDataspace::ADOBE_RGB));
static_assert(static_cast<uint32_t>(ADATASPACE_BT2020) ==
              static_cast<uint32_t>(AidlDataspace::BT2020));
static_assert(static_cast<uint32_t>(ADATASPACE_BT709) ==
              static_cast<uint32_t>(AidlDataspace::BT709));
static_assert(static_cast<uint32_t>(ADATASPACE_DCI_P3) ==
              static_cast<uint32_t>(AidlDataspace::DCI_P3));
static_assert(static_cast<uint32_t>(ADATASPACE_SRGB_LINEAR) ==
              static_cast<uint32_t>(AidlDataspace::SRGB_LINEAR));

static_assert(static_cast<uint32_t>(ADATASPACE_UNKNOWN) ==
              static_cast<uint32_t>(HidlDataspace::UNKNOWN));
static_assert(static_cast<uint32_t>(ADATASPACE_SCRGB_LINEAR) ==
              static_cast<uint32_t>(HidlDataspace::V0_SCRGB_LINEAR));
static_assert(static_cast<uint32_t>(ADATASPACE_SRGB) ==
              static_cast<uint32_t>(HidlDataspace::V0_SRGB));
static_assert(static_cast<uint32_t>(ADATASPACE_SCRGB) ==
              static_cast<uint32_t>(HidlDataspace::V0_SCRGB));
static_assert(static_cast<uint32_t>(ADATASPACE_DISPLAY_P3) ==
              static_cast<uint32_t>(HidlDataspace::DISPLAY_P3));
static_assert(static_cast<uint32_t>(ADATASPACE_BT2020_PQ) ==
              static_cast<uint32_t>(HidlDataspace::BT2020_PQ));
static_assert(static_cast<uint32_t>(ADATASPACE_ADOBE_RGB) ==
              static_cast<uint32_t>(HidlDataspace::ADOBE_RGB));
static_assert(static_cast<uint32_t>(ADATASPACE_BT2020) ==
              static_cast<uint32_t>(HidlDataspace::BT2020));
static_assert(static_cast<uint32_t>(ADATASPACE_BT709) ==
              static_cast<uint32_t>(HidlDataspace::V0_BT709));
static_assert(static_cast<uint32_t>(ADATASPACE_DCI_P3) ==
              static_cast<uint32_t>(HidlDataspace::DCI_P3));
static_assert(static_cast<uint32_t>(ADATASPACE_SRGB_LINEAR) ==
              static_cast<uint32_t>(HidlDataspace::V0_SRGB_LINEAR));

static_assert(static_cast<uint32_t>(AidlDataspace::UNKNOWN) ==
              static_cast<uint32_t>(HidlDataspace::UNKNOWN));
static_assert(static_cast<uint32_t>(AidlDataspace::ARBITRARY) ==
              static_cast<uint32_t>(HidlDataspace::ARBITRARY));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_SHIFT) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_SHIFT));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_MASK) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_MASK));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_UNSPECIFIED) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_UNSPECIFIED));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_BT709) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_BT709));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_BT601_625) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_BT601_625));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_BT601_625_UNADJUSTED) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_BT601_625_UNADJUSTED));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_BT601_525) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_BT601_525));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_BT601_525_UNADJUSTED) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_BT601_525_UNADJUSTED));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_BT2020) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_BT2020));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_BT2020_CONSTANT_LUMINANCE) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_BT2020_CONSTANT_LUMINANCE));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_BT470M) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_BT470M));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_FILM) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_FILM));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_DCI_P3) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_DCI_P3));
static_assert(static_cast<uint32_t>(AidlDataspace::STANDARD_ADOBE_RGB) ==
              static_cast<uint32_t>(HidlDataspace::STANDARD_ADOBE_RGB));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_SHIFT) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_SHIFT));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_MASK) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_MASK));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_UNSPECIFIED) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_UNSPECIFIED));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_LINEAR) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_LINEAR));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_SRGB) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_SRGB));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_SMPTE_170M) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_SMPTE_170M));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_GAMMA2_2) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_GAMMA2_2));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_GAMMA2_6) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_GAMMA2_6));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_GAMMA2_8) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_GAMMA2_8));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_ST2084) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_ST2084));
static_assert(static_cast<uint32_t>(AidlDataspace::TRANSFER_HLG) ==
              static_cast<uint32_t>(HidlDataspace::TRANSFER_HLG));
static_assert(static_cast<uint32_t>(AidlDataspace::RANGE_SHIFT) ==
              static_cast<uint32_t>(HidlDataspace::RANGE_SHIFT));
static_assert(static_cast<uint32_t>(AidlDataspace::RANGE_MASK) ==
              static_cast<uint32_t>(HidlDataspace::RANGE_MASK));
static_assert(static_cast<uint32_t>(AidlDataspace::RANGE_UNSPECIFIED) ==
              static_cast<uint32_t>(HidlDataspace::RANGE_UNSPECIFIED));
static_assert(static_cast<uint32_t>(AidlDataspace::RANGE_FULL) ==
              static_cast<uint32_t>(HidlDataspace::RANGE_FULL));
static_assert(static_cast<uint32_t>(AidlDataspace::RANGE_LIMITED) ==
              static_cast<uint32_t>(HidlDataspace::RANGE_LIMITED));
static_assert(static_cast<uint32_t>(AidlDataspace::RANGE_EXTENDED) ==
              static_cast<uint32_t>(HidlDataspace::RANGE_EXTENDED));
static_assert(static_cast<uint32_t>(AidlDataspace::SRGB_LINEAR) ==
              static_cast<uint32_t>(HidlDataspace::V0_SRGB_LINEAR));
static_assert(static_cast<uint32_t>(AidlDataspace::SCRGB_LINEAR) ==
              static_cast<uint32_t>(HidlDataspace::V0_SCRGB_LINEAR));
static_assert(static_cast<uint32_t>(AidlDataspace::SRGB) ==
              static_cast<uint32_t>(HidlDataspace::V0_SRGB));
static_assert(static_cast<uint32_t>(AidlDataspace::SCRGB) ==
              static_cast<uint32_t>(HidlDataspace::V0_SCRGB));
static_assert(static_cast<uint32_t>(AidlDataspace::JFIF) ==
              static_cast<uint32_t>(HidlDataspace::V0_JFIF));
static_assert(static_cast<uint32_t>(AidlDataspace::BT601_625) ==
              static_cast<uint32_t>(HidlDataspace::V0_BT601_625));
static_assert(static_cast<uint32_t>(AidlDataspace::BT601_525) ==
              static_cast<uint32_t>(HidlDataspace::V0_BT601_525));
static_assert(static_cast<uint32_t>(AidlDataspace::BT709) ==
              static_cast<uint32_t>(HidlDataspace::V0_BT709));
static_assert(static_cast<uint32_t>(AidlDataspace::DCI_P3_LINEAR) ==
              static_cast<uint32_t>(HidlDataspace::DCI_P3_LINEAR));
static_assert(static_cast<uint32_t>(AidlDataspace::DCI_P3) ==
              static_cast<uint32_t>(HidlDataspace::DCI_P3));
static_assert(static_cast<uint32_t>(AidlDataspace::DISPLAY_P3_LINEAR) ==
              static_cast<uint32_t>(HidlDataspace::DISPLAY_P3_LINEAR));
static_assert(static_cast<uint32_t>(AidlDataspace::DISPLAY_P3) ==
              static_cast<uint32_t>(HidlDataspace::DISPLAY_P3));
static_assert(static_cast<uint32_t>(AidlDataspace::ADOBE_RGB) ==
              static_cast<uint32_t>(HidlDataspace::ADOBE_RGB));
static_assert(static_cast<uint32_t>(AidlDataspace::BT2020_LINEAR) ==
              static_cast<uint32_t>(HidlDataspace::BT2020_LINEAR));
static_assert(static_cast<uint32_t>(AidlDataspace::BT2020) ==
              static_cast<uint32_t>(HidlDataspace::BT2020));
static_assert(static_cast<uint32_t>(AidlDataspace::BT2020_PQ) ==
              static_cast<uint32_t>(HidlDataspace::BT2020_PQ));
static_assert(static_cast<uint32_t>(AidlDataspace::DEPTH) ==
              static_cast<uint32_t>(HidlDataspace::DEPTH));
static_assert(static_cast<uint32_t>(AidlDataspace::SENSOR) ==
              static_cast<uint32_t>(HidlDataspace::SENSOR));
static_assert(static_cast<uint32_t>(AidlDataspace::BT2020_ITU) ==
              static_cast<uint32_t>(HidlDataspace::BT2020_ITU));
static_assert(static_cast<uint32_t>(AidlDataspace::BT2020_ITU_PQ) ==
              static_cast<uint32_t>(HidlDataspace::BT2020_ITU_PQ));
static_assert(static_cast<uint32_t>(AidlDataspace::BT2020_ITU_HLG) ==
              static_cast<uint32_t>(HidlDataspace::BT2020_ITU_HLG));
static_assert(static_cast<uint32_t>(AidlDataspace::BT2020_HLG) ==
              static_cast<uint32_t>(HidlDataspace::BT2020_HLG));
static_assert(static_cast<uint32_t>(AidlDataspace::DISPLAY_BT2020) ==
              static_cast<uint32_t>(HidlDataspace::DISPLAY_BT2020));
static_assert(static_cast<uint32_t>(AidlDataspace::DYNAMIC_DEPTH) ==
              static_cast<uint32_t>(HidlDataspace::DYNAMIC_DEPTH));
static_assert(static_cast<uint32_t>(AidlDataspace::JPEG_APP_SEGMENTS) ==
              static_cast<uint32_t>(HidlDataspace::JPEG_APP_SEGMENTS));
static_assert(static_cast<uint32_t>(AidlDataspace::HEIF) ==
              static_cast<uint32_t>(HidlDataspace::HEIF));
