/*
 * Copyright 2016 The Android Open Source Project
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

#include <android/frameworks/vr/composer/1.0/IVrComposerClient.h>
#include <hardware/gralloc.h>
#include <hardware/gralloc1.h>
#include <log/log.h>

#include "impl/vr_hwc.h"
#include "impl/vr_composer_client.h"

namespace android {
namespace dvr {

using android::hardware::graphics::common::V1_0::PixelFormat;
using android::frameworks::vr::composer::V1_0::IVrComposerClient;

VrComposerClient::VrComposerClient(dvr::VrHwc& hal)
    : ComposerClient(hal), mVrHal(hal) {}

VrComposerClient::~VrComposerClient() {}

std::unique_ptr<ComposerClient::CommandReader>
VrComposerClient::createCommandReader() {
  return std::unique_ptr<CommandReader>(new VrCommandReader(*this));
}

VrComposerClient::VrCommandReader::VrCommandReader(VrComposerClient& client)
    : CommandReader(client), mVrClient(client), mVrHal(client.mVrHal) {}

VrComposerClient::VrCommandReader::~VrCommandReader() {}

bool VrComposerClient::VrCommandReader::parseCommand(
    IComposerClient::Command command, uint16_t length) {
  IVrComposerClient::VrCommand vrCommand =
      static_cast<IVrComposerClient::VrCommand>(command);
  switch (vrCommand) {
    case IVrComposerClient::VrCommand::SET_LAYER_INFO:
      return parseSetLayerInfo(length);
    case IVrComposerClient::VrCommand::SET_CLIENT_TARGET_METADATA:
      return parseSetClientTargetMetadata(length);
    case IVrComposerClient::VrCommand::SET_LAYER_BUFFER_METADATA:
      return parseSetLayerBufferMetadata(length);
    default:
      return CommandReader::parseCommand(command, length);
  }
}

bool VrComposerClient::VrCommandReader::parseSetLayerInfo(uint16_t length) {
  if (length != 2) {
    return false;
  }

  auto err = mVrHal.setLayerInfo(mDisplay, mLayer, read(), read());
  if (err != Error::NONE) {
    mWriter.setError(getCommandLoc(), err);
  }

  return true;
}

bool VrComposerClient::VrCommandReader::parseSetClientTargetMetadata(
    uint16_t length) {
  if (length != 7)
    return false;

  auto err = mVrHal.setClientTargetMetadata(mDisplay, readBufferMetadata());
  if (err != Error::NONE)
    mWriter.setError(getCommandLoc(), err);

  return true;
}

bool VrComposerClient::VrCommandReader::parseSetLayerBufferMetadata(
    uint16_t length) {
  if (length != 7)
    return false;

  auto err = mVrHal.setLayerBufferMetadata(mDisplay, mLayer,
                                           readBufferMetadata());
  if (err != Error::NONE)
    mWriter.setError(getCommandLoc(), err);

  return true;
}

IVrComposerClient::BufferMetadata
VrComposerClient::VrCommandReader::readBufferMetadata() {
  IVrComposerClient::BufferMetadata metadata = {
    .width = read(),
    .height = read(),
    .stride = read(),
    .layerCount = read(),
    .format = static_cast<PixelFormat>(readSigned()),
    .usage = read64(),
  };
  return metadata;
}

}  // namespace dvr
}  // namespace android
