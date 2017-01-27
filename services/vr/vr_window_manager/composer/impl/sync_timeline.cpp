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
#include "sync_timeline.h"

#include <sys/cdefs.h>
#include <sw_sync.h>
#include <unistd.h>

namespace android {
namespace dvr {

SyncTimeline::SyncTimeline() {}

SyncTimeline::~SyncTimeline() {}

bool SyncTimeline::Initialize() {
  timeline_fd_.reset(sw_sync_timeline_create());
  return timeline_fd_ >= 0;
}

int SyncTimeline::CreateFence(int time) {
  return sw_sync_fence_create(timeline_fd_.get(), "dummy fence", time);
}

bool SyncTimeline::IncrementTimeline() {
  return sw_sync_timeline_inc(timeline_fd_.get(), 1) == 0;
}

}  // namespace dvr
}  // namespace android
