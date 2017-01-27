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
#ifndef VR_WINDOW_MANAGER_COMPOSER_IMPL_SYNC_TIMELINE_H_
#define VR_WINDOW_MANAGER_COMPOSER_IMPL_SYNC_TIMELINE_H_

#include <android-base/unique_fd.h>

namespace android {
namespace dvr {

// TODO(dnicoara): Remove this and move to EGL based fences.
class SyncTimeline {
 public:
  SyncTimeline();
  ~SyncTimeline();

  bool Initialize();

  int CreateFence(int time);
  bool IncrementTimeline();

 private:
  base::unique_fd timeline_fd_;

  SyncTimeline(const SyncTimeline&) = delete;
  void operator=(const SyncTimeline&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_COMPOSER_IMPL_SYNC_TIMELINE_H_
