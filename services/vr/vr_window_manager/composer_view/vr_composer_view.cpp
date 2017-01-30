/*
 * Copyright 2017 The Android Open Source Project
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
#include <binder/ProcessState.h>
#include <hwbinder/IPCThreadState.h>
#include <impl/vr_composer_view.h>
#include <impl/vr_hwc.h>

using namespace android;
using namespace android::dvr;

int main(int, char**) {
  android::ProcessState::self()->startThreadPool();

  const char instance[] = "vr_hwcomposer";
  sp<IComposer> service = HIDL_FETCH_IComposer(instance);
  LOG_ALWAYS_FATAL_IF(!service.get(), "Failed to get service");
  LOG_ALWAYS_FATAL_IF(service->isRemote(), "Service is remote");

  LOG_ALWAYS_FATAL_IF(service->registerAsService(instance) != ::android::OK,
                      "Failed to register service");

  sp<IVrComposerView> composer_view = HIDL_FETCH_IVrComposerView(
      "DaydreamDisplay");
  LOG_ALWAYS_FATAL_IF(!composer_view.get(),
                      "Failed to get vr_composer_view service");
  LOG_ALWAYS_FATAL_IF(composer_view->isRemote(),
                      "vr_composer_view service is remote");

  composer_view->registerAsService("DaydreamDisplay");

  GetVrComposerViewFromIVrComposerView(composer_view.get())->Initialize(
      GetComposerViewFromIComposer(service.get()));

  android::hardware::ProcessState::self()->startThreadPool();
  android::hardware::IPCThreadState::self()->joinThreadPool();

  return 0;
}
