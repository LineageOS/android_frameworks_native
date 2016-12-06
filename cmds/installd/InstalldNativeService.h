/**
 * Copyright (c) 2016, The Android Open Source Project
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

#ifndef _INSTALLD_NATIVE_SERVICE_H_
#define _INSTALLD_NATIVE_SERVICE_H_

#include <vector>

#include <binder/BinderService.h>

#include "android/os/BnInstalld.h"

namespace android {
namespace installd {

class InstalldNativeService : public BinderService<InstalldNativeService>, public os::BnInstalld {
  public:
    static status_t start();
    static char const* getServiceName() { return "installd"; }
    virtual status_t dump(int fd, const Vector<String16> &args) override;

    binder::Status createAppData(const std::unique_ptr<std::string>& uuid,
            const std::string& pkgname, int32_t userid, int32_t flags, int32_t appid,
            const std::string& seinfo, int32_t targetSdkVersion);
};

}  // namespace installd
}  // namespace android

#endif  // _INSTALLD_NATIVE_SERVICE_H_
