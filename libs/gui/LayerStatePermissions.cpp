/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <binder/IPCThreadState.h>
#include <gui/LayerStatePermissions.h>
#include <private/android_filesystem_config.h>
#ifndef __ANDROID_VNDK__
#include <binder/PermissionCache.h>
#endif // __ANDROID_VNDK__
#include <gui/LayerState.h>

namespace android {
std::vector<std::pair<String16, int>> LayerStatePermissions::mPermissionMap = {
        // If caller has ACCESS_SURFACE_FLINGER, they automatically get ROTATE_SURFACE_FLINGER
        // permission, as well
        {String16("android.permission.ACCESS_SURFACE_FLINGER"),
         layer_state_t::Permission::ACCESS_SURFACE_FLINGER |
                 layer_state_t::Permission::ROTATE_SURFACE_FLINGER},
        {String16("android.permission.ROTATE_SURFACE_FLINGER"),
         layer_state_t::Permission::ROTATE_SURFACE_FLINGER},
        {String16("android.permission.INTERNAL_SYSTEM_WINDOW"),
         layer_state_t::Permission::INTERNAL_SYSTEM_WINDOW},
};

static bool callingThreadHasPermission(const String16& permission __attribute__((unused)),
                                       int pid __attribute__((unused)),
                                       int uid __attribute__((unused))) {
#ifndef __ANDROID_VNDK__
    return uid == AID_GRAPHICS || uid == AID_SYSTEM ||
            PermissionCache::checkPermission(permission, pid, uid);
#endif // __ANDROID_VNDK__
    return false;
}

uint32_t LayerStatePermissions::getTransactionPermissions(int pid, int uid) {
    uint32_t permissions = 0;
    for (const auto& [permissionName, permissionVal] : mPermissionMap) {
        if (callingThreadHasPermission(permissionName, pid, uid)) {
            permissions |= permissionVal;
        }
    }

    return permissions;
}
} // namespace android
