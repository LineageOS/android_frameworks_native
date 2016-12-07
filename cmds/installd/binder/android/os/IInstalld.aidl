/*
 * Copyright (C) 2016 The Android Open Source Project
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

package android.os;

interface IInstalld {
    void createUserData(@nullable @utf8InCpp String uuid, int userId, int userSerial, int flags);
    void destroyUserData(@nullable @utf8InCpp String uuid, int userId, int flags);

    void createAppData(in @nullable @utf8InCpp String uuid, in @utf8InCpp String packageName,
            int userId, int flags, int appId, in @utf8InCpp String seInfo, int targetSdkVersion);
    void restoreconAppData(@nullable @utf8InCpp String uuid, @utf8InCpp String packageName,
            int userId, int flags, int appId, @utf8InCpp String seInfo);
    void migrateAppData(@nullable @utf8InCpp String uuid, @utf8InCpp String packageName,
            int userId, int flags);
    void clearAppData(@nullable @utf8InCpp String uuid, @utf8InCpp String packageName,
            int userId, int flags, long ceDataInode);
    void destroyAppData(@nullable @utf8InCpp String uuid, @utf8InCpp String packageName,
            int userId, int flags, long ceDataInode);
    long getAppDataInode(@nullable @utf8InCpp String uuid, @utf8InCpp String packageName,
            int userId, int flags);

    void moveCompleteApp(@nullable @utf8InCpp String fromUuid, @nullable @utf8InCpp String toUuid,
            @utf8InCpp String packageName, @utf8InCpp String dataAppName, int appId,
            @utf8InCpp String seInfo, int targetSdkVersion);
}
