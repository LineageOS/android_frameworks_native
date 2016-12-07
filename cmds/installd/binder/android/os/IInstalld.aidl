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

    void rmdex(@utf8InCpp String codePath, @utf8InCpp String instructionSet);

    boolean mergeProfiles(int uid, @utf8InCpp String packageName);
    boolean dumpProfiles(int uid, @utf8InCpp String packageName, @utf8InCpp String codePaths);
    void clearAppProfiles(@utf8InCpp String packageName);
    void destroyAppProfiles(@utf8InCpp String packageName);

    void idmap(@utf8InCpp String targetApkPath, @utf8InCpp String overlayApkPath, int uid);
    void rmPackageDir(@utf8InCpp String packageDir);
    void markBootComplete(@utf8InCpp String instructionSet);
    void freeCache(@nullable @utf8InCpp String uuid, long freeStorageSize);
    void linkNativeLibraryDirectory(@nullable @utf8InCpp String uuid,
            @utf8InCpp String packageName, @utf8InCpp String nativeLibPath32, int userId);
    void createOatDir(@utf8InCpp String oatDir, @utf8InCpp String instructionSet);
    void linkFile(@utf8InCpp String relativePath, @utf8InCpp String fromBase,
            @utf8InCpp String toBase);
    void moveAb(@utf8InCpp String apkPath, @utf8InCpp String instructionSet,
            @utf8InCpp String outputPath);
    void deleteOdex(@utf8InCpp String apkPath, @utf8InCpp String instructionSet,
            @utf8InCpp String outputPath);
}
