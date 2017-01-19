/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "CacheItem.h"

#include <stdint.h>
#include <inttypes.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include "utils.h"

using android::base::StringPrintf;

namespace android {
namespace installd {

CacheItem::CacheItem(const std::shared_ptr<CacheItem>& parent, FTSENT* p) : mParent(parent) {
    level = p->fts_level;
    directory = S_ISDIR(p->fts_statp->st_mode);
    size = p->fts_statp->st_blocks * 512;
    modified = p->fts_statp->st_mtime;
    mName = p->fts_path;
}

CacheItem::~CacheItem() {
}

std::string CacheItem::toString() {
    return StringPrintf("%s size=%" PRId64 " mod=%ld", buildPath().c_str(), size, modified);
}

std::string CacheItem::buildPath() {
    std::string res = mName;
    std::shared_ptr<CacheItem> parent = mParent;
    while (parent) {
        res.insert(0, parent->mName);
        parent = parent->mParent;
    }
    return res;
}

int CacheItem::purge() {
    auto path = buildPath();
    if (directory) {
        return delete_dir_contents_and_dir(path, true);
    } else {
        int res = unlink(path.c_str());
        if (res != 0) {
            PLOG(WARNING) << "Failed to unlink " << path;
        }
        return res;
    }
}

}  // namespace installd
}  // namespace android
