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

#define ATRACE_TAG ATRACE_TAG_PACKAGE_MANAGER

#include "CacheTracker.h"

#include <fts.h>
#include <sys/quota.h>
#include <utils/Trace.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include "utils.h"

using android::base::StringPrintf;

namespace android {
namespace installd {

CacheTracker::CacheTracker(userid_t userId, appid_t appId, const std::string& quotaDevice) :
        cacheUsed(0), cacheQuota(0), mUserId(userId), mAppId(appId), mQuotaDevice(quotaDevice),
        mItemsLoaded(false) {
}

CacheTracker::~CacheTracker() {
}

std::string CacheTracker::toString() {
    return StringPrintf("UID=%d used=%" PRId64 " quota=%" PRId64 " ratio=%d",
            multiuser_get_uid(mUserId, mAppId), cacheUsed, cacheQuota, getCacheRatio());
}

void CacheTracker::addDataPath(const std::string& dataPath) {
    mDataPaths.push_back(dataPath);
}

void CacheTracker::loadStats() {
    int cacheGid = multiuser_get_cache_gid(mUserId, mAppId);
    if (cacheGid != -1 && !mQuotaDevice.empty()) {
        ATRACE_BEGIN("loadStats quota");
        struct dqblk dq;
        if (quotactl(QCMD(Q_GETQUOTA, GRPQUOTA), mQuotaDevice.c_str(), cacheGid,
                reinterpret_cast<char*>(&dq)) != 0) {
            ATRACE_END();
            if (errno != ESRCH) {
                PLOG(ERROR) << "Failed to quotactl " << mQuotaDevice << " for GID " << cacheGid;
            }
        } else {
            cacheUsed = dq.dqb_curspace;
            ATRACE_END();
            return;
        }
    }

    ATRACE_BEGIN("loadStats tree");
    cacheUsed = 0;
    for (auto path : mDataPaths) {
        auto cachePath = read_path_inode(path, "cache", kXattrInodeCache);
        auto codeCachePath = read_path_inode(path, "code_cache", kXattrInodeCodeCache);
        calculate_tree_size(cachePath, &cacheUsed);
        calculate_tree_size(codeCachePath, &cacheUsed);
    }
    ATRACE_END();
}

void CacheTracker::loadItemsFrom(const std::string& path) {
    FTS *fts;
    FTSENT *p;
    char *argv[] = { (char*) path.c_str(), nullptr };
    if (!(fts = fts_open(argv, FTS_PHYSICAL | FTS_XDEV, NULL))) {
        PLOG(WARNING) << "Failed to fts_open " << path;
        return;
    }
    // TODO: add support for "user.atomic" and "user.tombstone" xattrs
    while ((p = fts_read(fts)) != NULL) {
        switch (p->fts_info) {
        case FTS_D:
            // Track the newest mtime of anything inside so we consider
            // deleting the directory last
            p->fts_number = p->fts_statp->st_mtime;
            break;
        case FTS_DP:
            p->fts_statp->st_mtime = p->fts_number;

            // Ignore the actual top-level cache directories
            if (p->fts_level == 0) break;
        case FTS_DEFAULT:
        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
            // TODO: optimize path memory footprint
            items.push_back(std::shared_ptr<CacheItem>(new CacheItem(nullptr, p)));

            // Track the newest modified item under this tree
            p->fts_parent->fts_number =
                    std::max(p->fts_parent->fts_number, p->fts_statp->st_mtime);
            break;
        }
    }
    fts_close(fts);
}

void CacheTracker::loadItems() {
    items.clear();

    ATRACE_BEGIN("loadItems");
    for (auto path : mDataPaths) {
        loadItemsFrom(read_path_inode(path, "cache", kXattrInodeCache));
        loadItemsFrom(read_path_inode(path, "code_cache", kXattrInodeCodeCache));
    }
    ATRACE_END();

    ATRACE_BEGIN("sortItems");
    auto cmp = [](std::shared_ptr<CacheItem> left, std::shared_ptr<CacheItem> right) {
        // TODO: sort dotfiles last
        // TODO: sort code_cache last
        if (left->modified != right->modified) {
            return (left->modified > right->modified);
        }
        if (left->level != right->level) {
            return (left->level < right->level);
        }
        return left->directory;
    };
    std::sort(items.begin(), items.end(), cmp);
    ATRACE_END();
}

void CacheTracker::ensureItems() {
    if (mItemsLoaded) {
        return;
    } else {
        loadItems();
        mItemsLoaded = true;
    }
}

int CacheTracker::getCacheRatio() {
    if (cacheQuota == 0) {
        return 0;
    } else {
        return (cacheUsed * 10000) / cacheQuota;
    }
}

}  // namespace installd
}  // namespace android
