
#include "timeinstate.h"

#include <sys/sysinfo.h>

#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>

#include <android-base/unique_fd.h>
#include <bpf/BpfMap.h>
#include <cputimeinstate.h>
#include <libbpf.h>

namespace android {
namespace bpf {

static constexpr uint64_t NSEC_PER_SEC = 1000000000;
static constexpr uint64_t NSEC_PER_YEAR = NSEC_PER_SEC * 60 * 60 * 24 * 365;

using std::vector;

TEST(TimeInStateTest, SingleUid) {
    auto times = getUidCpuFreqTimes(0);
    ASSERT_TRUE(times.has_value());
    EXPECT_FALSE(times->empty());
}

TEST(TimeInStateTest, AllUid) {
    vector<size_t> sizes;
    auto map = getUidsCpuFreqTimes();
    ASSERT_TRUE(map.has_value());

    ASSERT_FALSE(map->empty());

    auto firstEntry = map->begin()->second;
    for (const auto &subEntry : firstEntry) sizes.emplace_back(subEntry.size());

    for (const auto &vec : *map) {
        ASSERT_EQ(vec.second.size(), sizes.size());
        for (size_t i = 0; i < vec.second.size(); ++i) ASSERT_EQ(vec.second[i].size(), sizes[i]);
    }
}

TEST(TimeInStateTest, SingleAndAllUidConsistent) {
    auto map = getUidsCpuFreqTimes();
    ASSERT_TRUE(map.has_value());
    ASSERT_FALSE(map->empty());

    for (const auto &kv : *map) {
        uint32_t uid = kv.first;
        auto times1 = kv.second;
        auto times2 = getUidCpuFreqTimes(uid);
        ASSERT_TRUE(times2.has_value());

        ASSERT_EQ(times1.size(), times2->size());
        for (uint32_t i = 0; i < times1.size(); ++i) {
            ASSERT_EQ(times1[i].size(), (*times2)[i].size());
            for (uint32_t j = 0; j < times1[i].size(); ++j) {
                ASSERT_LE((*times2)[i][j] - times1[i][j], NSEC_PER_SEC);
            }
        }
    }
}

void TestCheckDelta(uint64_t before, uint64_t after) {
    // Times should never decrease
    ASSERT_LE(before, after);
    // UID can't have run for more than ~1s on each CPU
    ASSERT_LE(after - before, NSEC_PER_SEC * 2 * get_nprocs_conf());
}

TEST(TimeInStateTest, AllUidMonotonic) {
    auto map1 = getUidsCpuFreqTimes();
    ASSERT_TRUE(map1.has_value());
    sleep(1);
    auto map2 = getUidsCpuFreqTimes();
    ASSERT_TRUE(map2.has_value());

    for (const auto &kv : *map1) {
        uint32_t uid = kv.first;
        auto times = kv.second;
        ASSERT_NE(map2->find(uid), map2->end());
        for (uint32_t policy = 0; policy < times.size(); ++policy) {
            for (uint32_t freqIdx = 0; freqIdx < times[policy].size(); ++freqIdx) {
                auto before = times[policy][freqIdx];
                auto after = (*map2)[uid][policy][freqIdx];
                ASSERT_NO_FATAL_FAILURE(TestCheckDelta(before, after));
            }
        }
    }
}

TEST(TimeInStateTest, AllUidSanityCheck) {
    auto map = getUidsCpuFreqTimes();
    ASSERT_TRUE(map.has_value());

    bool foundLargeValue = false;
    for (const auto &kv : *map) {
        for (const auto &timeVec : kv.second) {
            for (const auto &time : timeVec) {
                ASSERT_LE(time, NSEC_PER_YEAR);
                if (time > UINT32_MAX) foundLargeValue = true;
            }
        }
    }
    // UINT32_MAX nanoseconds is less than 5 seconds, so if every part of our pipeline is using
    // uint64_t as expected, we should have some times higher than that.
    ASSERT_TRUE(foundLargeValue);
}

TEST(TimeInStateTest, RemoveUid) {
    uint32_t uid = 0;
    {
        // Find an unused UID
        auto times = getUidsCpuFreqTimes();
        ASSERT_TRUE(times.has_value());
        ASSERT_FALSE(times->empty());
        for (const auto &kv : *times) uid = std::max(uid, kv.first);
        ++uid;
    }
    {
        // Add a map entry for our fake UID by copying a real map entry
        android::base::unique_fd fd{bpf_obj_get(BPF_FS_PATH "map_time_in_state_uid_times_map")};
        ASSERT_GE(fd, 0);
        time_key_t k;
        ASSERT_FALSE(getFirstMapKey(fd, &k));
        std::vector<val_t> vals(get_nprocs_conf());
        ASSERT_FALSE(findMapEntry(fd, &k, vals.data()));
        k.uid = uid;
        ASSERT_FALSE(writeToMapEntry(fd, &k, vals.data(), BPF_NOEXIST));
    }
    auto times = getUidCpuFreqTimes(uid);
    ASSERT_TRUE(times.has_value());
    ASSERT_FALSE(times->empty());

    uint64_t sum = 0;
    for (size_t i = 0; i < times->size(); ++i) {
        for (auto x : (*times)[i]) sum += x;
    }
    ASSERT_GT(sum, (uint64_t)0);

    ASSERT_TRUE(clearUidCpuFreqTimes(uid));

    auto allTimes = getUidsCpuFreqTimes();
    ASSERT_TRUE(allTimes.has_value());
    ASSERT_FALSE(allTimes->empty());
    ASSERT_EQ(allTimes->find(uid), allTimes->end());
}

} // namespace bpf
} // namespace android
