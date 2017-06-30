#include <errno.h>
#include <sched.h>
#include <sys/types.h>
#include <unistd.h>

#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <thread>

#include <dvr/performance_client_api.h>
#include <gtest/gtest.h>
#include <private/android_filesystem_config.h>

namespace {

const char kTrustedUidEnvironmentVariable[] = "GTEST_TRUSTED_UID";

}  // anonymous namespace

TEST(DISABLED_PerformanceTest, SetCpuPartition) {
  int error;

  // Test setting the the partition for the current task.
  error = dvrSetCpuPartition(0, "/application/background");
  EXPECT_EQ(0, error);

  error = dvrSetCpuPartition(0, "/application/performance");
  EXPECT_EQ(0, error);

  // Test setting the partition for one of our tasks.
  bool done = false;
  pid_t task_id = 0;
  std::mutex mutex;
  std::condition_variable done_condition, id_condition;

  std::thread thread([&] {
    std::unique_lock<std::mutex> lock(mutex);

    task_id = gettid();
    id_condition.notify_one();

    done_condition.wait(lock, [&done] { return done; });
  });

  {
    std::unique_lock<std::mutex> lock(mutex);
    id_condition.wait(lock, [&task_id] { return task_id != 0; });
  }
  EXPECT_NE(0, task_id);

  error = dvrSetCpuPartition(task_id, "/application");
  EXPECT_EQ(0, error);

  {
    std::lock_guard<std::mutex> lock(mutex);
    done = true;
    done_condition.notify_one();
  }
  thread.join();

  // Test setting the partition for a task that isn't valid using
  // the task id of the thread that we just joined. Technically the
  // id could wrap around by the time we get here, but this is
  // extremely unlikely.
  error = dvrSetCpuPartition(task_id, "/application");
  EXPECT_EQ(-EINVAL, error);

  // Test setting the partition for a task that doesn't belong to us.
  error = dvrSetCpuPartition(1, "/application");
  EXPECT_EQ(-EINVAL, error);

  // Test setting the partition to one that doesn't exist.
  error = dvrSetCpuPartition(0, "/foobar");
  EXPECT_EQ(-ENOENT, error);
}

TEST(PerformanceTest, SetSchedulerClass) {
  int error;

  // TODO(eieio): Test all supported scheduler classes and priority levels.

  error = dvrSetSchedulerClass(0, "background");
  EXPECT_EQ(0, error);
  EXPECT_EQ(SCHED_BATCH, sched_getscheduler(0));

  error = dvrSetSchedulerClass(0, "audio:low");
  EXPECT_EQ(0, error);
  EXPECT_EQ(SCHED_FIFO | SCHED_RESET_ON_FORK, sched_getscheduler(0));

  error = dvrSetSchedulerClass(0, "normal");
  EXPECT_EQ(0, error);
  EXPECT_EQ(SCHED_NORMAL, sched_getscheduler(0));

  error = dvrSetSchedulerClass(0, "foobar");
  EXPECT_EQ(-EINVAL, error);
}

// This API mirrors SetSchedulerClass for now. Replace with with a more specific
// test once the policy API is fully implemented.
TEST(PerformanceTest, SetSchedulerPolicy) {
  int error;

  error = dvrSetSchedulerPolicy(0, "background");
  EXPECT_EQ(0, error);
  EXPECT_EQ(SCHED_BATCH, sched_getscheduler(0));

  error = dvrSetSchedulerPolicy(0, "audio:low");
  EXPECT_EQ(0, error);
  EXPECT_EQ(SCHED_FIFO | SCHED_RESET_ON_FORK, sched_getscheduler(0));

  error = dvrSetSchedulerPolicy(0, "normal");
  EXPECT_EQ(0, error);
  EXPECT_EQ(SCHED_NORMAL, sched_getscheduler(0));

  error = dvrSetSchedulerPolicy(0, "foobar");
  EXPECT_EQ(-EINVAL, error);
}

TEST(PerformanceTest, SchedulerClassResetOnFork) {
  int error;

  error = dvrSetSchedulerClass(0, "graphics:high");
  EXPECT_EQ(0, error);
  EXPECT_EQ(SCHED_FIFO | SCHED_RESET_ON_FORK, sched_getscheduler(0));

  int scheduler = -1;
  std::thread thread([&]() { scheduler = sched_getscheduler(0); });
  thread.join();

  EXPECT_EQ(SCHED_NORMAL, scheduler);

  // Return to SCHED_NORMAL.
  error = dvrSetSchedulerClass(0, "normal");
  EXPECT_EQ(0, error);
  EXPECT_EQ(SCHED_NORMAL, sched_getscheduler(0));
}

TEST(PerformanceTest, GetCpuPartition) {
  int error;
  char partition[PATH_MAX + 1];

  error = dvrSetCpuPartition(0, "/");
  ASSERT_EQ(0, error);

  error = dvrGetCpuPartition(0, partition, sizeof(partition));
  EXPECT_EQ(0, error);
  EXPECT_EQ("/", std::string(partition));

  error = dvrSetCpuPartition(0, "/application");
  EXPECT_EQ(0, error);

  error = dvrGetCpuPartition(0, partition, sizeof(partition));
  EXPECT_EQ(0, error);
  EXPECT_EQ("/application", std::string(partition));

  // Test passing a buffer that is too short.
  error = dvrGetCpuPartition(0, partition, 5);
  EXPECT_EQ(-ENOBUFS, error);

  // Test getting the partition for a task that doesn't belong to us.
  error = dvrGetCpuPartition(1, partition, sizeof(partition));
  EXPECT_EQ(-EINVAL, error);

  // Test passing a nullptr value for partition buffer.
  error = dvrGetCpuPartition(0, nullptr, sizeof(partition));
  EXPECT_EQ(-EINVAL, error);
}

TEST(PerformanceTest, Permissions) {
  int error;

  const int original_uid = getuid();
  const int original_gid = getgid();
  int trusted_uid = -1;

  // See if the environment variable GTEST_TRUSTED_UID is set. If it is enable
  // testing the ActivityManager trusted uid permission checks using that uid.
  const char* trusted_uid_env = std::getenv(kTrustedUidEnvironmentVariable);
  if (trusted_uid_env)
    trusted_uid = std::atoi(trusted_uid_env);

  ASSERT_EQ(AID_ROOT, original_uid)
      << "This test must run as root to function correctly!";

  // Test unprivileged policies on a task that does not belong to this process.
  // Use the init process (task_id=1) as the target.
  error = dvrSetSchedulerPolicy(1, "batch");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(1, "background");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(1, "foreground");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(1, "normal");
  EXPECT_EQ(-EINVAL, error);

  // Switch the uid/gid to an id that should not have permission to access any
  // privileged actions.
  ASSERT_EQ(0, setresgid(AID_NOBODY, AID_NOBODY, -1))
      << "Failed to set gid: " << strerror(errno);
  ASSERT_EQ(0, setresuid(AID_NOBODY, AID_NOBODY, -1))
      << "Failed to set uid: " << strerror(errno);

  // Unprivileged policies.
  error = dvrSetSchedulerPolicy(0, "batch");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "background");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "foreground");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "normal");
  EXPECT_EQ(0, error);

  // Privileged policies.
  error = dvrSetSchedulerPolicy(0, "audio:low");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "audio:high");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "graphics");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "graphics:low");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "graphics:high");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "sensors");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "sensors:low");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "sensors:high");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "vr:system:arp");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "vr:app:render");
  EXPECT_EQ(-EINVAL, error);

  // uid=AID_SYSTEM / gid=AID_NOBODY
  ASSERT_EQ(0, setresuid(original_uid, original_uid, -1))
      << "Failed to restore uid: " << strerror(errno);
  ASSERT_EQ(0, setresuid(AID_SYSTEM, AID_SYSTEM, -1))
      << "Failed to set uid: " << strerror(errno);

  // Unprivileged policies.
  error = dvrSetSchedulerPolicy(0, "batch");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "background");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "foreground");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "normal");
  EXPECT_EQ(0, error);

  // Privileged policies.
  error = dvrSetSchedulerPolicy(0, "audio:low");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "audio:high");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "graphics");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "graphics:low");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "graphics:high");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "sensors");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "sensors:low");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "sensors:high");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "vr:system:arp");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "vr:app:render");
  EXPECT_EQ(0, error);

  // uid=AID_NOBODY / gid=AID_SYSTEM
  ASSERT_EQ(0, setresuid(original_uid, original_uid, -1))
      << "Failed to restore uid: " << strerror(errno);
  ASSERT_EQ(0, setresgid(original_gid, original_gid, -1))
      << "Failed to restore gid: " << strerror(errno);
  ASSERT_EQ(0, setresgid(AID_SYSTEM, AID_SYSTEM, -1))
      << "Failed to set gid: " << strerror(errno);
  ASSERT_EQ(0, setresuid(AID_SYSTEM, AID_NOBODY, -1))
      << "Failed to set uid: " << strerror(errno);

  // Unprivileged policies.
  error = dvrSetSchedulerPolicy(0, "batch");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "background");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "foreground");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "normal");
  EXPECT_EQ(0, error);

  // Privileged policies.
  error = dvrSetSchedulerPolicy(0, "audio:low");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "audio:high");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "graphics");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "graphics:low");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "graphics:high");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "sensors");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "sensors:low");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "sensors:high");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "vr:system:arp");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "vr:app:render");
  EXPECT_EQ(0, error);

  // uid=AID_GRAPHICS / gid=AID_NOBODY
  ASSERT_EQ(0, setresuid(original_uid, original_uid, -1))
      << "Failed to restore uid: " << strerror(errno);
  ASSERT_EQ(0, setresgid(original_gid, original_gid, -1))
      << "Failed to restore gid: " << strerror(errno);
  ASSERT_EQ(0, setresgid(AID_NOBODY, AID_NOBODY, -1))
      << "Failed to set gid: " << strerror(errno);
  ASSERT_EQ(0, setresuid(AID_GRAPHICS, AID_GRAPHICS, -1))
      << "Failed to set uid: " << strerror(errno);

  // Unprivileged policies.
  error = dvrSetSchedulerPolicy(0, "batch");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "background");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "foreground");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "normal");
  EXPECT_EQ(0, error);

  // Privileged policies.
  error = dvrSetSchedulerPolicy(0, "audio:low");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "audio:high");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "graphics");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "graphics:low");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "graphics:high");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "sensors");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "sensors:low");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "sensors:high");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "vr:system:arp");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "vr:app:render");
  EXPECT_EQ(-EINVAL, error);

  // uid=AID_NOBODY / gid=AID_GRAPHICS
  ASSERT_EQ(0, setresuid(original_uid, original_uid, -1))
      << "Failed to restore uid: " << strerror(errno);
  ASSERT_EQ(0, setresgid(original_gid, original_gid, -1))
      << "Failed to restore gid: " << strerror(errno);
  ASSERT_EQ(0, setresgid(AID_GRAPHICS, AID_GRAPHICS, -1))
      << "Failed to set gid: " << strerror(errno);
  ASSERT_EQ(0, setresuid(AID_NOBODY, AID_NOBODY, -1))
      << "Failed to set uid: " << strerror(errno);

  // Unprivileged policies.
  error = dvrSetSchedulerPolicy(0, "batch");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "background");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "foreground");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "normal");
  EXPECT_EQ(0, error);

  // Privileged policies.
  error = dvrSetSchedulerPolicy(0, "audio:low");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "audio:high");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "graphics");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "graphics:low");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "graphics:high");
  EXPECT_EQ(0, error);
  error = dvrSetSchedulerPolicy(0, "sensors");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "sensors:low");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "sensors:high");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "vr:system:arp");
  EXPECT_EQ(-EINVAL, error);
  error = dvrSetSchedulerPolicy(0, "vr:app:render");
  EXPECT_EQ(-EINVAL, error);

  if (trusted_uid != -1) {
    // uid=<trusted uid> / gid=AID_NOBODY
    ASSERT_EQ(0, setresuid(original_uid, original_uid, -1))
        << "Failed to restore uid: " << strerror(errno);
    ASSERT_EQ(0, setresgid(original_gid, original_gid, -1))
        << "Failed to restore gid: " << strerror(errno);
    ASSERT_EQ(0, setresgid(AID_NOBODY, AID_NOBODY, -1))
        << "Failed to set gid: " << strerror(errno);
    ASSERT_EQ(0, setresuid(trusted_uid, trusted_uid, -1))
        << "Failed to set uid: " << strerror(errno);

    // Unprivileged policies.
    error = dvrSetSchedulerPolicy(0, "batch");
    EXPECT_EQ(0, error);
    error = dvrSetSchedulerPolicy(0, "background");
    EXPECT_EQ(0, error);
    error = dvrSetSchedulerPolicy(0, "foreground");
    EXPECT_EQ(0, error);
    error = dvrSetSchedulerPolicy(0, "normal");
    EXPECT_EQ(0, error);

    // Privileged policies.
    error = dvrSetSchedulerPolicy(0, "audio:low");
    EXPECT_EQ(-EINVAL, error);
    error = dvrSetSchedulerPolicy(0, "audio:high");
    EXPECT_EQ(-EINVAL, error);
    error = dvrSetSchedulerPolicy(0, "graphics");
    EXPECT_EQ(0, error);
    error = dvrSetSchedulerPolicy(0, "graphics:low");
    EXPECT_EQ(0, error);
    error = dvrSetSchedulerPolicy(0, "graphics:high");
    EXPECT_EQ(0, error);
    error = dvrSetSchedulerPolicy(0, "sensors");
    EXPECT_EQ(-EINVAL, error);
    error = dvrSetSchedulerPolicy(0, "sensors:low");
    EXPECT_EQ(-EINVAL, error);
    error = dvrSetSchedulerPolicy(0, "sensors:high");
    EXPECT_EQ(-EINVAL, error);
    error = dvrSetSchedulerPolicy(0, "vr:system:arp");
    EXPECT_EQ(0, error);
    error = dvrSetSchedulerPolicy(0, "vr:app:render");
    EXPECT_EQ(0, error);
  }

  // Restore original effective uid/gid.
  ASSERT_EQ(0, setresgid(original_gid, original_gid, -1))
      << "Failed to restore gid: " << strerror(errno);
  ASSERT_EQ(0, setresuid(original_uid, original_uid, -1))
      << "Failed to restore uid: " << strerror(errno);
}
