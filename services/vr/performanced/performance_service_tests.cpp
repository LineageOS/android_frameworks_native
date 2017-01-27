#include <errno.h>
#include <sched.h>

#include <condition_variable>
#include <mutex>
#include <thread>

#include <dvr/performance_client_api.h>
#include <gtest/gtest.h>

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
