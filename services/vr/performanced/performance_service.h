#ifndef ANDROID_DVR_PERFORMANCED_PERFORMANCE_SERVICE_H_
#define ANDROID_DVR_PERFORMANCED_PERFORMANCE_SERVICE_H_

#include <string>
#include <unordered_map>

#include <pdx/service.h>

#include "cpu_set.h"

namespace android {
namespace dvr {

// PerformanceService manages compute partitions usings cpusets. Different
// cpusets are assigned specific purposes and performance characteristics;
// clients may request for threads to be moved into these cpusets to help
// achieve system performance goals.
class PerformanceService : public pdx::ServiceBase<PerformanceService> {
 public:
  pdx::Status<void> HandleMessage(pdx::Message& message) override;
  bool IsInitialized() const override;

  std::string DumpState(size_t max_length) override;

 private:
  friend BASE;

  PerformanceService();

  int OnSetCpuPartition(pdx::Message& message, pid_t task_id,
                        const std::string& partition);
  int OnSetSchedulerClass(pdx::Message& message, pid_t task_id,
                          const std::string& scheduler_class);
  std::string OnGetCpuPartition(pdx::Message& message, pid_t task_id);

  CpuSetManager cpuset_;

  int sched_fifo_min_priority_;
  int sched_fifo_max_priority_;

  // Scheduler class config type.
  struct SchedulerClassConfig {
    unsigned long timer_slack;
    int scheduler_policy;
    int priority;
  };

  std::unordered_map<std::string, SchedulerClassConfig> scheduler_classes_;

  PerformanceService(const PerformanceService&) = delete;
  void operator=(const PerformanceService&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_PERFORMANCED_PERFORMANCE_SERVICE_H_
