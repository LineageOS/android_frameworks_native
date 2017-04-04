#include "performance_service.h"

#include <sched.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <pdx/default_transport/service_endpoint.h>
#include <pdx/rpc/argument_encoder.h>
#include <pdx/rpc/message_buffer.h>
#include <pdx/rpc/remote_method.h>
#include <private/dvr/performance_rpc.h>

#include "task.h"

// This prctl is only available in Android kernels.
#define PR_SET_TIMERSLACK_PID 41

using android::pdx::Message;
using android::pdx::rpc::DispatchRemoteMethod;
using android::pdx::default_transport::Endpoint;

namespace {

const char kCpuSetBasePath[] = "/dev/cpuset";

constexpr unsigned long kTimerSlackForegroundNs = 50000;
constexpr unsigned long kTimerSlackBackgroundNs = 40000000;

}  // anonymous namespace

namespace android {
namespace dvr {

PerformanceService::PerformanceService()
    : BASE("PerformanceService",
           Endpoint::Create(PerformanceRPC::kClientPath)) {
  cpuset_.Load(kCpuSetBasePath);

  Task task(getpid());
  ALOGI("Running in cpuset=%s uid=%d gid=%d", task.GetCpuSetPath().c_str(),
        task.user_id()[Task::kUidReal], task.group_id()[Task::kUidReal]);

  // Errors here are checked in IsInitialized().
  sched_fifo_min_priority_ = sched_get_priority_min(SCHED_FIFO);
  sched_fifo_max_priority_ = sched_get_priority_max(SCHED_FIFO);

  const int fifo_range = sched_fifo_max_priority_ - sched_fifo_min_priority_;
  const int fifo_low = sched_fifo_min_priority_;
  const int fifo_medium = sched_fifo_min_priority_ + fifo_range / 5;

  // TODO(eieio): Make this configurable on the command line.
  cpuset_.MoveUnboundTasks("/kernel");

  // Setup the scheduler classes.
  scheduler_classes_ = {
      {"audio:low",
       {.timer_slack = kTimerSlackForegroundNs,
        .scheduler_policy = SCHED_FIFO | SCHED_RESET_ON_FORK,
        .priority = fifo_medium}},
      {"audio:high",
       {.timer_slack = kTimerSlackForegroundNs,
        .scheduler_policy = SCHED_FIFO | SCHED_RESET_ON_FORK,
        .priority = fifo_medium + 3}},
      {"graphics",
       {.timer_slack = kTimerSlackForegroundNs,
        .scheduler_policy = SCHED_FIFO | SCHED_RESET_ON_FORK,
        .priority = fifo_medium}},
      {"graphics:low",
       {.timer_slack = kTimerSlackForegroundNs,
        .scheduler_policy = SCHED_FIFO | SCHED_RESET_ON_FORK,
        .priority = fifo_medium}},
      {"graphics:high",
       {.timer_slack = kTimerSlackForegroundNs,
        .scheduler_policy = SCHED_FIFO | SCHED_RESET_ON_FORK,
        .priority = fifo_medium + 2}},
      {"sensors",
       {.timer_slack = kTimerSlackForegroundNs,
        .scheduler_policy = SCHED_FIFO | SCHED_RESET_ON_FORK,
        .priority = fifo_low}},
      {"sensors:low",
       {.timer_slack = kTimerSlackForegroundNs,
        .scheduler_policy = SCHED_FIFO | SCHED_RESET_ON_FORK,
        .priority = fifo_low}},
      {"sensors:high",
       {.timer_slack = kTimerSlackForegroundNs,
        .scheduler_policy = SCHED_FIFO | SCHED_RESET_ON_FORK,
        .priority = fifo_low + 1}},
      {"normal",
       {.timer_slack = kTimerSlackForegroundNs,
        .scheduler_policy = SCHED_NORMAL,
        .priority = 0}},
      {"foreground",
       {.timer_slack = kTimerSlackForegroundNs,
        .scheduler_policy = SCHED_NORMAL,
        .priority = 0}},
      {"background",
       {.timer_slack = kTimerSlackBackgroundNs,
        .scheduler_policy = SCHED_BATCH,
        .priority = 0}},
      {"batch",
       {.timer_slack = kTimerSlackBackgroundNs,
        .scheduler_policy = SCHED_BATCH,
        .priority = 0}},
  };
}

bool PerformanceService::IsInitialized() const {
  return BASE::IsInitialized() && cpuset_ && sched_fifo_min_priority_ >= 0 &&
         sched_fifo_max_priority_ >= 0;
}

std::string PerformanceService::DumpState(size_t /*max_length*/) {
  return cpuset_.DumpState();
}

int PerformanceService::OnSetCpuPartition(Message& message, pid_t task_id,
                                          const std::string& partition) {
  Task task(task_id);
  if (!task || task.thread_group_id() != message.GetProcessId())
    return -EINVAL;

  auto target_set = cpuset_.Lookup(partition);
  if (!target_set)
    return -ENOENT;

  const auto attach_error = target_set->AttachTask(task_id);
  if (attach_error)
    return attach_error;

  return 0;
}

int PerformanceService::OnSetSchedulerClass(
    Message& message, pid_t task_id, const std::string& scheduler_class) {
  // Make sure the task id is valid and belongs to the sending process.
  Task task(task_id);
  if (!task || task.thread_group_id() != message.GetProcessId())
    return -EINVAL;

  struct sched_param param;

  // TODO(eieio): Apply rules based on the requesting process. Applications are
  // only allowed one audio thread that runs at SCHED_FIFO. System services can
  // have more than one.
  auto search = scheduler_classes_.find(scheduler_class);
  if (search != scheduler_classes_.end()) {
    auto config = search->second;
    param.sched_priority = config.priority;
    sched_setscheduler(task_id, config.scheduler_policy, &param);
    prctl(PR_SET_TIMERSLACK_PID, config.timer_slack, task_id);
    ALOGI("PerformanceService::OnSetSchedulerClass: Set task=%d to class=%s.",
          task_id, scheduler_class.c_str());
    return 0;
  } else {
    ALOGE(
        "PerformanceService::OnSetSchedulerClass: Invalid class=%s requested "
        "by task=%d.",
        scheduler_class.c_str(), task_id);
    return -EINVAL;
  }
}

std::string PerformanceService::OnGetCpuPartition(Message& message,
                                                  pid_t task_id) {
  // Make sure the task id is valid and belongs to the sending process.
  Task task(task_id);
  if (!task || task.thread_group_id() != message.GetProcessId())
    REPLY_ERROR_RETURN(message, EINVAL, "");

  return task.GetCpuSetPath();
}

pdx::Status<void> PerformanceService::HandleMessage(Message& message) {
  switch (message.GetOp()) {
    case PerformanceRPC::SetCpuPartition::Opcode:
      DispatchRemoteMethod<PerformanceRPC::SetSchedulerClass>(
          *this, &PerformanceService::OnSetCpuPartition, message);
      return {};

    case PerformanceRPC::SetSchedulerClass::Opcode:
      DispatchRemoteMethod<PerformanceRPC::SetSchedulerClass>(
          *this, &PerformanceService::OnSetSchedulerClass, message);
      return {};

    case PerformanceRPC::GetCpuPartition::Opcode:
      DispatchRemoteMethod<PerformanceRPC::GetCpuPartition>(
          *this, &PerformanceService::OnGetCpuPartition, message);
      return {};

    default:
      return Service::HandleMessage(message);
  }
}

}  // namespace dvr
}  // namespace android
