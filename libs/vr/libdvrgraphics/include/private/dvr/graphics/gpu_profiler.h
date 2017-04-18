#ifndef ANDROID_DVR_GPU_PROFILER_H_
#define ANDROID_DVR_GPU_PROFILER_H_

// This file contains classes and macros related to run-time performance
// profiling of GPU processing.

#include <deque>
#include <map>
#include <memory>
#include <stack>
#include <vector>

#include <private/dvr/graphics/vr_gl_extensions.h>

namespace android {
namespace dvr {

// While enabled, GL commands will be submitted each frame to query timestamps
// of GPU workloads that have been traced using the ION_PROFILE_GPU macro
// defined below.
//
// Basic workflow:
//  - have the app framework call PollGlTimerQueries at the start of each frame.
//  - place ION_PROFILE_GPU("MyGlWorkload") at the start of code scopes where
//    GL draw commands are performed that you want to trace.
class GpuProfiler {
 public:
  // Gets the GpuProfiler singleton instance.
  static GpuProfiler* Get();

  GpuProfiler();
  ~GpuProfiler();

  bool IsGpuProfilingSupported() const;

  // Enables runtime GPU tracing. While enabled, GL commands will be submitted
  // each frame to query timestamps of GPU workloads that have been traced using
  // one of the TRACE_GPU* macros defined below.
  void SetEnableGpuTracing(bool enabled) { enable_gpu_tracing_ = enabled; }

  bool enabled() const { return enable_gpu_tracing_ && has_gl_context_; }

  // Attempt to keep the GPU times in sync with CPU times.
  void SetEnableSyncCpuTime(bool enabled) { sync_with_cpu_time_ = enabled; }

  // When sync cpu time is enabled because of mobile GPU timer query issues,
  // it can sometimes help to put a beginning timer query at the start of the
  // frame to sync the CPU time when GPU work begins.
  void QueryFrameBegin();

  // Polls (non-blocking) for completed GL timer query data and adds events into
  // the trace buffer. Must call once close to the start of each frame.
  void PollGlTimerQueries();

  // Call glFinish and process all pending timer queries.
  void FinishGlTimerQueries();

  // Records the beginning of a scoped GL trace event.
  void EnterGlScope(const char* scope_name);

  // Records the end of a scoped GL trace event.
  void LeaveGlScope(const char* scope_name, std::weak_ptr<int64_t> duration_ns,
                    int print_period);

  // Must be called when the GL context is created. The GpuProfiler will be
  // inactive until this is called.
  void OnGlContextCreated();

  // Must be called before the GL context is destroyed. The GpuProfiler will be
  // inactive until a call to OnGlContextCreated().
  void OnGlContextDestroyed();

 private:
  // Data to queue the pending GPU timer queries that need to be polled
  // for completion.
  struct GpuTimerQuery {
    enum QueryType {
      kQueryBeginFrame,
      kQueryBeginScope,
      kQueryEndScope,
    };

    // scope_id is only required for kQueryBeginScope query types.
    GpuTimerQuery(int64_t timestamp_ns, const char* scope_name,
                  std::weak_ptr<int64_t> duration_ns, int print_period,
                  GLuint query_id, QueryType type)
        : timestamp_ns(timestamp_ns),
          scope_name(scope_name),
          duration_ns(duration_ns),
          print_period(print_period),
          query_id(query_id),
          type(type) {}

    int64_t timestamp_ns;
    const char* scope_name;
    std::weak_ptr<int64_t> duration_ns;
    int print_period;
    GLuint query_id;
    QueryType type;
  };

  // Struct that tracks timing data for a particular trace scope.
  struct TimerData {
    void reset();

    // Print the profiling data.
    void print(const char* name) const;

    // Enter a scope, records the timestamp for later matching with leave.
    void enter(int64_t timestamp_ns);

    // Compute the elapsed time for the scope.
    void leave(int64_t timestamp_ns, const char* name,
               std::weak_ptr<int64_t> duration_ns, int print_period);

    bool entered = false;
    int64_t total_elapsed_ns = 0;
    int64_t enter_timestamp_ns = 0;
    int num_events = 0;
  };

  // Clear out events and free GL resources.
  void Clear();

  // Called when we detect that we've overflowed the pending query queue. This
  // shouldn't occur in practice, and probably indicates some internal
  // mismanagement of the gl query objects.
  void OnPendingQueryOverflow();

  // Synchronises the GL timebase with the CallTraceManager timebase.
  void SyncGlTimebase();

  // Returns a GL timer query ID if possible. Otherwise returns 0.
  GLuint TryAllocateGlQueryId();

  // Setting for enabling GPU tracing.
  bool enable_gpu_tracing_;

  // True if we have a GL context, false otherwise. When the GpuProfiler is
  // first created we assume no GL context.
  bool has_gl_context_;

  // Setting for synchronizing GPU timestamps with CPU time.
  bool sync_with_cpu_time_;

  // Nanosecond offset to the GL timebase to compute the CallTraceManager time.
  int64_t gl_timer_offset_ns_;

  std::map<const char*, TimerData> events_;

  // For GPU event TraceRecords, this tracks the pending queries that will
  // be asynchronously polled (in order) and then added to the TraceRecorder
  // buffer with the GPU timestamps.
  std::deque<GpuTimerQuery> pending_gpu_queries_;

  // Available ids for use with GLTimerQuery as needed. This will generally
  // reach a steady state after a few frames. Always push and pop from the back
  // to avoid shifting the vector.
  std::stack<GLuint, std::vector<GLuint> > gl_timer_query_id_pool_;
};

// Traces the GPU start and end times of the GL commands submitted in the
// same scope. Typically used via the TRACE_GPU macro.
class ScopedGlTracer {
 public:
  ScopedGlTracer(const char* name, std::weak_ptr<int64_t> duration_ns,
                 int print_period, bool finish)
      : name_(name),
        duration_ns_(duration_ns),
        print_period_(print_period),
        is_finish_(finish) {
    GpuProfiler* profiler = GpuProfiler::Get();
    if (profiler->enabled()) {
      profiler->EnterGlScope(name);
    }
  }

  ~ScopedGlTracer() {
    GpuProfiler* profiler = GpuProfiler::Get();
    if (profiler->enabled()) {
      profiler->LeaveGlScope(name_, duration_ns_, print_period_);
      if (is_finish_) {
        GpuProfiler::Get()->FinishGlTimerQueries();
      }
    }
  }

 private:
  const char* name_;
  std::weak_ptr<int64_t> duration_ns_;
  int print_period_;
  bool is_finish_;
};

}  // namespace dvr
}  // namespace android

#define PROFILING_PASTE1(x, y) x##y
#define PROFILING_PASTE2(x, y) PROFILING_PASTE1(x, y)
#define PROFILING_PASTE3(x) PROFILING_PASTE2(x, __LINE__)

// This macro can be used in any GL operation scope to trace the resulting
// GPU work. The argument must be a literal string. Specify the number of frames
// to wait before printing an average result in the num_frames_period argument.
#define TRACE_GPU_PRINT(group_name, num_frames_period)        \
  (void)group_name " must be a literal string.";              \
  android::dvr::ScopedGlTracer PROFILING_PASTE3(gpu_tracer_)( \
      group_name, std::weak_ptr<int64_t>(), num_frames_period, false)

// This macro can be used in any GL operation scope to trace the resulting
// GPU work. The argument must be a literal string. The duration parameter
// is a weak_ptr to a int64_t that will receive duration values asynchronously
// during calls to PollGlTimerQueries.
#define TRACE_GPU(group_name, duration_ns_weak_ptr)           \
  (void)group_name " must be a literal string.";              \
  android::dvr::ScopedGlTracer PROFILING_PASTE3(gpu_tracer_)( \
      group_name, duration_ns_weak_ptr, -1, false)

// This macro can be used in any GL operation scope to trace the resulting
// GPU work. The argument must be a literal string. Specify the number of frames
// to wait before printing an average result in the num_frames_period argument.
#define TRACE_GPU_PRINT_FINISH(group_name)                    \
  (void)group_name " must be a literal string.";              \
  android::dvr::ScopedGlTracer PROFILING_PASTE3(gpu_tracer_)( \
      group_name, std::weak_ptr<int64_t>(), 1, true)

// This macro can be used in any GL operation scope to trace the resulting
// GPU work. The argument must be a literal string. The duration parameter
// is a weak_ptr to a int64_t that will receive duration values asynchronously
// during calls to PollGlTimerQueries.
#define TRACE_GPU_FINISH(group_name, duration_ns_weak_ptr)    \
  (void)group_name " must be a literal string.";              \
  android::dvr::ScopedGlTracer PROFILING_PASTE3(gpu_tracer_)( \
      group_name, duration_ns_weak_ptr, -1, true)

#endif  // ANDROID_DVR_GPU_PROFILER_H_
