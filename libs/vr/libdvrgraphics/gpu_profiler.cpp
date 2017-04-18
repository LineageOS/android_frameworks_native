#include "include/private/dvr/graphics/gpu_profiler.h"

#include <log/log.h>

#include <private/dvr/clock_ns.h>

namespace android {
namespace dvr {

namespace {

constexpr int kMaxPendingQueries = 32;

}  // anonynmous namespace

static int64_t AdjustTimerQueryToNs(int64_t gpu_time) { return gpu_time; }

void GpuProfiler::TimerData::reset() {
  total_elapsed_ns = 0;
  num_events = 0;
}

void GpuProfiler::TimerData::print(const char* name) const {
  ALOGI("GPU_TIME[%s]: %f ms", name,
        (float)((double)total_elapsed_ns / 1000000.0 / (double)num_events));
}

// Enter a scope, records the timestamp for later matching with leave.
void GpuProfiler::TimerData::enter(int64_t timestamp_ns) {
  entered = true;
  enter_timestamp_ns = timestamp_ns;
}

// Compute the elapsed time for the scope.
void GpuProfiler::TimerData::leave(int64_t timestamp_ns, const char* name,
                                   std::weak_ptr<int64_t> duration_ns,
                                   int print_period) {
  if (!entered) {
    // We got the leave event but are missing the enter. This can happen if
    // OnPendingQueryOverflow() is called, or if the calls to enter()/leave()
    // aren't properly balanced. Ignore the call but print a warning.
    ALOGW("Ignoring GpuProfiler::TimerData::leave event with no enter event");
    return;
  }
  entered = false;

  int64_t elapsed = timestamp_ns - enter_timestamp_ns;
  if (elapsed > 1000 * 1000 * 1000) {
    // More than one second, drop it as invalid data.
    return;
  }
  if (auto out_ns = duration_ns.lock()) {
    *out_ns = elapsed;
  }
  total_elapsed_ns += elapsed;
  if (print_period > 0 && ++num_events >= print_period) {
    print(name);
    reset();
  }
}

GpuProfiler* GpuProfiler::Get() {
  static GpuProfiler* profiler = new GpuProfiler();
  return profiler;
}

GpuProfiler::GpuProfiler()
    : enable_gpu_tracing_(true),
      has_gl_context_(false),
      sync_with_cpu_time_(false),
      gl_timer_offset_ns_(0) {
}

GpuProfiler::~GpuProfiler() { Clear(); }

bool GpuProfiler::IsGpuProfilingSupported() const {
  // TODO(jbates) check for GL_EXT_disjoint_timer_query
  return true;
}

GLuint GpuProfiler::TryAllocateGlQueryId() {
  if (pending_gpu_queries_.size() >= kMaxPendingQueries)
    OnPendingQueryOverflow();

  GLuint query_id = 0;
  if (gl_timer_query_id_pool_.empty()) {
    glGenQueries(1, &query_id);
  } else {
    query_id = gl_timer_query_id_pool_.top();
    gl_timer_query_id_pool_.pop();
  }
  return query_id;
}

void GpuProfiler::EnterGlScope(const char* scope_name) {
  GLuint query_id = TryAllocateGlQueryId();
  if (query_id != 0) {
    glQueryCounter(query_id, GL_TIMESTAMP_EXT);
    pending_gpu_queries_.push_back(
        GpuTimerQuery(GetSystemClockNs(), scope_name, std::weak_ptr<int64_t>(),
                      -1, query_id, GpuTimerQuery::kQueryBeginScope));
  }
}

void GpuProfiler::LeaveGlScope(const char* scope_name,
                               std::weak_ptr<int64_t> duration_ns,
                               int print_period) {
  GLuint query_id = TryAllocateGlQueryId();
  if (query_id != 0) {
    glQueryCounter(query_id, GL_TIMESTAMP_EXT);
    pending_gpu_queries_.push_back(
        GpuTimerQuery(GetSystemClockNs(), scope_name, duration_ns, print_period,
                      query_id, GpuTimerQuery::kQueryEndScope));
  }
}

void GpuProfiler::OnGlContextCreated() {
  has_gl_context_ = true;
  gl_timer_offset_ns_ = 0;
  SyncGlTimebase();
}

void GpuProfiler::OnGlContextDestroyed() {
  has_gl_context_ = false;
  Clear();
}

void GpuProfiler::Clear() {
  events_.clear();
  for (auto& query : pending_gpu_queries_)
    glDeleteQueries(1, &query.query_id);
  pending_gpu_queries_.clear();
  while (!gl_timer_query_id_pool_.empty()) {
    GLuint id = gl_timer_query_id_pool_.top();
    gl_timer_query_id_pool_.pop();
    glDeleteQueries(1, &id);
  }
}

void GpuProfiler::OnPendingQueryOverflow() {
  ALOGW("Reached limit of %d pending queries in GpuProfiler."
        " Clearing all queries.", kMaxPendingQueries);
  Clear();
}

void GpuProfiler::SyncGlTimebase() {
  if (!sync_with_cpu_time_) {
    return;
  }

  // Clear disjoint error status.
  // This error status indicates that we need to ignore the result of the
  // timer query because of some kind of disjoint GPU event such as heat
  // throttling.
  GLint disjoint = 0;
  glGetIntegerv(GL_GPU_DISJOINT_EXT, &disjoint);

  // Try to get the current GL timestamp. Since the GPU can supposedly fail to
  // produce a timestamp occasionally we try a few times before giving up.
  int attempts_remaining = 3;
  do {
    GLint64 gl_timestamp = 0;
    glGetInteger64v(GL_TIMESTAMP_EXT, &gl_timestamp);
    gl_timestamp = AdjustTimerQueryToNs(gl_timestamp);

    // Now get the CPU timebase.
    int64_t cpu_timebase_ns = static_cast<int64_t>(GetSystemClockNs());

    disjoint = 0;
    glGetIntegerv(GL_GPU_DISJOINT_EXT, &disjoint);
    if (!disjoint) {
      gl_timer_offset_ns_ = cpu_timebase_ns - gl_timestamp;
      break;
    }
    ALOGW("WARNING: Skipping disjoint GPU timestamp");
  } while (--attempts_remaining > 0);

  if (attempts_remaining == 0) {
    ALOGE("ERROR: Failed to sync GL timebase due to disjoint results\n");
    gl_timer_offset_ns_ = 0;
  }
}

void GpuProfiler::QueryFrameBegin() {
  GLuint begin_frame_id = TryAllocateGlQueryId();
  if (begin_frame_id != 0) {
    glQueryCounter(begin_frame_id, GL_TIMESTAMP_EXT);
    pending_gpu_queries_.push_back(
        GpuTimerQuery(GetSystemClockNs(), 0, std::weak_ptr<int64_t>(), -1,
                      begin_frame_id, GpuTimerQuery::kQueryBeginFrame));
  }
}

void GpuProfiler::PollGlTimerQueries() {
  if (!enabled()) {
    return;
  }

#ifdef ENABLE_DISJOINT_TIMER_IGNORING
  bool has_checked_disjoint = false;
  bool was_disjoint = false;
#endif
  for (;;) {
    if (pending_gpu_queries_.empty()) {
      // No queries pending.
      return;
    }

    GpuTimerQuery query = pending_gpu_queries_.front();

    GLint available = 0;
    glGetQueryObjectiv(query.query_id, GL_QUERY_RESULT_AVAILABLE_EXT,
                       &available);
    if (!available) {
      // No queries available.
      return;
    }

    // Found an available query, remove it from pending queue.
    pending_gpu_queries_.pop_front();
    gl_timer_query_id_pool_.push(query.query_id);

#ifdef ENABLE_DISJOINT_TIMER_IGNORING
    if (!has_checked_disjoint) {
      // Check if we need to ignore the result of the timer query because
      // of some kind of disjoint GPU event such as heat throttling.
      // If so, we ignore all events that are available during this loop.
      has_checked_disjoint = true;
      GLint disjoint_occurred = 0;
      glGetIntegerv(GL_GPU_DISJOINT_EXT, &disjoint_occurred);
      was_disjoint = !!disjoint_occurred;
      if (was_disjoint) {
        ALOGW("Skipping disjoint GPU events");
      }
    }

    if (was_disjoint) {
      continue;
    }
#endif

    GLint64 timestamp_ns = 0;
    glGetQueryObjecti64v(query.query_id, GL_QUERY_RESULT_EXT, &timestamp_ns);
    timestamp_ns = AdjustTimerQueryToNs(timestamp_ns);

    int64_t adjusted_timestamp_ns;

    if (sync_with_cpu_time_) {
      adjusted_timestamp_ns = timestamp_ns + gl_timer_offset_ns_;

      if (query.type == GpuTimerQuery::kQueryBeginFrame ||
          query.type == GpuTimerQuery::kQueryBeginScope) {
        if (adjusted_timestamp_ns < query.timestamp_ns) {
          // GPU clock is behind, adjust our offset to correct it.
          gl_timer_offset_ns_ += query.timestamp_ns - adjusted_timestamp_ns;
          adjusted_timestamp_ns = query.timestamp_ns;
        }
      }
    } else {
      adjusted_timestamp_ns = timestamp_ns;
    }

    switch (query.type) {
      case GpuTimerQuery::kQueryBeginFrame:
        break;
      case GpuTimerQuery::kQueryBeginScope:
        events_[query.scope_name].enter(adjusted_timestamp_ns);
        break;
      case GpuTimerQuery::kQueryEndScope:
        events_[query.scope_name].leave(adjusted_timestamp_ns, query.scope_name,
                                        query.duration_ns, query.print_period);
        break;
    }
  }
}

void GpuProfiler::FinishGlTimerQueries() {
  if (!enabled()) {
    return;
  }

  glFlush();
  PollGlTimerQueries();
  int max_iterations = 100;
  while (!pending_gpu_queries_.empty()) {
    if (--max_iterations <= 0) {
      ALOGE("Error: GL timer queries failed to finish.");
      break;
    }
    PollGlTimerQueries();
    usleep(1000);
  }
}

}  // namespace dvr
}  // namespace android
