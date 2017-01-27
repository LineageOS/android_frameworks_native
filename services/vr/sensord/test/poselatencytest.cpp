#include <dvr/pose_client.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <vector>

// Creates a pose client and polls 30x for new data. Prints timestamp and
// latency.  Latency is calculated based on the difference between the
// current clock and the timestamp from the Myriad, which has been synced
// to QC time. Note that there is some clock drift and clocks are only sycned
// when the FW is loaded.
int main(int /*argc*/, char** /*argv*/) {
  DvrPose* pose_client = dvrPoseCreate();
  if (pose_client == nullptr) {
    printf("Unable to create pose client\n");
    return -1;
  }

  DvrPoseAsync last_state;
  DvrPoseAsync current_state;
  last_state.timestamp_ns = 0;
  current_state.timestamp_ns = 0;

  double avg_latency = 0;
  double min_latency = (float)UINT64_MAX;
  double max_latency = 0;
  double std = 0;
  std::vector<uint64_t> latency;

  int num_samples = 100;
  for (int i = 0; i < num_samples; ++i) {
    while (last_state.timestamp_ns == current_state.timestamp_ns) {
      uint32_t vsync_count = dvrPoseGetVsyncCount(pose_client);
      int err = dvrPoseGet(pose_client, vsync_count, &current_state);
      if (err) {
        printf("Error polling pose: %d\n", err);
        dvrPoseDestroy(pose_client);
        return err;
      }
    }
    struct timespec timespec;
    uint64_t timestamp, diff;
    clock_gettime(CLOCK_MONOTONIC, &timespec);
    timestamp =
        ((uint64_t)timespec.tv_sec * 1000000000) + (uint64_t)timespec.tv_nsec;
    if (timestamp < current_state.timestamp_ns) {
      printf("ERROR: excessive clock drift detected, reload FW to resync\n");
      return -1;
    }
    diff = timestamp - current_state.timestamp_ns;
    printf("%02d) ts = %" PRIu64 " time = %" PRIu64 "\n", i + 1,
           current_state.timestamp_ns, timestamp);
    printf("\tlatency: %" PRIu64 " ns (%" PRIu64 " us) (%" PRIu64 " ms)\n",
           diff, diff / 1000, diff / 1000000);

    avg_latency += diff;
    if (diff < min_latency) {
      min_latency = diff;
    }
    if (diff > max_latency) {
      max_latency = diff;
    }
    latency.push_back(diff);

    last_state = current_state;
  }
  avg_latency /= num_samples;
  for (unsigned int i = 0; i < latency.size(); i++) {
    std += pow(latency[i] - avg_latency, 2);
  }
  std /= latency.size();
  std = sqrt(std);

  printf("\n************************\n");
  printf("Avg latency =  %lf ns (%lf us) (%lf ms)\n", avg_latency,
         avg_latency / 1000, avg_latency / 1000000);
  printf("Max latency =  %lf ns (%lf us) (%lf ms)\n", max_latency,
         max_latency / 1000, max_latency / 1000000);
  printf("Min latency =  %lf ns (%lf us) (%lf ms)\n", min_latency,
         min_latency / 1000, min_latency / 1000000);
  printf("Standard dev = %lf ns (%lf us) (%lf ms)\n", std, std / 1000,
         std / 1000000);
  printf("\n************************\n");
  return 0;
}
