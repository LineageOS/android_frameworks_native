#ifndef ANDROID_DVR_SENSORD_SENSOR_SERVICE_H_
#define ANDROID_DVR_SENSORD_SENSOR_SERVICE_H_

#include <forward_list>
#include <unordered_map>
#include <vector>

#include <pdx/service.h>
#include <pthread.h>

#include "sensor_thread.h"

namespace android {
namespace dvr {

class SensorClient;

/*
 * SensorService implements the sensor service over ServiceFS.
 * The sensor service provides an interface to one sensor over
 * each channel.
 */
class SensorService : public pdx::ServiceBase<SensorService> {
 public:
  int HandleMessage(pdx::Message& msg) override;
  std::shared_ptr<pdx::Channel> OnChannelOpen(pdx::Message& msg) override;
  void OnChannelClose(pdx::Message& msg,
                      const std::shared_ptr<pdx::Channel>& chan) override;

  // Enqueue the events in [begin_events, end_events) onto any clients that care
  // about them.
  // Safe to call concurrently with any other public member functions.
  void EnqueueEvents(const sensors_event_t* begin_events,
                     const sensors_event_t* end_events);

 private:
  friend BASE;

  // Initializes the service. Keeps a reference to sensor_thread, which must be
  // non-null.
  explicit SensorService(SensorThread* sensor_thread);

  // The abstraction around the sensor HAL.
  SensorThread* sensor_thread_;

  // All of the clients we are connected to. This is the one place in this class
  // where we keep the SensorClient instances alive using shared_ptr instances.
  std::forward_list<std::shared_ptr<SensorClient>> clients_;

  // Map types back to sensor indexes.
  std::unordered_map<int, int> type_to_sensor_;
  // For each sensor, the list of clients that are connected to it.
  // Every entry in here must also be in clients_, so that its reference count
  // remains positive.
  std::vector<std::forward_list<SensorClient*>> sensor_clients_;

  // Protects access to all member variables.
  std::mutex mutex_;

  // None of the following functions is thread-safe; callers must lock mutex_
  // before calling one.
  void AddClient(const std::shared_ptr<SensorClient>& client);
  void RemoveClient(const std::shared_ptr<SensorClient>& client);
  // Dissociate the indicated client from its sensor, if it has one; otherwise
  // do nothing.
  void RemoveSensorClient(SensorClient* client);

  SensorService(const SensorService&) = delete;
  void operator=(const SensorService&) = delete;
};

/*
 * SensorClient manages the service-side per-client context for each client
 * using the service.
 */
class SensorClient : public pdx::Channel {
 public:
  SensorClient(SensorService& /*service*/, int /*pid*/, int /*cid*/)
      : sensor_index_(-1), has_sensor_index_(false) {}

  bool has_sensor() const { return has_sensor_index_; }
  int sensor() const { return sensor_index_; }
  void set_sensor(int sensor) {
    sensor_index_ = sensor;
    has_sensor_index_ = true;
  }
  void unset_sensor() {
    sensor_index_ = -1;
    has_sensor_index_ = false;
  }

  int EventCount() const { return event_queue_.Count(); }

  // Push an event onto our queue.
  void EnqueueEvent(const sensors_event_t& event) { event_queue_.Push(event); }

  // Write all the events in our queue (and clear it) to the supplied
  // buffer. Buffer must be large enough.
  void WriteEvents(sensors_event_t* buffer);

 private:
  SensorClient(const SensorClient&) = delete;
  SensorClient& operator=(const SensorClient&) = delete;

  int sensor_index_ = -1;
  bool has_sensor_index_ = false;
  // Circular queue holds as-yet-unasked-for events for the sensor associated
  // with this client.
  class CircularQ {
   public:
    static const int kCqSize = 10;
    CircularQ() : head_(0), tail_(0), count_(0) {}
    ~CircularQ() {}
    void Push(const sensors_event_t& event);
    const sensors_event_t* Top() const;
    void Pop();
    bool Empty() const { return count_ == 0; }
    int Count() const { return count_; }

   private:
    sensors_event_t events_[kCqSize];
    int head_ = 0;
    int tail_ = 0;
    int count_ = 0;
  };
  CircularQ event_queue_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SENSORD_SENSOR_SERVICE_H_
