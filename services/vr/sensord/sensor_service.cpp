#include "sensor_service.h"

#include <hardware/sensors.h>
#include <log/log.h>
#include <pdx/default_transport/service_endpoint.h>
#include <poll.h>
#include <private/dvr/sensor-ipc.h>
#include <time.h>

using android::pdx::default_transport::Endpoint;

namespace android {
namespace dvr {

SensorService::SensorService(SensorThread* sensor_thread)
    : BASE("SensorService", Endpoint::Create(DVR_SENSOR_SERVICE_CLIENT)),
      sensor_thread_(sensor_thread) {
  sensor_clients_.resize(sensor_thread_->GetSensorCount());

  for (int i = 0; i < sensor_thread_->GetSensorCount(); ++i)
    type_to_sensor_[sensor_thread_->GetSensorType(i)] = i;
}

std::shared_ptr<pdx::Channel> SensorService::OnChannelOpen(pdx::Message& msg) {
  std::lock_guard<std::mutex> guard(mutex_);

  const pdx::MessageInfo& info = msg.GetInfo();

  std::shared_ptr<SensorClient> client(
      new SensorClient(*this, info.pid, info.cid));
  AddClient(client);
  return client;
}

void SensorService::OnChannelClose(pdx::Message& /*msg*/,
                                   const std::shared_ptr<pdx::Channel>& chan) {
  std::lock_guard<std::mutex> guard(mutex_);

  auto client = std::static_pointer_cast<SensorClient>(chan);
  if (!client) {
    ALOGW("WARNING: SensorClient was NULL!\n");
    return;
  }
  RemoveClient(client);
}

void SensorService::AddClient(const std::shared_ptr<SensorClient>& client) {
  clients_.push_front(client);
}

void SensorService::RemoveClient(const std::shared_ptr<SensorClient>& client) {
  // First remove it from the clients associated with its sensor, if any.
  RemoveSensorClient(client.get());

  // Finally, remove it from the list of clients we're aware of, and decrease
  // its reference count.
  clients_.remove(client);
}

void SensorService::RemoveSensorClient(SensorClient* client) {
  if (!client->has_sensor())
    return;

  std::forward_list<SensorClient*>& sensor_clients =
      sensor_clients_[client->sensor()];
  sensor_clients.remove(client);
  sensor_thread_->StopUsingSensor(client->sensor());

  client->unset_sensor();
}

int SensorService::HandleMessage(pdx::Message& msg) {
  int ret = 0;
  const pdx::MessageInfo& info = msg.GetInfo();
  switch (info.op) {
    case DVR_SENSOR_START: {
      std::lock_guard<std::mutex> guard(mutex_);
      // Associate this channel with the indicated sensor,
      // unless it already has an association. In that case,
      // fail.
      auto client = std::static_pointer_cast<SensorClient>(msg.GetChannel());
      if (client->has_sensor())
        REPLY_ERROR(msg, EINVAL, error);
      int sensor_type;
      if (msg.Read(&sensor_type, sizeof(sensor_type)) <
          (ssize_t)sizeof(sensor_type))
        REPLY_ERROR(msg, EIO, error);

      // Find the sensor of the requested type.
      if (type_to_sensor_.find(sensor_type) == type_to_sensor_.end())
        REPLY_ERROR(msg, EINVAL, error);
      const int sensor_index = type_to_sensor_[sensor_type];

      sensor_clients_[sensor_index].push_front(client.get());
      client->set_sensor(sensor_index);
      sensor_thread_->StartUsingSensor(sensor_index);

      REPLY_SUCCESS(msg, 0, error);
    }
    case DVR_SENSOR_STOP: {
      std::lock_guard<std::mutex> guard(mutex_);
      auto client = std::static_pointer_cast<SensorClient>(msg.GetChannel());
      if (!client->has_sensor())
        REPLY_ERROR(msg, EINVAL, error);
      RemoveSensorClient(client.get());
      REPLY_SUCCESS(msg, 0, error);
    }
    case DVR_SENSOR_POLL: {
      std::lock_guard<std::mutex> guard(mutex_);
      auto client = std::static_pointer_cast<SensorClient>(msg.GetChannel());

      // Package up the events we've got for this client. Number of
      // events, followed by 0 or more sensor events, popped from
      // this client's queue until it's empty.
      int num_events = client->EventCount();
      sensors_event_t out_buffer[num_events];
      client->WriteEvents(out_buffer);
      struct iovec svec[] = {
          {.iov_base = &num_events, .iov_len = sizeof(num_events)},
          {.iov_base = out_buffer,
           .iov_len = num_events * sizeof(sensors_event_t)},
      };
      ret = msg.WriteVector(svec, 2);
      int expected_size = sizeof(int) + num_events * sizeof(sensors_event_t);
      if (ret < expected_size) {
        ALOGI("error: msg.WriteVector wrote too little.");
        REPLY_ERROR(msg, EIO, error);
      }
      REPLY_SUCCESS(msg, 0, error);
    }
    default:
      // Do not lock mutex_ here, because this may call the on*() handlers,
      // which will lock the mutex themselves.
      ret = Service::HandleMessage(msg);
      break;
  }
error:
  return ret;
}

void SensorService::EnqueueEvents(const sensors_event_t* begin_events,
                                  const sensors_event_t* end_events) {
  std::lock_guard<std::mutex> guard(mutex_);

  // Put the sensor values we got in the circular queue for each client that
  // cares about the given event.
  for (const sensors_event_t* event = begin_events; event != end_events;
       ++event) {
    const int sensor_index = type_to_sensor_[event->type];
    for (const auto& client : sensor_clients_[sensor_index]) {
      client->EnqueueEvent(*event);
    }
  }
}

void SensorClient::WriteEvents(sensors_event_t* buffer) {
  while (!event_queue_.Empty()) {
    *buffer = *(event_queue_.Top());
    event_queue_.Pop();
    ++buffer;
  }
}

void SensorClient::CircularQ::Push(const sensors_event_t& event) {
  if (count_ != 0 && head_ == tail_) {
    Pop();  // If we're full, throw away the oldest event.
  }
  events_[head_] = event;
  head_ = (head_ + 1) % kCqSize;
  ++count_;
}

const sensors_event_t* SensorClient::CircularQ::Top() const {
  if (count_ == 0)
    return nullptr;
  return &events_[tail_];
}

void SensorClient::CircularQ::Pop() {
  if (count_ == 0)
    return;
  tail_ = (tail_ + 1) % kCqSize;
  --count_;
}

}  // namespace dvr
}  // namespace android
