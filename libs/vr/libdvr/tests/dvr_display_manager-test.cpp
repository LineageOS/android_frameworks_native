#include <base/logging.h>
#include <gtest/gtest.h>
#include <poll.h>

#include <android/hardware_buffer.h>

#include <algorithm>
#include <set>
#include <thread>
#include <vector>

#include <dvr/dvr_deleter.h>
#include <dvr/dvr_display_manager.h>
#include <dvr/dvr_surface.h>

#include <pdx/status.h>

using android::pdx::ErrorStatus;
using android::pdx::Status;

namespace android {
namespace dvr {

namespace {

DvrSurfaceAttribute GetAttribute(DvrSurfaceAttributeKey key, bool value) {
  DvrSurfaceAttribute attribute;
  attribute.key = key;
  attribute.value.type = DVR_SURFACE_ATTRIBUTE_TYPE_BOOL;
  attribute.value.bool_value = value;
  return attribute;
}

DvrSurfaceAttribute GetAttribute(DvrSurfaceAttributeKey key, int32_t value) {
  DvrSurfaceAttribute attribute;
  attribute.key = key;
  attribute.value.type = DVR_SURFACE_ATTRIBUTE_TYPE_INT32;
  attribute.value.bool_value = value;
  return attribute;
}

Status<UniqueDvrSurface> CreateApplicationSurface(bool visible = false,
                                                  int32_t z_order = 0) {
  DvrSurface* surface = nullptr;
  DvrSurfaceAttribute attributes[] = {
      GetAttribute(DVR_SURFACE_ATTRIBUTE_Z_ORDER, z_order),
      GetAttribute(DVR_SURFACE_ATTRIBUTE_VISIBLE, visible)};

  const int ret = dvrSurfaceCreate(
      attributes, std::extent<decltype(attributes)>::value, &surface);
  if (ret < 0)
    return ErrorStatus(-ret);
  else
    return {UniqueDvrSurface(surface)};
}

Status<UniqueDvrWriteBufferQueue> CreateSurfaceQueue(
    const UniqueDvrSurface& surface, uint32_t width, uint32_t height,
    uint32_t format, uint32_t layer_count, uint64_t usage, size_t capacity) {
  DvrWriteBufferQueue* queue;
  const int ret =
      dvrSurfaceCreateWriteBufferQueue(surface.get(), width, height, format,
                                       layer_count, usage, capacity, &queue);
  if (ret < 0)
    return ErrorStatus(-ret);
  else
    return {UniqueDvrWriteBufferQueue(queue)};
}

class TestDisplayManager {
 public:
  TestDisplayManager(UniqueDvrDisplayManager display_manager,
                     UniqueDvrSurfaceState surface_state)
      : display_manager_(std::move(display_manager)),
        surface_state_(std::move(surface_state)) {
    const int fd = dvrDisplayManagerGetEventFd(display_manager_.get());
    LOG_IF(INFO, fd < 0) << "Failed to get event fd: " << strerror(-fd);
    display_manager_event_fd_ = fd;
  }

  Status<UniqueDvrReadBufferQueue> GetReadBufferQueue(int surface_id,
                                                      int queue_id) {
    DvrReadBufferQueue* queue;
    const int ret = dvrDisplayManagerGetReadBufferQueue(
        display_manager_.get(), surface_id, queue_id, &queue);
    if (ret < 0)
      return ErrorStatus(-ret);
    else
      return {UniqueDvrReadBufferQueue(queue)};
  }

  Status<void> UpdateSurfaceState() {
    const int ret = dvrDisplayManagerGetSurfaceState(display_manager_.get(),
                                                     surface_state_.get());
    if (ret < 0)
      return ErrorStatus(-ret);
    else
      return {};
  }

  Status<void> WaitForUpdate() {
    if (display_manager_event_fd_ < 0)
      return ErrorStatus(-display_manager_event_fd_);

    const int kTimeoutMs = 10000;  // 10s
    pollfd pfd = {display_manager_event_fd_, POLLIN, 0};
    const int count = poll(&pfd, 1, kTimeoutMs);
    if (count < 0)
      return ErrorStatus(errno);
    else if (count == 0)
      return ErrorStatus(ETIMEDOUT);

    int events;
    const int ret = dvrDisplayManagerTranslateEpollEventMask(
        display_manager_.get(), pfd.revents, &events);
    if (ret < 0)
      return ErrorStatus(-ret);
    else if (events & POLLIN)
      return UpdateSurfaceState();
    else
      return ErrorStatus(EPROTO);
  }

  Status<size_t> GetSurfaceCount() {
    size_t count = 0;
    const int ret =
        dvrSurfaceStateGetSurfaceCount(surface_state_.get(), &count);
    if (ret < 0)
      return ErrorStatus(-ret);
    else
      return {count};
  }

  Status<DvrSurfaceUpdateFlags> GetUpdateFlags(size_t surface_index) {
    DvrSurfaceUpdateFlags update_flags;
    const int ret = dvrSurfaceStateGetUpdateFlags(surface_state_.get(),
                                                  surface_index, &update_flags);
    if (ret < 0)
      return ErrorStatus(-ret);
    else
      return {update_flags};
  }

  Status<int> GetSurfaceId(size_t surface_index) {
    int surface_id;
    const int ret = dvrSurfaceStateGetSurfaceId(surface_state_.get(),
                                                surface_index, &surface_id);
    if (ret < 0)
      return ErrorStatus(-ret);
    else
      return {surface_id};
  }

  Status<int> GetProcessId(size_t surface_index) {
    int process_id;
    const int ret = dvrSurfaceStateGetProcessId(surface_state_.get(),
                                                surface_index, &process_id);
    if (ret < 0)
      return ErrorStatus(-ret);
    else
      return {process_id};
  }

  Status<std::vector<DvrSurfaceAttribute>> GetAttributes(size_t surface_index) {
    std::vector<DvrSurfaceAttribute> attributes;
    size_t count = 0;
    const int ret = dvrSurfaceStateGetAttributeCount(surface_state_.get(),
                                                     surface_index, &count);
    if (ret < 0)
      return ErrorStatus(-ret);

    attributes.resize(count);
    const ssize_t return_count = dvrSurfaceStateGetAttributes(
        surface_state_.get(), surface_index, attributes.data(), count);
    if (return_count < 0)
      return ErrorStatus(-return_count);

    attributes.resize(return_count);
    return {std::move(attributes)};
  }

  Status<std::vector<int>> GetQueueIds(size_t surface_index) {
    std::vector<int> queue_ids;
    size_t count = 0;
    const int ret = dvrSurfaceStateGetQueueCount(surface_state_.get(),
                                                 surface_index, &count);
    if (ret < 0)
      return ErrorStatus(-ret);

    if (count > 0) {
      queue_ids.resize(count);
      const ssize_t return_count = dvrSurfaceStateGetQueueIds(
          surface_state_.get(), surface_index, queue_ids.data(), count);
      if (return_count < 0)
        return ErrorStatus(-return_count);

      queue_ids.resize(return_count);
    }

    return {std::move(queue_ids)};
  }

 private:
  UniqueDvrDisplayManager display_manager_;
  UniqueDvrSurfaceState surface_state_;

  // Owned by object in display_manager_, do not explicitly close.
  int display_manager_event_fd_;

  TestDisplayManager(const TestDisplayManager&) = delete;
  void operator=(const TestDisplayManager&) = delete;
};

class DvrDisplayManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    int ret;
    DvrDisplayManager* display_manager;
    DvrSurfaceState* surface_state;

    ret = dvrDisplayManagerCreate(&display_manager);
    ASSERT_EQ(0, ret) << "Failed to create display manager client";
    ASSERT_NE(nullptr, display_manager);

    ret = dvrSurfaceStateCreate(&surface_state);
    ASSERT_EQ(0, ret) << "Failed to create surface state object";
    ASSERT_NE(nullptr, surface_state);

    manager_.reset(
        new TestDisplayManager(UniqueDvrDisplayManager(display_manager),
                               UniqueDvrSurfaceState(surface_state)));
  }
  void TearDown() override {}

  std::unique_ptr<TestDisplayManager> manager_;
};

// TODO(eieio): Consider moving these somewhere more central because they are
// broadly useful.

template <typename T>
testing::AssertionResult StatusOk(const char* status_expression,
                                  const Status<T>& status) {
  if (!status.ok()) {
    return testing::AssertionFailure()
           << "(" << status_expression
           << ") expected to indicate success but actually contains error ("
           << status.error() << ")";
  } else {
    return testing::AssertionSuccess();
  }
}

template <typename T>
testing::AssertionResult StatusError(const char* status_expression,
                                     const Status<T>& status) {
  if (status.ok()) {
    return testing::AssertionFailure()
           << "(" << status_expression
           << ") expected to indicate error but instead indicates success.";
  } else {
    return testing::AssertionSuccess();
  }
}

template <typename T>
testing::AssertionResult StatusHasError(const char* status_expression,
                                        const char* /*error_code_expression*/,
                                        const Status<T>& status,
                                        int error_code) {
  if (status.ok()) {
    return StatusError(status_expression, status);
  } else if (status.error() != error_code) {
    return testing::AssertionFailure()
           << "(" << status_expression << ") expected to indicate error ("
           << error_code << ") but actually indicates error (" << status.error()
           << ")";
  } else {
    return testing::AssertionSuccess();
  }
}

template <typename T, typename U>
testing::AssertionResult StatusHasValue(const char* status_expression,
                                        const char* /*value_expression*/,
                                        const Status<T>& status,
                                        const U& value) {
  if (!status.ok()) {
    return StatusOk(status_expression, status);
  } else if (status.get() != value) {
    return testing::AssertionFailure()
           << "(" << status_expression << ") expected to contain value ("
           << testing::PrintToString(value) << ") but actually contains value ("
           << testing::PrintToString(status.get()) << ")";
  } else {
    return testing::AssertionSuccess();
  }
}

template <typename T, typename Op>
testing::AssertionResult StatusPred(const char* status_expression,
                                    const char* pred_expression,
                                    const Status<T>& status, Op pred) {
  if (!status.ok()) {
    return StatusOk(status_expression, status);
  } else if (!pred(status.get())) {
    return testing::AssertionFailure()
           << status_expression << " value ("
           << testing::PrintToString(status.get())
           << ") failed to pass predicate " << pred_expression;
  } else {
    return testing::AssertionSuccess();
  }
}

#define ASSERT_STATUS_OK(status) ASSERT_PRED_FORMAT1(StatusOk, status)
#define ASSERT_STATUS_ERROR(status) ASSERT_PRED_FORMAT1(StatusError, status)

#define ASSERT_STATUS_ERROR_VALUE(value, status) \
  ASSERT_PRED_FORMAT2(StatusHasError, status, value)

#define ASSERT_STATUS_EQ(value, status) \
  ASSERT_PRED_FORMAT2(StatusHasValue, status, value)

#define EXPECT_STATUS_OK(status) EXPECT_PRED_FORMAT1(StatusOk, status)
#define EXPECT_STATUS_ERROR(status) EXPECT_PRED_FORMAT1(StatusError, status)

#define EXPECT_STATUS_ERROR_VALUE(value, status) \
  EXPECT_PRED_FORMAT2(StatusHasError, status, value)

#define EXPECT_STATUS_EQ(value, status) \
  EXPECT_PRED_FORMAT2(StatusHasValue, status, value)

#define EXPECT_STATUS_PRED(pred, status) \
  EXPECT_PRED_FORMAT2(StatusPred, status, pred)

#if 0
// Verify utility predicate/macro functionality. This section is commented out
// because it is designed to fail in some cases to validate the helpers.
TEST_F(DvrDisplayManagerTest, ExpectVoid) {
  Status<void> status_error{ErrorStatus{EINVAL}};
  Status<void> status_ok{};

  EXPECT_STATUS_ERROR(status_error);
  EXPECT_STATUS_ERROR(status_ok);
  EXPECT_STATUS_OK(status_error);
  EXPECT_STATUS_OK(status_ok);

  EXPECT_STATUS_ERROR_VALUE(EINVAL, status_error);
  EXPECT_STATUS_ERROR_VALUE(ENOMEM, status_error);
  EXPECT_STATUS_ERROR_VALUE(EINVAL, status_ok);
  EXPECT_STATUS_ERROR_VALUE(ENOMEM, status_ok);
}

TEST_F(DvrDisplayManagerTest, ExpectInt) {
  Status<int> status_error{ErrorStatus{EINVAL}};
  Status<int> status_ok{10};

  EXPECT_STATUS_ERROR(status_error);
  EXPECT_STATUS_ERROR(status_ok);
  EXPECT_STATUS_OK(status_error);
  EXPECT_STATUS_OK(status_ok);

  EXPECT_STATUS_ERROR_VALUE(EINVAL, status_error);
  EXPECT_STATUS_ERROR_VALUE(ENOMEM, status_error);
  EXPECT_STATUS_ERROR_VALUE(EINVAL, status_ok);
  EXPECT_STATUS_ERROR_VALUE(ENOMEM, status_ok);

  EXPECT_STATUS_EQ(10, status_error);
  EXPECT_STATUS_EQ(20, status_error);
  EXPECT_STATUS_EQ(10, status_ok);
  EXPECT_STATUS_EQ(20, status_ok);

  auto pred1 = [](const auto& value) { return value < 15; };
  auto pred2 = [](const auto& value) { return value > 5; };
  auto pred3 = [](const auto& value) { return value > 15; };
  auto pred4 = [](const auto& value) { return value < 5; };

  EXPECT_STATUS_PRED(pred1, status_error);
  EXPECT_STATUS_PRED(pred2, status_error);
  EXPECT_STATUS_PRED(pred3, status_error);
  EXPECT_STATUS_PRED(pred4, status_error);
  EXPECT_STATUS_PRED(pred1, status_ok);
  EXPECT_STATUS_PRED(pred2, status_ok);
  EXPECT_STATUS_PRED(pred3, status_ok);
  EXPECT_STATUS_PRED(pred4, status_ok);
}
#endif

TEST_F(DvrDisplayManagerTest, SurfaceCreateEvent) {
  // Get surface state and verify there are no surfaces.
  ASSERT_STATUS_OK(manager_->UpdateSurfaceState());
  ASSERT_STATUS_EQ(0u, manager_->GetSurfaceCount());

  // Get flags for invalid surface index.
  EXPECT_STATUS_ERROR_VALUE(EINVAL, manager_->GetUpdateFlags(0));

  // Create an application surface.
  auto surface_status = CreateApplicationSurface();
  ASSERT_STATUS_OK(surface_status);
  UniqueDvrSurface surface = surface_status.take();
  ASSERT_NE(nullptr, surface.get());

  const int surface_id = dvrSurfaceGetId(surface.get());
  ASSERT_GE(surface_id, 0);

  // Now there should be one new surface.
  ASSERT_STATUS_OK(manager_->WaitForUpdate());
  EXPECT_STATUS_EQ(1u, manager_->GetSurfaceCount());

  // Verify the new surface flag is set.
  auto check_flags = [](const auto& value) {
    return value & DVR_SURFACE_UPDATE_FLAGS_NEW_SURFACE;
  };
  EXPECT_STATUS_PRED(check_flags, manager_->GetUpdateFlags(0));

  // Verify the surface id matches.
  EXPECT_STATUS_EQ(surface_id, manager_->GetSurfaceId(0));

  // Verify the owning process of the surface.
  EXPECT_STATUS_EQ(getpid(), manager_->GetProcessId(0));

  surface.reset();

  ASSERT_STATUS_OK(manager_->WaitForUpdate());
  EXPECT_STATUS_EQ(0u, manager_->GetSurfaceCount());
}

TEST_F(DvrDisplayManagerTest, SurfaceAttributeEvent) {
  // Get surface state and verify there are no surfaces.
  ASSERT_STATUS_OK(manager_->UpdateSurfaceState());
  ASSERT_STATUS_EQ(0u, manager_->GetSurfaceCount());

  // Get attributes for an invalid surface index.
  EXPECT_STATUS_ERROR_VALUE(EINVAL, manager_->GetAttributes(0));

  const bool kInitialVisibility = true;
  const int32_t kInitialZOrder = 10;
  auto surface_status =
      CreateApplicationSurface(kInitialVisibility, kInitialZOrder);
  ASSERT_STATUS_OK(surface_status);
  auto surface = surface_status.take();
  ASSERT_NE(nullptr, surface.get());

  ASSERT_STATUS_OK(manager_->WaitForUpdate());
  ASSERT_STATUS_EQ(1u, manager_->GetSurfaceCount());

  // Check the initial attribute values.
  auto attribute_status = manager_->GetAttributes(0);
  ASSERT_STATUS_OK(attribute_status);
  auto attributes = attribute_status.take();
  EXPECT_GE(attributes.size(), 2u);

  const std::set<int32_t> expected_keys = {DVR_SURFACE_ATTRIBUTE_Z_ORDER,
                                           DVR_SURFACE_ATTRIBUTE_VISIBLE};

  // Collect all the keys in attributes that match the expected keys.
  std::set<int32_t> actual_keys;
  std::for_each(attributes.begin(), attributes.end(),
                [&expected_keys, &actual_keys](const auto& attribute) {
                  if (expected_keys.find(attribute.key) != expected_keys.end())
                    actual_keys.emplace(attribute.key);
                });

  // If the sets match then attributes contained at least the expected keys,
  // even if other keys were also present.
  EXPECT_EQ(expected_keys, actual_keys);
}

TEST_F(DvrDisplayManagerTest, SurfaceQueueEvent) {
  // Create an application surface.
  auto surface_status = CreateApplicationSurface();
  ASSERT_STATUS_OK(surface_status);
  UniqueDvrSurface surface = surface_status.take();
  ASSERT_NE(nullptr, surface.get());

  const int surface_id = dvrSurfaceGetId(surface.get());
  ASSERT_GE(surface_id, 0);
  // Get surface state and verify there is one surface.
  ASSERT_STATUS_OK(manager_->WaitForUpdate());
  ASSERT_STATUS_EQ(1u, manager_->GetSurfaceCount());

  // Verify there are no queues for the surface recorded in the state snapshot.
  EXPECT_STATUS_EQ(std::vector<int>{}, manager_->GetQueueIds(0));

  // Create a new queue in the surface.
  auto write_queue_status = CreateSurfaceQueue(
      surface, 320, 240, AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM, 1,
      AHARDWAREBUFFER_USAGE_CPU_READ_RARELY, 1);
  ASSERT_STATUS_OK(write_queue_status);
  UniqueDvrWriteBufferQueue write_queue = write_queue_status.take();
  ASSERT_NE(nullptr, write_queue.get());

  const int queue_id = dvrWriteBufferQueueGetId(write_queue.get());
  ASSERT_GE(queue_id, 0);

  // Update surface state.
  ASSERT_STATUS_OK(manager_->WaitForUpdate());
  ASSERT_STATUS_EQ(1u, manager_->GetSurfaceCount());

  // Verify the buffers changed flag is set.
  auto check_flags = [](const auto& value) {
    return value & DVR_SURFACE_UPDATE_FLAGS_BUFFERS_CHANGED;
  };
  EXPECT_STATUS_PRED(check_flags, manager_->GetUpdateFlags(0));

  auto queue_ids_status = manager_->GetQueueIds(0);
  ASSERT_STATUS_OK(queue_ids_status);

  auto queue_ids = queue_ids_status.take();
  ASSERT_EQ(1u, queue_ids.size());
  EXPECT_EQ(queue_id, queue_ids[0]);

  auto read_queue_status = manager_->GetReadBufferQueue(surface_id, queue_id);
  ASSERT_STATUS_OK(read_queue_status);
  UniqueDvrReadBufferQueue read_queue = read_queue_status.take();
  ASSERT_NE(nullptr, read_queue.get());
  EXPECT_EQ(queue_id, dvrReadBufferQueueGetId(read_queue.get()));

  write_queue.reset();

  // Verify that destroying the queue generates a surface update event.
  ASSERT_STATUS_OK(manager_->WaitForUpdate());
  ASSERT_STATUS_EQ(1u, manager_->GetSurfaceCount());

  // Verify that the buffers changed flag is set.
  EXPECT_STATUS_PRED(check_flags, manager_->GetUpdateFlags(0));

  // Verify that the queue ids reflect the change.
  queue_ids_status = manager_->GetQueueIds(0);
  ASSERT_STATUS_OK(queue_ids_status);

  queue_ids = queue_ids_status.take();
  ASSERT_EQ(0u, queue_ids.size());
}

TEST_F(DvrDisplayManagerTest, MultiLayerBufferQueue) {
  // Create an application surface.
  auto surface_status = CreateApplicationSurface();
  ASSERT_STATUS_OK(surface_status);
  UniqueDvrSurface surface = surface_status.take();
  ASSERT_NE(nullptr, surface.get());

  // Get surface state and verify there is one surface.
  ASSERT_STATUS_OK(manager_->WaitForUpdate());
  ASSERT_STATUS_EQ(1u, manager_->GetSurfaceCount());

  // Create a new queue in the surface.
  const uint32_t kLayerCount = 3;
  auto write_queue_status = CreateSurfaceQueue(
      surface, 320, 240, AHARDWAREBUFFER_FORMAT_R8G8B8A8_UNORM, kLayerCount,
      AHARDWAREBUFFER_USAGE_CPU_READ_RARELY, 1);
  ASSERT_STATUS_OK(write_queue_status);
  UniqueDvrWriteBufferQueue write_queue = write_queue_status.take();
  ASSERT_NE(nullptr, write_queue.get());

  DvrWriteBuffer* buffer = nullptr;
  dvrWriteBufferCreateEmpty(&buffer);
  int fence_fd = -1;
  int error =
      dvrWriteBufferQueueDequeue(write_queue.get(), 1000, buffer, &fence_fd);
  ASSERT_EQ(0, error);

  AHardwareBuffer* hardware_buffer = nullptr;
  error = dvrWriteBufferGetAHardwareBuffer(buffer, &hardware_buffer);
  ASSERT_EQ(0, error);

  AHardwareBuffer_Desc desc = {};
  AHardwareBuffer_describe(hardware_buffer, &desc);
  ASSERT_EQ(kLayerCount, desc.layers);

  AHardwareBuffer_release(hardware_buffer);
  dvrWriteBufferDestroy(buffer);
}

}  // namespace

}  // namespace dvr
}  // namespace android
