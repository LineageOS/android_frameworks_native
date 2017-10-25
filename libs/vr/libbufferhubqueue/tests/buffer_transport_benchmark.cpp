#include <android/native_window.h>
#include <base/logging.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <dvr/dvr_api.h>
#include <dvr/performance_client_api.h>
#include <gtest/gtest.h>
#include <gui/BufferItem.h>
#include <gui/BufferItemConsumer.h>
#include <gui/Surface.h>
#include <private/dvr/buffer_hub_queue_producer.h>
#include <utils/Trace.h>

#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>  // for pipe

// Use ALWAYS at the tag level. Control is performed manually during command
// line processing.
#ifdef ATRACE_TAG
#undef ATRACE_TAG
#endif
#define ATRACE_TAG ATRACE_TAG_ALWAYS

using namespace android;
using namespace android::dvr;

static const String16 kBinderService = String16("bufferTransport");
static const uint32_t kBufferWidth = 100;
static const uint32_t kBufferHeight = 1;
static const uint32_t kBufferLayerCount = 1;
static const uint32_t kBufferFormat = HAL_PIXEL_FORMAT_BLOB;
static const uint64_t kBufferUsage =
    GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN;
static const int kMaxAcquiredImages = 1;
static const size_t kMaxQueueCounts = 128;

static int gConcurrency = 1;  // 1 writer at a time
static int gIterations = 1000;  // 1K times
static int gSleepIntervalUs = 16 * 1000;  // 16ms

enum BufferTransportServiceCode {
  CREATE_BUFFER_QUEUE = IBinder::FIRST_CALL_TRANSACTION,
};

// A mininal cross process helper class based on a bidirectional pipe pair. This
// is used to signal that Binder-based BufferTransportService has finished
// initialization.
class Pipe {
 public:
  static std::tuple<Pipe, Pipe> CreatePipePair() {
    int a[2] = {-1, -1};
    int b[2] = {-1, -1};

    pipe(a);
    pipe(b);

    return std::make_tuple(Pipe(a[0], b[1]), Pipe(b[0], a[1]));
  }

  Pipe() = default;

  Pipe(Pipe&& other) {
    read_fd_ = other.read_fd_;
    write_fd_ = other.write_fd_;
    other.read_fd_ = 0;
    other.write_fd_ = 0;
  }

  Pipe& operator=(Pipe&& other) {
    Reset();
    read_fd_ = other.read_fd_;
    write_fd_ = other.write_fd_;
    other.read_fd_ = 0;
    other.write_fd_ = 0;
    return *this;
  }

  ~Pipe() { Reset(); }

  Pipe(const Pipe&) = delete;
  Pipe& operator=(const Pipe&) = delete;
  Pipe& operator=(const Pipe&&) = delete;

  bool IsValid() { return read_fd_ > 0 && write_fd_ > 0; }

  void Signal() {
    bool val = true;
    int error = write(write_fd_, &val, sizeof(val));
    ASSERT_GE(error, 0);
  };

  void Wait() {
    bool val = false;
    int error = read(read_fd_, &val, sizeof(val));
    ASSERT_GE(error, 0);
  }

  void Reset() {
    if (read_fd_)
      close(read_fd_);
    if (write_fd_)
      close(write_fd_);
  }

 private:
  int read_fd_ = -1;
  int write_fd_ = -1;
  Pipe(int read_fd, int write_fd) : read_fd_{read_fd}, write_fd_{write_fd} {}
};

// A binder services that minics a compositor that consumes buffers. It provides
// one Binder interface to create a new Surface for buffer producer to write
// into; while itself will carry out no-op buffer consuming by acquiring then
// releasing the buffer immediately.
class BufferTransportService : public BBinder {
 public:
  BufferTransportService() = default;
  ~BufferTransportService() = default;

  virtual status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                              uint32_t flags = 0) {
    (void)flags;
    (void)data;
    switch (code) {
      case CREATE_BUFFER_QUEUE: {
        auto new_queue = std::make_shared<BufferQueueHolder>(this);
        reply->writeStrongBinder(
            IGraphicBufferProducer::asBinder(new_queue->producer_));
        buffer_queues_.push_back(new_queue);
        return NO_ERROR;
      }
      default:
        return UNKNOWN_TRANSACTION;
    };
  }

 private:
  struct FrameListener : public ConsumerBase::FrameAvailableListener {
   public:
    FrameListener(BufferTransportService* service,
                  sp<BufferItemConsumer> buffer_item_consumer)
        : service_(service),
          buffer_item_consumer_(buffer_item_consumer) {}

    void onFrameAvailable(const BufferItem& /*item*/) override {
      std::unique_lock<std::mutex> autolock(service_->reader_mutex_);

      BufferItem buffer;
      status_t ret = 0;
      {
        ATRACE_NAME("AcquireBuffer");
        ret = buffer_item_consumer_->acquireBuffer(&buffer, /*presentWhen=*/0,
                                                   /*waitForFence=*/false);
      }

      if (ret != NO_ERROR) {
        LOG(ERROR) << "Failed to acquire next buffer.";
        return;
      }

      {
        ATRACE_NAME("ReleaseBuffer");
        ret = buffer_item_consumer_->releaseBuffer(buffer);
      }

      if (ret != NO_ERROR) {
        LOG(ERROR) << "Failed to release buffer.";
        return;
      }
    }

   private:
    BufferTransportService* service_ = nullptr;
    sp<BufferItemConsumer> buffer_item_consumer_;
  };

  struct BufferQueueHolder {
    explicit BufferQueueHolder(BufferTransportService* service) {
      BufferQueue::createBufferQueue(&producer_, &consumer_);

      sp<BufferItemConsumer> buffer_item_consumer =
          new BufferItemConsumer(consumer_, kBufferUsage, kMaxAcquiredImages,
                                 /*controlledByApp=*/true);
      buffer_item_consumer->setName(String8("BinderBufferTransport"));
      frame_listener_ = new FrameListener(service, buffer_item_consumer);
      buffer_item_consumer->setFrameAvailableListener(frame_listener_);
    }

    sp<IGraphicBufferProducer> producer_;
    sp<IGraphicBufferConsumer> consumer_;
    sp<FrameListener> frame_listener_;
  };

  std::mutex reader_mutex_;
  std::vector<std::shared_ptr<BufferQueueHolder>> buffer_queues_;
};

// A virtual interfaces that abstracts the common BufferQueue operations, so
// that the test suite can use the same test case to drive different types of
// transport backends.
class BufferTransport {
 public:
  virtual ~BufferTransport() {}

  virtual int Start() = 0;
  virtual sp<Surface> CreateSurface() = 0;
};

// Binder-based buffer transport backend.
//
// On Start() a new process will be swapned to run a Binder server that
// actually consumes the buffer.
// On CreateSurface() a new Binder BufferQueue will be created, which the
// service holds the concrete binder node of the IGraphicBufferProducer while
// sending the binder proxy to the client. In another word, the producer side
// operations are carried out process while the consumer side operations are
// carried out within the BufferTransportService's own process.
class BinderBufferTransport : public BufferTransport {
 public:
  BinderBufferTransport() {}

  ~BinderBufferTransport() {
    if (client_pipe_.IsValid()) {
      client_pipe_.Signal();
      LOG(INFO) << "Client signals service to shut down.";
    }
  }

  int Start() override {
    // Fork a process to run a binder server. The parent process will return
    // a pipe here, and we use the pipe to signal the binder server to exit.
    client_pipe_ = CreateBinderServer();

    // Wait until service is ready.
    LOG(INFO) << "Service is ready for client.";
    client_pipe_.Wait();
    return 0;
  }

  sp<Surface> CreateSurface() override {
    sp<IServiceManager> sm = defaultServiceManager();
    service_ = sm->getService(kBinderService);
    if (service_ == nullptr) {
      LOG(ERROR) << "Failed to set the benchmark service.";
      return nullptr;
    }

    Parcel data;
    Parcel reply;
    int error = service_->transact(CREATE_BUFFER_QUEUE, data, &reply);
    if (error != NO_ERROR) {
      LOG(ERROR) << "Failed to get buffer queue over binder.";
      return nullptr;
    }

    sp<IBinder> binder;
    error = reply.readNullableStrongBinder(&binder);
    if (error != NO_ERROR) {
      LOG(ERROR) << "Failed to get IGraphicBufferProducer over binder.";
      return nullptr;
    }

    auto producer = interface_cast<IGraphicBufferProducer>(binder);
    if (producer == nullptr) {
      LOG(ERROR) << "Failed to get IGraphicBufferProducer over binder.";
      return nullptr;
    }

    sp<Surface> surface = new Surface(producer, /*controlledByApp=*/true);

    // Set buffer dimension.
    ANativeWindow* window = static_cast<ANativeWindow*>(surface.get());
    ANativeWindow_setBuffersGeometry(window, kBufferWidth, kBufferHeight,
                                     kBufferFormat);

    return surface;
  }

 private:
  static Pipe CreateBinderServer() {
    std::tuple<Pipe, Pipe> pipe_pair = Pipe::CreatePipePair();
    pid_t pid = fork();
    if (pid) {
      // parent, i.e. the client side.
      ProcessState::self()->startThreadPool();
      LOG(INFO) << "Binder server pid: " << pid;
      return std::move(std::get<0>(pipe_pair));
    } else {
      // child, i.e. the service side.
      Pipe service_pipe = std::move(std::get<1>(pipe_pair));

      ProcessState::self()->startThreadPool();
      sp<IServiceManager> sm = defaultServiceManager();
      sp<BufferTransportService> service = new BufferTransportService;
      sm->addService(kBinderService, service, false);

      LOG(INFO) << "Binder Service Running...";

      service_pipe.Signal();
      service_pipe.Wait();

      LOG(INFO) << "Service Exiting...";
      exit(EXIT_SUCCESS);

      /* never get here */
      return {};
    }
  }

  sp<IBinder> service_;
  Pipe client_pipe_;
};

// BufferHub/PDX-based buffer transport.
//
// On Start() a new thread will be swapned to run an epoll polling thread which
// minics the behavior of a compositor. Similar to Binder-based backend, the
// buffer available handler is also a no-op: Buffer gets acquired and released
// immediately.
// On CreateSurface() a pair of dvr::ProducerQueue and dvr::ConsumerQueue will
// be created. The epoll thread holds on the consumer queue and dequeues buffer
// from it; while the producer queue will be wrapped in a Surface and returned
// to test suite.
class BufferHubTransport : public BufferTransport {
 public:
  virtual ~BufferHubTransport() {
    stopped_.store(true);
    if (reader_thread_.joinable()) {
      reader_thread_.join();
    }
  }

  int Start() override {
    int ret = epoll_fd_.Create();
    if (ret < 0) {
      LOG(ERROR) << "Failed to create epoll fd: %s", strerror(-ret);
      return -1;
    }

    // Create the reader thread.
    reader_thread_ = std::thread([this]() {
      int ret = dvrSetSchedulerClass(0, "graphics");
      if (ret < 0) {
        LOG(ERROR) << "Failed to set thread priority";
        return;
      }


      ret = dvrSetCpuPartition(0, "/system/performance");
      if (ret < 0) {
        LOG(ERROR) << "Failed to set thread cpu partition";
        return;
      }

      stopped_.store(false);
      LOG(INFO) << "Reader Thread Running...";

      while (!stopped_.load()) {
        std::array<epoll_event, kMaxQueueCounts> events;

        // Don't sleep forever so that we will have a chance to wake up.
        const int ret = epoll_fd_.Wait(events.data(), events.size(),
                                       /*timeout=*/100);
        if (ret < 0) {
          LOG(ERROR) << "Error polling consumer queues.";
          continue;
        }
        if (ret == 0) {
          continue;
        }

        const int num_events = ret;
        for (int i = 0; i < num_events; i++) {
          uint32_t surface_index = events[i].data.u32;
          // LOG(INFO) << "!!! handle queue events index: " << surface_index;
          buffer_queues_[surface_index]->consumer_queue_->HandleQueueEvents();
        }
      }

      LOG(INFO) << "Reader Thread Exiting...";
    });

    return 0;
  }

  sp<Surface> CreateSurface() override {
    std::lock_guard<std::mutex> autolock(queue_mutex_);

    auto new_queue = std::make_shared<BufferQueueHolder>();
    if (new_queue->producer_ == nullptr) {
      LOG(ERROR) << "Failed to create buffer producer.";
      return nullptr;
    }

    sp<Surface> surface =
        new Surface(new_queue->producer_, /*controlledByApp=*/true);

    // Set buffer dimension.
    ANativeWindow* window = static_cast<ANativeWindow*>(surface.get());
    ANativeWindow_setBuffersGeometry(window, kBufferWidth, kBufferHeight,
                                     kBufferFormat);

    // Use the next position as buffer_queue index.
    uint32_t index = buffer_queues_.size();
    epoll_event event = {.events = EPOLLIN | EPOLLET, .data = {.u32 = index}};
    const int ret = epoll_fd_.Control(
        EPOLL_CTL_ADD, new_queue->consumer_queue_->queue_fd(), &event);
    if (ret < 0) {
      LOG(ERROR) << "Failed to track consumer queue: " << strerror(-ret)
                 << ", consumer queue fd: "
                 << new_queue->consumer_queue_->queue_fd();
      return nullptr;
    }

    new_queue->queue_index_ = index;
    buffer_queues_.push_back(new_queue);
    return surface;
  }

 private:
  struct BufferQueueHolder {
    BufferQueueHolder() {
      ProducerQueueConfigBuilder config_builder;
      producer_queue_ =
          ProducerQueue::Create(config_builder.SetDefaultWidth(kBufferWidth)
                                    .SetDefaultHeight(kBufferHeight)
                                    .SetDefaultFormat(kBufferFormat)
                                    .SetMetadata<DvrNativeBufferMetadata>()
                                    .Build(),
                                UsagePolicy{});
      consumer_queue_ = producer_queue_->CreateConsumerQueue();
      consumer_queue_->SetBufferAvailableCallback([this]() {
        size_t index = 0;
        pdx::LocalHandle fence;
        DvrNativeBufferMetadata meta;
        pdx::Status<std::shared_ptr<BufferConsumer>> status;

        {
          ATRACE_NAME("AcquireBuffer");
          status = consumer_queue_->Dequeue(0, &index, &meta, &fence);
        }
        if (!status.ok()) {
          LOG(ERROR) << "Failed to dequeue consumer buffer, error: "
                     << status.GetErrorMessage().c_str();
          return;
        }

        auto buffer = status.take();

        if (buffer) {
          ATRACE_NAME("ReleaseBuffer");
          buffer->ReleaseAsync();
        }
      });

      producer_ = BufferHubQueueProducer::Create(producer_queue_);
    }

    int count_ = 0;
    int queue_index_;
    std::shared_ptr<ProducerQueue> producer_queue_;
    std::shared_ptr<ConsumerQueue> consumer_queue_;
    sp<IGraphicBufferProducer> producer_;
  };

  std::atomic<bool> stopped_;
  std::thread reader_thread_;

  // Mutex to guard epoll_fd_ and buffer_queues_.
  std::mutex queue_mutex_;
  EpollFileDescriptor epoll_fd_;
  std::vector<std::shared_ptr<BufferQueueHolder>> buffer_queues_;
};

enum TransportType {
  kBinderBufferTransport,
  kBufferHubTransport,
};

// Main test suite, which supports two transport backend: 1) BinderBufferQueue,
// 2) BufferHubQueue. The test case drives the producer end of both transport
// backend by queuing buffers into the buffer queue by using ANativeWindow API.
class BufferTransportBenchmark
    : public ::testing::TestWithParam<TransportType> {
 public:
  void SetUp() override {
    switch (GetParam()) {
      case kBinderBufferTransport:
        transport_.reset(new BinderBufferTransport);
        break;
      case kBufferHubTransport:
        transport_.reset(new BufferHubTransport);
        break;
      default:
        FAIL() << "Unknown test case.";
        break;
    }
  }

 protected:
  void ProduceBuffers(sp<Surface> surface, int iterations, int sleep_usec) {
    ANativeWindow* window = static_cast<ANativeWindow*>(surface.get());
    ANativeWindow_Buffer buffer;
    int32_t error = 0;

    for (int i = 0; i < iterations; i++) {
      usleep(sleep_usec);

      {
        ATRACE_NAME("GainBuffer");
        error = ANativeWindow_lock(window, &buffer,
                                   /*inOutDirtyBounds=*/nullptr);
      }
      ASSERT_EQ(error, 0);

      {
        ATRACE_NAME("PostBuffer");
        error = ANativeWindow_unlockAndPost(window);
      }
      ASSERT_EQ(error, 0);
    }
  }

  std::unique_ptr<BufferTransport> transport_;
};

TEST_P(BufferTransportBenchmark, ContinuousLoad) {
  ASSERT_NE(transport_, nullptr);
  const int ret = transport_->Start();
  ASSERT_EQ(ret, 0);

  LOG(INFO) << "Start Running.";

  std::vector<std::thread> writer_threads;
  for (int i = 0; i < gConcurrency; i++) {
    std::thread writer_thread = std::thread([this]() {
      sp<Surface> surface = transport_->CreateSurface();
      ASSERT_NE(surface, nullptr);

      ASSERT_NO_FATAL_FAILURE(
          ProduceBuffers(surface, gIterations, gSleepIntervalUs));

      usleep(1000 * 100);
    });

    writer_threads.push_back(std::move(writer_thread));
  }

  for (auto& writer_thread : writer_threads) {
    writer_thread.join();
  }

  LOG(INFO) << "All done.";
};

INSTANTIATE_TEST_CASE_P(BufferTransportBenchmarkInstance,
                        BufferTransportBenchmark,
                        ::testing::ValuesIn({kBinderBufferTransport,
                                             kBufferHubTransport}));

// To run binder-based benchmark, use:
// adb shell buffer_transport_benchmark \
//   --gtest_filter="BufferTransportBenchmark.ContinuousLoad/0"
//
// To run bufferhub-based benchmark, use:
// adb shell buffer_transport_benchmark \
//   --gtest_filter="BufferTransportBenchmark.ContinuousLoad/1"
int main(int argc, char** argv) {
  bool tracing_enabled = false;

  // Parse arguments in addition to "--gtest_filter" paramters.
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "--help") {
      std::cout << "Usage: binderThroughputTest [OPTIONS]" << std::endl;
      std::cout << "\t-c N: Specify number of concurrent writer threads, "
                   "(default: 1, max: 128)."
                << std::endl;
      std::cout << "\t-i N: Specify number of iterations, (default: 1000)."
                << std::endl;
      std::cout << "\t-s N: Specify sleep interval in usec, (default: 16000)."
                << std::endl;
      std::cout << "\t--trace: Enable systrace logging."
                << std::endl;
      return 0;
    }
    if (std::string(argv[i]) == "-c") {
      gConcurrency = atoi(argv[i + 1]);
      i++;
      continue;
    }
    if (std::string(argv[i]) == "-s") {
      gSleepIntervalUs = atoi(argv[i + 1]);
      i++;
      continue;
    }
    if (std::string(argv[i]) == "-i") {
      gIterations = atoi(argv[i + 1]);
      i++;
      continue;
    }
    if (std::string(argv[i]) == "--trace") {
      tracing_enabled = true;
      continue;
    }
  }

  // Setup ATRACE/systrace based on command line.
  atrace_setup();
  atrace_set_tracing_enabled(tracing_enabled);

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
