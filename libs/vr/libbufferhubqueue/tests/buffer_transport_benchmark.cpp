#include <android/native_window.h>
#include <android-base/logging.h>
#include <benchmark/benchmark.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <dvr/dvr_api.h>
#include <dvr/performance_client_api.h>
#include <gui/BufferItem.h>
#include <gui/BufferItemConsumer.h>
#include <gui/Surface.h>
#include <private/dvr/buffer_hub_queue_producer.h>
#include <utils/Trace.h>

#include <chrono>
#include <functional>
#include <iostream>
#include <thread>
#include <vector>

#include <poll.h>
#include <sys/wait.h>

// Use ALWAYS at the tag level. Control is performed manually during command
// line processing.
#ifdef ATRACE_TAG
#undef ATRACE_TAG
#endif
#define ATRACE_TAG ATRACE_TAG_ALWAYS

using namespace android;
using namespace android::dvr;
using ::benchmark::State;

static const String16 kBinderService = String16("bufferTransport");
static const uint32_t kBufferWidth = 100;
static const uint32_t kBufferHeight = 1;
static const uint32_t kBufferFormat = HAL_PIXEL_FORMAT_BLOB;
static const uint64_t kBufferUsage =
    GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN;
static const int kMaxAcquiredImages = 1;
static const int kQueueDepth = 2;  // We are double buffering for this test.
static const size_t kMaxQueueCounts = 128;

enum BufferTransportServiceCode {
  CREATE_BUFFER_QUEUE = IBinder::FIRST_CALL_TRANSACTION,
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
    FrameListener(BufferTransportService* /*service*/,
                  sp<BufferItemConsumer> buffer_item_consumer)
        : buffer_item_consumer_(buffer_item_consumer) {}

    void onFrameAvailable(const BufferItem& /*item*/) override {
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

  int Start() override {
    sp<IServiceManager> sm = defaultServiceManager();
    service_ = sm->getService(kBinderService);
    if (service_ == nullptr) {
      LOG(ERROR) << "Failed to get the benchmark service.";
      return -EIO;
    }

    LOG(INFO) << "Binder server is ready for client.";
    return 0;
  }

  sp<Surface> CreateSurface() override {
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
  sp<IBinder> service_;
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
          buffer_queues_[surface_index]->consumer_queue_->HandleQueueEvents();
        }
      }

      LOG(INFO) << "Reader Thread Exiting...";
    });

    return 0;
  }

  sp<Surface> CreateSurface() override {
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
class BufferTransportBenchmark : public ::benchmark::Fixture {
 public:
  void SetUp(State& state) override {
    if (state.thread_index == 0) {
      const int transport = state.range(0);
      switch (transport) {
        case kBinderBufferTransport:
          transport_.reset(new BinderBufferTransport);
          break;
        case kBufferHubTransport:
          transport_.reset(new BufferHubTransport);
          break;
        default:
          CHECK(false) << "Unknown test case.";
          break;
      }

      CHECK(transport_);
      const int ret = transport_->Start();
      CHECK_EQ(ret, 0);

      LOG(INFO) << "Transport backend running, transport=" << transport << ".";

      // Create surfaces for each thread.
      surfaces_.resize(state.threads);
      for (int i = 0; i < state.threads; i++) {
        // Common setup every thread needs.
        surfaces_[i] = transport_->CreateSurface();
        CHECK(surfaces_[i]);

        LOG(INFO) << "Surface initialized on thread " << i << ".";
      }
    }
  }

  void TearDown(State& state) override {
    if (state.thread_index == 0) {
      surfaces_.clear();
      transport_.reset();
      LOG(INFO) << "Tear down benchmark.";
    }
  }

 protected:
  std::unique_ptr<BufferTransport> transport_;
  std::vector<sp<Surface>> surfaces_;
};

BENCHMARK_DEFINE_F(BufferTransportBenchmark, Producers)(State& state) {
  ANativeWindow* window = nullptr;
  ANativeWindow_Buffer buffer;
  int32_t error = 0;
  double total_gain_buffer_us = 0;
  double total_post_buffer_us = 0;
  int iterations = 0;

  while (state.KeepRunning()) {
    if (window == nullptr) {
      CHECK(surfaces_[state.thread_index]);
      window = static_cast<ANativeWindow*>(surfaces_[state.thread_index].get());

      // Lock buffers a couple time from the queue, so that we have the buffer
      // allocated.
      for (int i = 0; i < kQueueDepth; i++) {
        error = ANativeWindow_lock(window, &buffer,
                                   /*inOutDirtyBounds=*/nullptr);
        CHECK_EQ(error, 0);
        error = ANativeWindow_unlockAndPost(window);
        CHECK_EQ(error, 0);
      }
    }

    {
      ATRACE_NAME("GainBuffer");
      auto t1 = std::chrono::high_resolution_clock::now();
      error = ANativeWindow_lock(window, &buffer,
                                 /*inOutDirtyBounds=*/nullptr);
      auto t2 = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::micro> delta_us = t2 - t1;
      total_gain_buffer_us += delta_us.count();
    }
    CHECK_EQ(error, 0);

    {
      ATRACE_NAME("PostBuffer");
      auto t1 = std::chrono::high_resolution_clock::now();
      error = ANativeWindow_unlockAndPost(window);
      auto t2 = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double, std::micro> delta_us = t2 - t1;
      total_post_buffer_us += delta_us.count();
    }
    CHECK_EQ(error, 0);

    iterations++;
  }

  state.counters["gain_buffer_us"] = ::benchmark::Counter(
      total_gain_buffer_us / iterations, ::benchmark::Counter::kAvgThreads);
  state.counters["post_buffer_us"] = ::benchmark::Counter(
      total_post_buffer_us / iterations, ::benchmark::Counter::kAvgThreads);
  state.counters["producer_us"] = ::benchmark::Counter(
      (total_gain_buffer_us + total_post_buffer_us) / iterations,
      ::benchmark::Counter::kAvgThreads);
}

BENCHMARK_REGISTER_F(BufferTransportBenchmark, Producers)
    ->Unit(::benchmark::kMicrosecond)
    ->Ranges({{kBinderBufferTransport, kBufferHubTransport}})
    ->ThreadRange(1, 32);

static void runBinderServer() {
  ProcessState::self()->setThreadPoolMaxThreadCount(0);
  ProcessState::self()->startThreadPool();

  sp<IServiceManager> sm = defaultServiceManager();
  sp<BufferTransportService> service = new BufferTransportService;
  sm->addService(kBinderService, service, false);

  LOG(INFO) << "Binder server running...";

  while (true) {
    int stat, retval;
    retval = wait(&stat);
    if (retval == -1 && errno == ECHILD) {
      break;
    }
  }

  LOG(INFO) << "Service Exiting...";
}

// To run binder-based benchmark, use:
// adb shell buffer_transport_benchmark \
//   --benchmark_filter="BufferTransportBenchmark/ContinuousLoad/0/"
//
// To run bufferhub-based benchmark, use:
// adb shell buffer_transport_benchmark \
//   --benchmark_filter="BufferTransportBenchmark/ContinuousLoad/1/"
int main(int argc, char** argv) {
  bool tracing_enabled = false;

  // Parse arguments in addition to "--benchmark_filter" paramters.
  for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "--help") {
      std::cout << "Usage: binderThroughputTest [OPTIONS]" << std::endl;
      std::cout << "\t--trace: Enable systrace logging."
                << std::endl;
      return 0;
    }
    if (std::string(argv[i]) == "--trace") {
      tracing_enabled = true;
      continue;
    }
  }

  // Setup ATRACE/systrace based on command line.
  atrace_setup();
  atrace_set_tracing_enabled(tracing_enabled);

  pid_t pid = fork();
  if (pid == 0) {
    // parent, i.e. the client side.
    ProcessState::self()->startThreadPool();

    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
  } else {
    LOG(INFO) << "Benchmark process pid: " << pid;
    runBinderServer();
  }
}
