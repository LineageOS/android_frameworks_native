#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>

#include <fstream>
#include <iostream>
#include <tuple>
#include <vector>

#include <unistd.h>
#include <sys/wait.h>

using namespace std;
using namespace android;

enum BinderWorkerServiceCode {
    BINDER_NOP = IBinder::FIRST_CALL_TRANSACTION,
};

#define ASSERT_TRUE(cond) \
do { \
    if (!(cond)) {\
       cerr << __func__ << ":" << __LINE__ << " condition:" << #cond << " failed\n" << endl; \
       exit(EXIT_FAILURE); \
    } \
} while (0)

class BinderWorkerService : public BBinder
{
public:
    BinderWorkerService() {}
    ~BinderWorkerService() {}
    virtual status_t onTransact(uint32_t code,
                                const Parcel& data, Parcel* reply,
                                uint32_t flags = 0) {
        (void)flags;
        (void)data;
        (void)reply;
        switch (code) {
        case BINDER_NOP:
            return NO_ERROR;
        default:
            return UNKNOWN_TRANSACTION;
        };
    }
};

static uint64_t warn_latency = std::numeric_limits<uint64_t>::max();

struct ProcResults {
    vector<uint64_t> data;

    ProcResults(size_t capacity) { data.reserve(capacity); }

    void add_time(uint64_t time) { data.push_back(time); }
    void combine_with(const ProcResults& append) {
        data.insert(data.end(), append.data.begin(), append.data.end());
    }
    uint64_t worst() {
        return *max_element(data.begin(), data.end());
    }
    void dump_to_file(string filename) {
        ofstream output;
        output.open(filename);
        if (!output.is_open()) {
            cerr << "Failed to open '" << filename << "'." << endl;
            exit(EXIT_FAILURE);
        }
        for (uint64_t value : data) {
            output << value << "\n";
        }
        output.close();
    }
    void dump() {
        if (data.size() == 0) {
            // This avoids index-out-of-bounds below.
            cout << "error: no data\n" << endl;
            return;
        }

        size_t num_long_transactions = 0;
        for (uint64_t elem : data) {
            if (elem > warn_latency) {
                num_long_transactions += 1;
            }
        }

        if (num_long_transactions > 0) {
            cout << (double)num_long_transactions / data.size() << "% of transactions took longer "
                "than estimated max latency. Consider setting -m to be higher than "
                << worst() / 1000 << " microseconds" << endl;
        }

        sort(data.begin(), data.end());

        uint64_t total_time = 0;
        for (uint64_t elem : data) {
            total_time += elem;
        }

        double best = (double)data[0] / 1.0E6;
        double worst = (double)data.back() / 1.0E6;
        double average = (double)total_time / data.size() / 1.0E6;
        cout << "average:" << average << "ms worst:" << worst << "ms best:" << best << "ms" << endl;

        double percentile_50 = data[(50 * data.size()) / 100] / 1.0E6;
        double percentile_90 = data[(90 * data.size()) / 100] / 1.0E6;
        double percentile_95 = data[(95 * data.size()) / 100] / 1.0E6;
        double percentile_99 = data[(99 * data.size()) / 100] / 1.0E6;
        cout << "50%: " << percentile_50 << " ";
        cout << "90%: " << percentile_90 << " ";
        cout << "95%: " << percentile_95 << " ";
        cout << "99%: " << percentile_99 << endl;
    }
};

class Pipe {
    int m_readFd;
    int m_writeFd;
    Pipe(int readFd, int writeFd) : m_readFd{readFd}, m_writeFd{writeFd} {}
    Pipe(const Pipe &) = delete;
    Pipe& operator=(const Pipe &) = delete;
    Pipe& operator=(const Pipe &&) = delete;
public:
    Pipe(Pipe&& rval) noexcept {
        m_readFd = rval.m_readFd;
        m_writeFd = rval.m_writeFd;
        rval.m_readFd = 0;
        rval.m_writeFd = 0;
    }
    ~Pipe() {
        if (m_readFd)
            close(m_readFd);
        if (m_writeFd)
            close(m_writeFd);
    }
    void signal() {
        bool val = true;
        int error = write(m_writeFd, &val, sizeof(val));
        ASSERT_TRUE(error >= 0);
    };
    void wait() {
        bool val = false;
        int error = read(m_readFd, &val, sizeof(val));
        ASSERT_TRUE(error >= 0);
    }
    void send(const ProcResults& v) {
        size_t num_elems = v.data.size();

        int error = write(m_writeFd, &num_elems, sizeof(size_t));
        ASSERT_TRUE(error >= 0);

        char* to_write = (char*)v.data.data();
        size_t num_bytes = sizeof(uint64_t) * num_elems;

        while (num_bytes > 0) {
            int ret = write(m_writeFd, to_write, num_bytes);
            ASSERT_TRUE(ret >= 0);
            num_bytes -= ret;
            to_write += ret;
        }
    }
    void recv(ProcResults& v) {
        size_t num_elems = 0;
        int error = read(m_readFd, &num_elems, sizeof(size_t));
        ASSERT_TRUE(error >= 0);

        v.data.resize(num_elems);
        char* read_to = (char*)v.data.data();
        size_t num_bytes = sizeof(uint64_t) * num_elems;

        while (num_bytes > 0) {
            int ret = read(m_readFd, read_to, num_bytes);
            ASSERT_TRUE(ret >= 0);
            num_bytes -= ret;
            read_to += ret;
        }
    }
    static tuple<Pipe, Pipe> createPipePair() {
        int a[2];
        int b[2];

        int error1 = pipe(a);
        int error2 = pipe(b);
        ASSERT_TRUE(error1 >= 0);
        ASSERT_TRUE(error2 >= 0);

        return make_tuple(Pipe(a[0], b[1]), Pipe(b[0], a[1]));
    }
};

String16 generateServiceName(int num)
{
    char num_str[32];
    snprintf(num_str, sizeof(num_str), "%d", num);
    String16 serviceName = String16("binderWorker") + String16(num_str);
    return serviceName;
}

void worker_fx(int num,
               int worker_count,
               int iterations,
               int payload_size,
               bool cs_pair,
               Pipe p)
{
    // Create BinderWorkerService and for go.
    ProcessState::self()->startThreadPool();
    sp<IServiceManager> serviceMgr = defaultServiceManager();
    sp<BinderWorkerService> service = new BinderWorkerService;
    serviceMgr->addService(generateServiceName(num), service);

    srand(num);
    p.signal();
    p.wait();

    // If client/server pairs, then half the workers are
    // servers and half are clients
    int server_count = cs_pair ? worker_count / 2 : worker_count;

    // Get references to other binder services.
    cout << "Created BinderWorker" << num << endl;
    (void)worker_count;
    vector<sp<IBinder> > workers;
    for (int i = 0; i < server_count; i++) {
        if (num == i)
            continue;
        workers.push_back(serviceMgr->waitForService(generateServiceName(i)));
    }

    p.signal();
    p.wait();

    ProcResults results(iterations);
    chrono::time_point<chrono::high_resolution_clock> start, end;

    // Skip the benchmark if server of a cs_pair.
    if (!(cs_pair && num < server_count)) {
        for (int i = 0; i < iterations; i++) {
            Parcel data, reply;
            int target = cs_pair ? num % server_count : rand() % workers.size();
            int sz = payload_size;

            while (sz >= sizeof(uint32_t)) {
                data.writeInt32(0);
                sz -= sizeof(uint32_t);
            }
            start = chrono::high_resolution_clock::now();
            status_t ret = workers[target]->transact(BINDER_NOP, data, &reply);
            end = chrono::high_resolution_clock::now();

            uint64_t cur_time = uint64_t(chrono::duration_cast<chrono::nanoseconds>(end - start).count());
            results.add_time(cur_time);

            if (ret != NO_ERROR) {
               cout << "thread " << num << " failed " << ret << "i : " << i << endl;
               exit(EXIT_FAILURE);
            }
        }
    }

    // Signal completion to master and wait.
    p.signal();
    p.wait();

    // Send results to master and wait for go to exit.
    p.send(results);
    p.wait();

    exit(EXIT_SUCCESS);
}

Pipe make_worker(int num, int iterations, int worker_count, int payload_size, bool cs_pair)
{
    auto pipe_pair = Pipe::createPipePair();
    pid_t pid = fork();
    if (pid) {
        /* parent */
        return std::move(get<0>(pipe_pair));
    } else {
        /* child */
        worker_fx(num, worker_count, iterations, payload_size, cs_pair,
                  std::move(get<1>(pipe_pair)));
        /* never get here */
        return std::move(get<0>(pipe_pair));
    }

}

void wait_all(vector<Pipe>& v)
{
    for (int i = 0; i < v.size(); i++) {
        v[i].wait();
    }
}

void signal_all(vector<Pipe>& v)
{
    for (int i = 0; i < v.size(); i++) {
        v[i].signal();
    }
}

void run_main(int iterations, int workers, int payload_size, int cs_pair,
              bool training_round = false, bool dump_to_file = false, string dump_filename = "") {
    vector<Pipe> pipes;
    // Create all the workers and wait for them to spawn.
    for (int i = 0; i < workers; i++) {
        pipes.push_back(make_worker(i, iterations, workers, payload_size, cs_pair));
    }
    wait_all(pipes);
    // All workers have now been spawned and added themselves to service
    // manager. Signal each worker to obtain a handle to the server workers from
    // servicemanager.
    signal_all(pipes);
    // Wait for each worker to finish obtaining a handle to all server workers
    // from servicemanager.
    wait_all(pipes);

    // Run the benchmark and wait for completion.
    chrono::time_point<chrono::high_resolution_clock> start, end;
    cout << "waiting for workers to complete" << endl;
    start = chrono::high_resolution_clock::now();
    signal_all(pipes);
    wait_all(pipes);
    end = chrono::high_resolution_clock::now();

    // Calculate overall throughput.
    double iterations_per_sec = double(iterations * workers) / (chrono::duration_cast<chrono::nanoseconds>(end - start).count() / 1.0E9);
    cout << "iterations per sec: " << iterations_per_sec << endl;

    // Collect all results from the workers.
    cout << "collecting results" << endl;
    signal_all(pipes);
    ProcResults tot_results(0), tmp_results(0);
    for (int i = 0; i < workers; i++) {
        pipes[i].recv(tmp_results);
        tot_results.combine_with(tmp_results);
    }

    // Kill all the workers.
    cout << "killing workers" << endl;
    signal_all(pipes);
    for (int i = 0; i < workers; i++) {
        int status;
        wait(&status);
        if (status != 0) {
            cout << "nonzero child status" << status << endl;
        }
    }
    if (training_round) {
        // Sets warn_latency to 2 * worst from the training round.
        warn_latency = 2 * tot_results.worst();
        cout << "Max latency during training: " << tot_results.worst() / 1.0E6 << "ms" << endl;
    } else {
        if (dump_to_file) {
            tot_results.dump_to_file(dump_filename);
        }
        tot_results.dump();
    }
}

int main(int argc, char *argv[])
{
    int workers = 2;
    int iterations = 10000;
    int payload_size = 0;
    bool cs_pair = false;
    bool training_round = false;
    int max_time_us;
    bool dump_to_file = false;
    string dump_filename;

    // Parse arguments.
    for (int i = 1; i < argc; i++) {
        if (string(argv[i]) == "--help") {
            cout << "Usage: binderThroughputTest [OPTIONS]" << endl;
            cout << "\t-i N    : Specify number of iterations." << endl;
            cout << "\t-m N    : Specify expected max latency in microseconds." << endl;
            cout << "\t-p      : Split workers into client/server pairs." << endl;
            cout << "\t-s N    : Specify payload size." << endl;
            cout << "\t-t      : Run training round." << endl;
            cout << "\t-w N    : Specify total number of workers." << endl;
            cout << "\t-d FILE : Dump raw data to file." << endl;
            return 0;
        }
        if (string(argv[i]) == "-w") {
            if (i + 1 == argc) {
                cout << "-w requires an argument\n" << endl;
                exit(EXIT_FAILURE);
            }
            workers = atoi(argv[i+1]);
            i++;
            continue;
        }
        if (string(argv[i]) == "-i") {
            if (i + 1 == argc) {
                cout << "-i requires an argument\n" << endl;
                exit(EXIT_FAILURE);
            }
            iterations = atoi(argv[i+1]);
            i++;
            continue;
        }
        if (string(argv[i]) == "-s") {
            if (i + 1 == argc) {
                cout << "-s requires an argument\n" << endl;
                exit(EXIT_FAILURE);
            }
            payload_size = atoi(argv[i+1]);
            i++;
            continue;
        }
        if (string(argv[i]) == "-p") {
            // client/server pairs instead of spreading
            // requests to all workers. If true, half
            // the workers become clients and half servers
            cs_pair = true;
            continue;
        }
        if (string(argv[i]) == "-t") {
            // Run one training round before actually collecting data
            // to get an approximation of max latency.
            training_round = true;
            continue;
        }
        if (string(argv[i]) == "-m") {
            if (i + 1 == argc) {
                cout << "-m requires an argument\n" << endl;
                exit(EXIT_FAILURE);
            }
            // Caller specified the max latency in microseconds.
            // No need to run training round in this case.
            max_time_us = atoi(argv[i+1]);
            if (max_time_us <= 0) {
                cout << "Max latency -m must be positive." << endl;
                exit(EXIT_FAILURE);
            }
            warn_latency = max_time_us * 1000ull;
            i++;
            continue;
        }
        if (string(argv[i]) == "-d") {
            if (i + 1 == argc) {
                cout << "-d requires an argument\n" << endl;
                exit(EXIT_FAILURE);
            }
            dump_to_file = true;
            dump_filename = argv[i + 1];
            i++;
            continue;
        }
    }

    if (training_round) {
        cout << "Start training round" << endl;
        run_main(iterations, workers, payload_size, cs_pair, true);
        cout << "Completed training round" << endl << endl;
    }

    run_main(iterations, workers, payload_size, cs_pair, false, dump_to_file, dump_filename);
    return 0;
}
