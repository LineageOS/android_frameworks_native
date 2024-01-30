/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <inttypes.h>
#include <android/hardware_buffer.h>
#include <android/sensor.h>
#include <sensor/Sensor.h>
#include <sensor/SensorManager.h>
#include <sensor/SensorEventQueue.h>
#include <utils/Looper.h>
#include <vndk/hardware_buffer.h>

using namespace android;

static nsecs_t sStartTime = 0;


int receiver(__unused int fd, __unused int events, void* data) {
    sp<SensorEventQueue> q((SensorEventQueue*)data);
    ssize_t n;
    ASensorEvent buffer[8];

    static nsecs_t oldTimeStamp = 0;

    while ((n = q->read(buffer, 8)) > 0) {
        for (int i=0 ; i<n ; i++) {
            float t;
            if (oldTimeStamp) {
                t = float(buffer[i].timestamp - oldTimeStamp) / s2ns(1);
            } else {
                t = float(buffer[i].timestamp - sStartTime) / s2ns(1);
            }
            oldTimeStamp = buffer[i].timestamp;

            if (buffer[i].type == Sensor::TYPE_ACCELEROMETER) {
                printf("%" PRId64 "\t%8f\t%8f\t%8f\t%f\n",
                        buffer[i].timestamp,
                        buffer[i].data[0], buffer[i].data[1], buffer[i].data[2],
                        1.0/t);
            }

        }
    }
    if (n<0 && n != -EAGAIN) {
        printf("error reading events (%s)\n", strerror(-n));
    }
    return 1;
}

void testInvalidSharedMem_NoCrash(SensorManager &mgr) {
    AHardwareBuffer *hardwareBuffer;
    char* buffer;

    constexpr size_t kEventSize = sizeof(ASensorEvent);
    constexpr size_t kNEvent = 4096; // enough to contain 1.5 * 800 * 2.2 events
    constexpr size_t kMemSize = kEventSize * kNEvent;
    AHardwareBuffer_Desc desc = {
            .width = static_cast<uint32_t>(kMemSize),
            .height = 1,
            .layers = 1,
            .format = AHARDWAREBUFFER_FORMAT_BLOB,
            .usage = AHARDWAREBUFFER_USAGE_SENSOR_DIRECT_DATA
                        | AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN,
    };

    AHardwareBuffer_allocate(&desc, &hardwareBuffer);
    AHardwareBuffer_lock(hardwareBuffer, AHARDWAREBUFFER_USAGE_CPU_READ_RARELY,
                         -1, nullptr, reinterpret_cast<void **>(&buffer));

    const native_handle_t *resourceHandle = AHardwareBuffer_getNativeHandle(hardwareBuffer);

    // Pass in AHardwareBuffer, but with the wrong DIRECT_CHANNEL_TYPE to see
    // if anything in the Sensor framework crashes
    int ret = mgr.createDirectChannel(
            kMemSize, ASENSOR_DIRECT_CHANNEL_TYPE_SHARED_MEMORY, resourceHandle);

    // Should not succeed (ret != OK) and the device runtime shouldn't restart
    printf("createInvalidDirectChannel=%d\n", ret);

    // Secondary test: correct channel creation & destruction (should print 0)
    ret = mgr.createDirectChannel(kMemSize, ASENSOR_DIRECT_CHANNEL_TYPE_HARDWARE_BUFFER,
                                  resourceHandle);
    printf("createValidDirectChannel=%d\n", ret);

    // Third test: double-destroy (should not crash)
    mgr.destroyDirectChannel(ret);
    AHardwareBuffer_release(hardwareBuffer);
    printf("duplicate destroyDirectChannel...\n");
    mgr.destroyDirectChannel(ret);
}

int main() {
    SensorManager& mgr = SensorManager::getInstanceForPackage(String16("Sensor Service Test"));

    testInvalidSharedMem_NoCrash(mgr);

    Sensor const* const* list;
    ssize_t count = mgr.getSensorList(&list);
    printf("numSensors=%d\n", int(count));

    sp<SensorEventQueue> q = mgr.createEventQueue();
    printf("queue=%p\n", q.get());

    Sensor const* accelerometer = mgr.getDefaultSensor(Sensor::TYPE_ACCELEROMETER);
    printf("accelerometer=%p (%s)\n",
            accelerometer, accelerometer->getName().c_str());

    sStartTime = systemTime();

    q->enableSensor(accelerometer);

    q->setEventRate(accelerometer, ms2ns(10));

    sp<Looper> loop = new Looper(false);
    loop->addFd(q->getFd(), 0, ALOOPER_EVENT_INPUT, receiver, q.get());

    do {
        //printf("about to poll...\n");
        int32_t ret = loop->pollOnce(-1);
        switch (ret) {
            case ALOOPER_POLL_WAKE:
                //("ALOOPER_POLL_WAKE\n");
                break;
            case ALOOPER_POLL_CALLBACK:
                //("ALOOPER_POLL_CALLBACK\n");
                break;
            case ALOOPER_POLL_TIMEOUT:
                printf("ALOOPER_POLL_TIMEOUT\n");
                break;
            case ALOOPER_POLL_ERROR:
                printf("ALOOPER_POLL_ERROR\n");
                break;
            default:
                printf("ugh? poll returned %d\n", ret);
                break;
        }
    } while (1);


    return 0;
}
