// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <jni.h>
#include <string>

#include <gui/BufferQueue.h>

void log(JNIEnv* env, std::string l) {
    jclass clazz = env->FindClass("com/android/graphics/bufferstreamsdemoapp/LogOutput");
    jmethodID getInstance = env->GetStaticMethodID(clazz, "getInstance",
        "()Lcom/android/graphics/bufferstreamsdemoapp/LogOutput;");
    jmethodID addLog = env->GetMethodID(clazz, "addLog", "(Ljava/lang/String;)V");
    jobject dmg = env->CallStaticObjectMethod(clazz, getInstance);

    jstring jlog = env->NewStringUTF(l.c_str());
    env->CallVoidMethod(dmg, addLog, jlog);
}

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_android_graphics_bufferstreamsdemoapp_BufferStreamJNI_stringFromJNI(JNIEnv* env,
                                                                             jobject /* this */) {
    const char* hello = "Hello from C++";
    return env->NewStringUTF(hello);
}

JNIEXPORT void JNICALL
Java_com_android_graphics_bufferstreamsdemoapp_BufferStreamJNI_testBufferQueueCreation(
        JNIEnv* env, jobject /* thiz */) {

    log(env, "Calling testBufferQueueCreation.");
    android::sp<android::IGraphicBufferProducer> producer;
    log(env, "Created producer.");
    android::sp<android::IGraphicBufferConsumer> consumer;
    log(env, "Created consumer.");
    android::BufferQueue::createBufferQueue(&producer, &consumer);
    log(env, "Created BufferQueue successfully.");
    log(env, "Done!");
}
}