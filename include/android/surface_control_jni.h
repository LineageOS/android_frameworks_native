/*
 * Copyright 2022 The Android Open Source Project
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

/**
 * @addtogroup NativeActivity Native Activity
 * @{
 */

/**
 * @file surface_control_jni.h
 */

#ifndef ANDROID_SURFACE_CONTROL_JNI_H
#define ANDROID_SURFACE_CONTROL_JNI_H

#include <jni.h>
#include <sys/cdefs.h>

#include <android/surface_control.h>

__BEGIN_DECLS

/**
 * Return the ASurfaceControl wrapped by a Java SurfaceControl object.
 *
 * This method does not acquire any additional reference to the ASurfaceControl
 * that is returned. To keep the ASurfaceControl alive after the Java
 * SurfaceControl object is closed, explicitly or by the garbage collector, be
 * sure to use ASurfaceControl_acquire() to acquire an additional reference.
 *
 * Available since API level 34.
 */
ASurfaceControl* _Nullable ASurfaceControl_fromSurfaceControl(JNIEnv* _Nonnull env,
        jobject _Nonnull surfaceControlObj) __INTRODUCED_IN(__ANDROID_API_U__);

/**
 * Return the ASurfaceTransaction wrapped by a Java Transaction object.
 *
 * The returned ASurfaceTransaction is still owned by the Java Transaction object is only
 * valid while the Java Transaction object is alive. In particular, the returned transaction
 * must NOT be deleted with ASurfaceTransaction_delete.
 * May return nullptr on error.
 *
 * Available since API level 34.
 */
ASurfaceTransaction* _Nullable ASurfaceTransaction_fromTransaction(JNIEnv* _Nonnull env,
        jobject _Nonnull transactionObj) __INTRODUCED_IN(__ANDROID_API_U__);

__END_DECLS

#endif // ANDROID_SURFACE_CONTROL_JNI_H
/** @} */
