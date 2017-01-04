/*
 * Copyright (C) 2005 The Android Open Source Project
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

#define LOG_TAG "IInterface"
#include <utils/Log.h>
#include <binder/IInterface.h>

namespace android {

// ---------------------------------------------------------------------------

IInterface::IInterface() 
    : RefBase() {
}

IInterface::~IInterface() {
}

// static
sp<IBinder> IInterface::asBinder(const IInterface* iface)
{
    if (iface == NULL) return NULL;
    return const_cast<IInterface*>(iface)->onAsBinder();
}

// static
sp<IBinder> IInterface::asBinder(const sp<IInterface>& iface)
{
    if (iface == NULL) return NULL;
    return iface->onAsBinder();
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundefined-bool-conversion"

sp<IBinder> IInterface::asBinder()
{
    return this ? onAsBinder() : NULL;
}

sp<const IBinder> IInterface::asBinder() const
{
    return this ? const_cast<IInterface*>(this)->onAsBinder() : NULL;
}

#pragma GCC diagnostic pop

// ---------------------------------------------------------------------------

}; // namespace android
