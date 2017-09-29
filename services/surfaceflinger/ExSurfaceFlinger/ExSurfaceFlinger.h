/* Copyright (c) 2015 - 2017, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef ANDROID_EX_SURFACE_FLINGER_H
#define ANDROID_EX_SURFACE_FLINGER_H

#include "SurfaceFlinger.h"

namespace android {

class ExSurfaceFlinger : public SurfaceFlinger
{
public:

    ExSurfaceFlinger();

protected:
    friend class ExLayer;

    virtual void updateExtendedMode();
    virtual void getIndexLOI(size_t dpy,
                     bool& bIgnoreLayers,
                     String8& nameLOI);
    virtual bool updateLayerVisibleNonTransparentRegion(
                     const int& dpy, const sp<Layer>& layer,
                     bool& bIgnoreLayers, String8& nameLOI,
                     uint32_t layerStack);
    virtual void delayDPTransactionIfNeeded(
                     const Vector<DisplayState>& displays);
    virtual bool canDrawLayerinScreenShot(
                     const sp<const DisplayDevice>& hw,
                     const sp<Layer>& layer);
    virtual void isfreezeSurfacePresent(
                     bool& freezeSurfacePresent,
                     const sp<const DisplayDevice>& hw,
                     const int32_t& id);
    virtual void setOrientationEventControl(
                     bool& freezeSurfacePresent,
                     const int32_t& id);
    virtual void updateVisibleRegionsDirty();
    virtual bool IsHWCDisabled() { return mDebugDisableHWC; }
    virtual ~ExSurfaceFlinger();

    /* Extended Mode
     * No video on primary but video will be shown full
     * screen on External
     */
    static bool sExtendedMode;
    static bool isExtendedMode() { return sExtendedMode; }
    bool mDebugLogs;
    bool isDebug() { return mDebugLogs; }
    bool mDisableExtAnimation;

    static bool sAllowHDRFallBack;
    static bool AllowHDRFallBack() { return sAllowHDRFallBack; }

#ifdef DEBUG_CONT_DUMPSYS
    virtual status_t dump(int fd, const Vector<String16>& args);
    virtual void dumpDrawCycle(bool prePrepare );

    struct {
      Mutex lock;
      const char *name = "/data/vendor/display/dumpsys.txt";
      bool running = false;
      bool noLimit = false;
      bool replaceAfterCommit = false;
      long int position = 0;
    } mFileDump;
#endif

};

}; //namespace android

#endif //ANDROID_EX_SURFACE_FLINGER_H
