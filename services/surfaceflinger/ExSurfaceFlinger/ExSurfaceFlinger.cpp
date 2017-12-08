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

#include "ExSurfaceFlinger.h"
#include "ExLayer.h"
#include <fstream>
#include <cutils/properties.h>
#include <ui/GraphicBufferAllocator.h>
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

namespace android {

bool ExSurfaceFlinger::sExtendedMode = false;
bool ExSurfaceFlinger::sAllowHDRFallBack = false;

ExSurfaceFlinger::ExSurfaceFlinger() {
    char property[PROPERTY_VALUE_MAX] = {0};

    mDebugLogs = false;
    if ((property_get("persist.debug.qdframework.logs", property, NULL) > 0) &&
        (!strncmp(property, "1", PROPERTY_VALUE_MAX ) ||
         (!strncasecmp(property,"true", PROPERTY_VALUE_MAX )))) {
        mDebugLogs = true;
    }

    ALOGD_IF(isDebug(),"Creating custom SurfaceFlinger %s",__FUNCTION__);

    mDisableExtAnimation = false;
    if ((property_get("sys.disable_ext_animation", property, "0") > 0) &&
        (!strncmp(property, "1", PROPERTY_VALUE_MAX ) ||
         (!strncasecmp(property,"true", PROPERTY_VALUE_MAX )))) {
        mDisableExtAnimation = true;
    }

    ALOGD_IF(isDebug(),"Animation on external is %s in %s",
             mDisableExtAnimation ? "disabled" : "not disabled", __FUNCTION__);

    if((property_get("sys.hwc_disable_hdr", property, "0") > 0) &&
       (!strncmp(property, "1", PROPERTY_VALUE_MAX ) ||
        (!strncasecmp(property,"true", PROPERTY_VALUE_MAX )))) {
        sAllowHDRFallBack = true;
    }
}

ExSurfaceFlinger::~ExSurfaceFlinger() { }

void ExSurfaceFlinger::updateExtendedMode() {
    char prop[PROPERTY_VALUE_MAX];
    property_get("sys.extended_mode", prop, "0");
    sExtendedMode = atoi(prop) ? true : false;
}

void ExSurfaceFlinger::getIndexLOI(size_t dpy,
                               bool& bIgnoreLayers,
                               String8& nameLOI ) {
    mDrawingState.traverseInReverseZOrder([&](Layer* layer) {
        /* iterate through the layer list to find ext_only layers and store
         * the index
         */
        if (layer->isSecureDisplay()) {
            bIgnoreLayers = true;
            nameLOI = static_cast<String8>("unnamed");
            if (!dpy)
                nameLOI = layer->getName();
            return;
        }
        /* iterate through the layer list to find ext_only layers or yuv
         * layer(extended_mode) and store the index
         */
        if (dpy && (layer->isExtOnly() ||
                     (isExtendedMode() && layer->isYuvLayer()))) {
            bIgnoreLayers= true;
            nameLOI = layer->getName();
        }
    });
}

bool ExSurfaceFlinger::updateLayerVisibleNonTransparentRegion(
        const int& dpy, const sp<Layer>& layer,
        bool& bIgnoreLayers, String8& nameLOI,
        uint32_t layerStack) {

    /* Only add the layer marked as "external_only" or yuvLayer
     * (extended_mode) to external list and
     * only remove the layer marked as "external_only" or yuvLayer in
     * extended_mode from primary list
     * and do not add the layer marked as "internal_only" to external list
     * Add secure UI layers to primary and remove other layers from internal
     * and external list
     */
    if (((bIgnoreLayers && strcmp(nameLOI, layer->getName())) ||
         (!dpy && layer->isExtOnly()) ||
         (!dpy && isExtendedMode() && layer->isYuvLayer()))||
        (dpy && layer->isIntOnly())) {
        /* Ignore all other layers except the layers marked as ext_only
         * by setting visible non transparent region empty
         */
        Region visibleNonTransRegion;
        visibleNonTransRegion.set(Rect(0,0));
        layer->setVisibleNonTransparentRegion(visibleNonTransRegion);
        return true;
    }
    /* only consider the layers on the given later stack
     * Override layers created using presentation class by the layers having
     * ext_only flag enabled
     */
    if (layer->getLayerStack() != layerStack && !bIgnoreLayers) {
        /* set the visible region as empty since we have removed the
         * layerstack check in rebuildLayerStack() function
         */
        Region visibleNonTransRegion;
        visibleNonTransRegion.set(Rect(0,0));
        layer->setVisibleNonTransparentRegion(visibleNonTransRegion);
        return true;
    }

    if (mDisableExtAnimation) {
        /* Remove screenShotSurface from secondary displays when ext animation disabled */
        const int screenShotLen = strlen("ScreenshotSurface");
        if (dpy && !strncmp(layer->getName(), "ScreenshotSurface", screenShotLen) ) {
            Region visibleNonTransRegion;
            visibleNonTransRegion.set(Rect(0, 0));
            layer->setVisibleNonTransparentRegion(visibleNonTransRegion);
            return true;
        }
    }

    return false;
}

void ExSurfaceFlinger::delayDPTransactionIfNeeded(
        const Vector<DisplayState>& displays) {
    /* Delay the display projection transaction by 50ms only when the disable
     * external rotation animation feature is enabled
     */
    if (mDisableExtAnimation) {
        size_t count = displays.size();
        for (size_t i=0 ; i<count ; i++) {
            const DisplayState& s(displays[i]);
            if ((mDisplays.indexOfKey(s.token) >= 0) && (s.token !=
                    mBuiltinDisplays[DisplayDevice::DISPLAY_PRIMARY])) {
                const uint32_t what = s.what;
                /* Invalidate and Delay the binder thread by 50 ms on
                 * eDisplayProjectionChanged to trigger a draw cycle so that
                 * it can fix one incorrect frame on the External, when we
                 * disable external animation
                 */
                if (what & DisplayState::eDisplayProjectionChanged) {
                    invalidateHwcGeometry();
                    repaintEverything();
                    usleep(50000);
                }
            }
        }
    }
}

bool ExSurfaceFlinger::canDrawLayerinScreenShot(
                             const sp<const DisplayDevice>& hw,
                             const sp<Layer>& layer) {
    int dispType = hw->getDisplayType();
    /* a) Don't draw SecureDisplayLayer or ProtectedLayer.
     * b) Don't let ext_only and extended_mode to be captured
     * If not, we would see incorrect image during rotation
     * on primary.
     */
    if (!layer->isSecureDisplay()
        && !layer->isProtected()
        && !(!dispType && (layer->isExtOnly() ||
          (isExtendedMode() && layer->isYuvLayer())))
        && !(layer->isIntOnly() && dispType)
        && layer->isVisible()) {
         return true;
    }
    return false;
}

void ExSurfaceFlinger::isfreezeSurfacePresent(bool& freezeSurfacePresent,
                             const sp<const DisplayDevice>& hw,
                             const int32_t& id) {
    freezeSurfacePresent = false;
    /* Look for ScreenShotSurface in external layer list, only when
     * disable external rotation animation feature is enabled
     */
    if (mDisableExtAnimation && (id != HWC_DISPLAY_PRIMARY)) {
    /* Get the layers in the current drawing state */
        mDrawingState.traverseInZOrder([&](Layer* layer) {
            static int screenShotLen = strlen("ScreenshotSurface");
            /* check the layers associated with external display */
            if (layer->getLayerStack() == hw->getLayerStack()) {
                if (!strncmp(layer->getName(), "ScreenshotSurface",
                            screenShotLen)) {
                    /* Screenshot layer is present, and animation in
                     * progress
                     */
                    freezeSurfacePresent = true;
                    return;
                }
            }
        });
    }
}

// TODO: setOrientationEventControl will not work bcoz of setAnimating .
#ifndef USE_HWC2
void ExSurfaceFlinger::setOrientationEventControl(bool& freezeSurfacePresent,
                             const int32_t& id) {
    HWComposer& hwc(getHwComposer());
    HWComposer::LayerListIterator cur = hwc.begin(id);

    if (freezeSurfacePresent) {
        /* If freezeSurfacePresent, set ANIMATING flag
         * which is used to support disable animation on external
         */
// TODO: setAnimating will not work because of display-defs.h file is not defined .
#if 0
        cur->setAnimating(true);
#endif
    }
}
#else
void ExSurfaceFlinger::setOrientationEventControl(bool& freezeSurfacePresent,
                             const int32_t& dpy) {
    if (!freezeSurfacePresent)
        return;

    sp<const DisplayDevice> displayDevice(mDisplays[dpy]);
    const Vector<sp<Layer>>& currentLayers(
                            displayDevice->getVisibleLayersSortedByZ());
    const auto hwcId = displayDevice->getHwcDisplayId();
    for (auto& layer : currentLayers) {
        layer->setLayerAnimating(hwcId);
    }
}
#endif

void ExSurfaceFlinger::updateVisibleRegionsDirty() {
    /* If extended_mode is set, and set mVisibleRegionsDirty
     * as we need to rebuildLayerStack
     */
    if (isExtendedMode()) {
        mVisibleRegionsDirty = true;
    }
}

#ifdef DEBUG_CONT_DUMPSYS
status_t ExSurfaceFlinger::dump(int fd, const Vector<String16>& args) {
    // Format: adb shell dumpsys SurfaceFlinger --file --no-limit
    size_t numArgs = args.size();
    status_t err = NO_ERROR;

    if (!numArgs || ((args[0] != String16("--file")) &&
       (args[0] != String16("--allocated_buffers")))) {
        return SurfaceFlinger::dump(fd, args);
    }

    if (args[0] == String16("--allocated_buffers")) {
        String8 dumpsys;
        GraphicBufferAllocator& alloc(GraphicBufferAllocator::get());
        alloc.dump(dumpsys);
        write(fd, dumpsys.string(), dumpsys.size());
        return NO_ERROR;
    }

    Mutex::Autolock _l(mFileDump.lock);

    // Same command is used to start and end dump.
    mFileDump.running = !mFileDump.running;

    if (mFileDump.running) {
        // Create an empty file or erase existing file.
        std::fstream fs;
        fs.open(mFileDump.name, std::ios::out);
        if (!fs) {
            mFileDump.running = false;
            err = UNKNOWN_ERROR;
        } else {
            mFileDump.position = 0;
            if (numArgs >= 2 && (args[1] == String16("--nolimit"))) {
                mFileDump.noLimit = true;
            } else {
                mFileDump.noLimit = false;
            }
        }
    }

    String8 result;
    result += mFileDump.running ? "Start" : "End";
    result += mFileDump.noLimit ? " unlimited" : " fixed limit";
    result += " dumpsys to file : ";
    result += mFileDump.name;
    result += "\n";

    write(fd, result.string(), result.size());

    return NO_ERROR;
}

void ExSurfaceFlinger::dumpDrawCycle(bool prePrepare) {
    Mutex::Autolock _l(mFileDump.lock);

    // User might stop dump collection in middle of prepare & commit.
    // Collect dumpsys again after commit and replace.
    if (!mFileDump.running && !mFileDump.replaceAfterCommit) {
        return;
    }

    Vector<String16> args;
    size_t index = 0;
    String8 dumpsys;

    dumpAllLocked(args, index, dumpsys);

    char timeStamp[32];
    char dataSize[32];
    char hms[32];
    long millis;
    struct timeval tv;
    struct tm *ptm;

    gettimeofday(&tv, NULL);
    ptm = localtime(&tv.tv_sec);
    strftime (hms, sizeof (hms), "%H:%M:%S", ptm);
    millis = tv.tv_usec / 1000;
    snprintf(timeStamp, sizeof(timeStamp), "Timestamp: %s.%03ld", hms, millis);
    snprintf(dataSize, sizeof(dataSize), "Size: %8zu", dumpsys.size());

    std::fstream fs;
    fs.open(mFileDump.name, std::ios::in | std::ios::out);
    if (!fs) {
        ALOGE("Failed to open %s file for dumpsys", mFileDump.name);
        return;
    }

    // Format:
    //    | start code | after commit? | time stamp | dump size | dump data |
    fs.seekp(mFileDump.position, std::ios::beg);

    fs << "#@#@-- DUMPSYS START --@#@#" << std::endl;
    fs << "PostCommit: " << ( prePrepare ? "false" : "true" ) << std::endl;
    fs << timeStamp << std::endl;
    fs << dataSize << std::endl;
    fs << dumpsys << std::endl;

    if (prePrepare) {
        mFileDump.replaceAfterCommit = true;
    } else {
        mFileDump.replaceAfterCommit = false;
        // Reposition only after commit.
        // Keep file size to appx 20 MB limit by default, wrap around if exceeds.
        mFileDump.position = fs.tellp();
        if (!mFileDump.noLimit && (mFileDump.position > (20 * 1024 * 1024))) {
            mFileDump.position = 0;
        }
    }

    fs.close();
}
#endif

}; // namespace android
