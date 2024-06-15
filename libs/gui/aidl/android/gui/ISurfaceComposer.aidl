/*
 * Copyright 2021 The Android Open Source Project
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

package android.gui;

import android.gui.CaptureArgs;
import android.gui.Color;
import android.gui.CompositionPreference;
import android.gui.ContentSamplingAttributes;
import android.gui.DisplayBrightness;
import android.gui.DisplayCaptureArgs;
import android.gui.DisplayDecorationSupport;
import android.gui.DisplayedFrameStats;
import android.gui.DisplayModeSpecs;
import android.gui.DisplayPrimaries;
import android.gui.DisplayState;
import android.gui.DisplayStatInfo;
import android.gui.DynamicDisplayInfo;
import android.gui.FrameEvent;
import android.gui.FrameStats;
import android.gui.HdrConversionCapability;
import android.gui.HdrConversionStrategy;
import android.gui.IDisplayEventConnection;
import android.gui.IFpsListener;
import android.gui.IHdrLayerInfoListener;
import android.gui.IRegionSamplingListener;
import android.gui.IScreenCaptureListener;
import android.gui.ISurfaceComposerClient;
import android.gui.ITunnelModeEnabledListener;
import android.gui.IWindowInfosListener;
import android.gui.IWindowInfosPublisher;
import android.gui.LayerCaptureArgs;
import android.gui.LayerDebugInfo;
import android.gui.OverlayProperties;
import android.gui.PullAtomData;
import android.gui.ScreenCaptureResults;
import android.gui.ARect;
import android.gui.SchedulingPolicy;
import android.gui.StalledTransactionInfo;
import android.gui.StaticDisplayInfo;
import android.gui.WindowInfosListenerInfo;

/** @hide */
interface ISurfaceComposer {

    enum VsyncSource {
        eVsyncSourceApp = 0,
        eVsyncSourceSurfaceFlinger = 1
    }

    enum EventRegistration {
        modeChanged = 1 << 0,
        frameRateOverride = 1 << 1,
    }

    /**
     * Signal that we're done booting.
     * Requires ACCESS_SURFACE_FLINGER permission
     */
    void bootFinished();

    /**
     * Create a display event connection
     *
     * layerHandle
     *     Optional binder handle representing a Layer in SF to associate the new
     *     DisplayEventConnection with. This handle can be found inside a surface control after
     *     surface creation, see ISurfaceComposerClient::createSurface. Set to null if no layer
     *     association should be made.
     */
    @nullable IDisplayEventConnection createDisplayEventConnection(VsyncSource vsyncSource,
            EventRegistration eventRegistration, @nullable IBinder layerHandle);

    /**
     * Create a connection with SurfaceFlinger.
     */
    @nullable ISurfaceComposerClient createConnection();

    /**
     * Create a virtual display
     *
     * displayName
     *     The name of the virtual display
     * secure
     *     Whether this virtual display is secure
     * requestedRefreshRate
     *     The refresh rate, frames per second, to request on the virtual display.
     *     This is just a request, the actual rate may be adjusted to align well
     *     with physical displays running concurrently. If 0 is specified, the
     *     virtual display is refreshed at the physical display refresh rate.
     *
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    @nullable IBinder createDisplay(@utf8InCpp String displayName, boolean secure,
            float requestedRefreshRate);

    /**
     * Destroy a virtual display
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    void destroyDisplay(IBinder display);

    /**
     * Get stable IDs for connected physical displays.
     */
    long[] getPhysicalDisplayIds();

    /**
     * Get token for a physical display given its stable ID obtained via getPhysicalDisplayIds or
     * a DisplayEventReceiver hotplug event.
     */
    @nullable IBinder getPhysicalDisplayToken(long displayId);

    /**
     * Returns the frame timestamps supported by SurfaceFlinger.
     */
    FrameEvent[] getSupportedFrameTimestamps();

    /**
     * Set display power mode. depending on the mode, it can either trigger
     * screen on, off or low power mode and wait for it to complete.
     * requires ACCESS_SURFACE_FLINGER permission.
     */
    void setPowerMode(IBinder display, int mode);

    /**
     * Returns display statistics for a given display
     * intended to be used by the media framework to properly schedule
     * video frames */
    DisplayStatInfo getDisplayStats(@nullable IBinder display);

    /**
     * Get transactional state of given display.
     */
    DisplayState getDisplayState(IBinder display);

    /**
     * Gets immutable information about given physical display.
     */
    StaticDisplayInfo getStaticDisplayInfo(long displayId);

    /**
     * Gets dynamic information about given physical display.
     */
    DynamicDisplayInfo getDynamicDisplayInfoFromId(long displayId);

    DynamicDisplayInfo getDynamicDisplayInfoFromToken(IBinder display);

    DisplayPrimaries getDisplayNativePrimaries(IBinder display);

    void setActiveColorMode(IBinder display, int colorMode);

    /**
     * Sets the user-preferred display mode that a device should boot in.
     */
    void setBootDisplayMode(IBinder display, int displayModeId);

    /**
     * Clears the user-preferred display mode. The device should now boot in system preferred
     * display mode.
     */
    void clearBootDisplayMode(IBinder display);

    /**
     * Gets whether boot time display mode operations are supported on the device.
     *
     * outSupport
     *      An output parameter for whether boot time display mode operations are supported.
     *
     * Returns NO_ERROR upon success. Otherwise,
     *      NAME_NOT_FOUND if the display is invalid, or
     *      BAD_VALUE      if the output parameter is invalid.
     */
    // TODO(b/213909104) : Add unit tests to verify surface flinger boot time APIs
    boolean getBootDisplayModeSupport();

    /**
     * Gets the HDR conversion capabilities of the device. The conversion capability defines whether
     * conversion from sourceType to outputType is possible (with or without latency).
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
     List<HdrConversionCapability> getHdrConversionCapabilities();

     /**
      * Sets the HDR conversion strategy of the device.
      * Returns the preferred HDR output type of the device, in case when HdrConversionStrategy has
      * autoAllowedHdrTypes set. Returns Hdr::INVALID in other cases.
      *
      * Requires the ACCESS_SURFACE_FLINGER permission.
      */
     int setHdrConversionStrategy(in HdrConversionStrategy hdrConversionStrategy);

     /**
      * Gets whether HDR output conversion operations are supported on the device.
      */
     boolean getHdrOutputConversionSupport();

    /**
     * Switches Auto Low Latency Mode on/off on the connected display, if it is
     * available. This should only be called if the display supports Auto Low
     * Latency Mode as reported in #getDynamicDisplayInfo.
     * For more information, see the HDMI 2.1 specification.
     */
    void setAutoLowLatencyMode(IBinder display, boolean on);

    /**
     * This will start sending infoframes to the connected display with
     * ContentType=Game (if on=true). This should only be called if the display
     * Game Content Type as reported in #getDynamicDisplayInfo.
     * For more information, see the HDMI 1.4 specification.
     */
    void setGameContentType(IBinder display, boolean on);

    /**
     * Capture the specified screen. This requires READ_FRAME_BUFFER
     * permission.  This function will fail if there is a secure window on
     * screen and DisplayCaptureArgs.captureSecureLayers is false.
     *
     * This function can capture a subregion (the source crop) of the screen.
     * The subregion can be optionally rotated.  It will also be scaled to
     * match the size of the output buffer.
     */
    oneway void captureDisplay(in DisplayCaptureArgs args, IScreenCaptureListener listener);

    /**
     * Capture the specified screen. This requires the READ_FRAME_BUFFER
     * permission.
     */
    oneway void captureDisplayById(long displayId, in CaptureArgs args,
            IScreenCaptureListener listener);

    /**
     * Capture a subtree of the layer hierarchy, potentially ignoring the root node.
     * This requires READ_FRAME_BUFFER permission. This function will fail if there
     * is a secure window on screen. This is a blocking call and will return the
     * ScreenCaptureResults, including the captured buffer. Because this is blocking, the
     * caller doesn't care about the fence and the binder thread in SurfaceFlinger will wait
     * on the fence to fire before returning the results.
     */
    ScreenCaptureResults captureLayersSync(in LayerCaptureArgs args);

    /**
     * Capture a subtree of the layer hierarchy, potentially ignoring the root node.
     * This requires READ_FRAME_BUFFER permission. This function will fail if there
     * is a secure window on screen
     */
    oneway void captureLayers(in LayerCaptureArgs args, IScreenCaptureListener listener);

    /**
     * Clears the frame statistics for animations.
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    void clearAnimationFrameStats();

    /**
     * Gets the frame statistics for animations.
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    FrameStats getAnimationFrameStats();

    /**
     * Overrides the supported HDR modes for the given display device.
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    void overrideHdrTypes(IBinder display, in int[] hdrTypes);

    /**
     * Pulls surfaceflinger atoms global stats and layer stats to pipe to statsd.
     *
     * Requires the calling uid be from system server.
     */
    PullAtomData onPullAtom(int atomId);

    /**
     * Gets the list of active layers in Z order for debugging purposes
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    List<LayerDebugInfo> getLayerDebugInfo();

    /**
     * Gets the composition preference of the default data space and default pixel format,
     * as well as the wide color gamut data space and wide color gamut pixel format.
     * If the wide color gamut data space is V0_SRGB, then it implies that the platform
     * has no wide color gamut support.
     *
     */
    CompositionPreference getCompositionPreference();

    /**
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    ContentSamplingAttributes getDisplayedContentSamplingAttributes(IBinder display);

    /**
     * Turns on the color sampling engine on the display.
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    void setDisplayContentSamplingEnabled(IBinder display, boolean enable, byte componentMask, long maxFrames);

    /**
     * Returns statistics on the color profile of the last frame displayed for a given display
     *
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    DisplayedFrameStats getDisplayedContentSample(IBinder display, long maxFrames, long timestamp);

    /**
     * Gets whether SurfaceFlinger can support protected content in GPU composition.
     */
    boolean getProtectedContentSupport();

    /**
     * Queries whether the given display is a wide color display.
     * Requires the ACCESS_SURFACE_FLINGER permission.
     */
    boolean isWideColorDisplay(IBinder token);

    /**
     * Registers a listener to stream median luma updates from SurfaceFlinger.
     *
     * The sampling area is bounded by both samplingArea and the given stopLayerHandle
     * (i.e., only layers behind the stop layer will be captured and sampled).
     *
     * Multiple listeners may be provided so long as they have independent listeners.
     * If multiple listeners are provided, the effective sampling region for each listener will
     * be bounded by whichever stop layer has a lower Z value.
     *
     * Requires the same permissions as captureLayers and captureScreen.
     */
    void addRegionSamplingListener(in ARect samplingArea, @nullable IBinder stopLayerHandle, IRegionSamplingListener listener);

    /**
     * Removes a listener that was streaming median luma updates from SurfaceFlinger.
     */
    void removeRegionSamplingListener(IRegionSamplingListener listener);

    /**
     * Registers a listener that streams fps updates from SurfaceFlinger.
     *
     * The listener will stream fps updates for the layer tree rooted at the layer denoted by the
     * task ID, i.e., the layer must have the task ID as part of its layer metadata with key
     * METADATA_TASK_ID. If there is no such layer, then no fps is expected to be reported.
     *
     * Multiple listeners may be supported.
     *
     * Requires the READ_FRAME_BUFFER permission.
     */
    void addFpsListener(int taskId, IFpsListener listener);

    /**
     * Removes a listener that was streaming fps updates from SurfaceFlinger.
     */
    void removeFpsListener(IFpsListener listener);

    /**
     * Registers a listener to receive tunnel mode enabled updates from SurfaceFlinger.
     *
     * Requires ACCESS_SURFACE_FLINGER permission.
     */
    void addTunnelModeEnabledListener(ITunnelModeEnabledListener listener);

    /**
     * Removes a listener that was receiving tunnel mode enabled updates from SurfaceFlinger.
     *
     * Requires ACCESS_SURFACE_FLINGER permission.
     */
    void removeTunnelModeEnabledListener(ITunnelModeEnabledListener listener);

    /**
     * Sets the refresh rate boundaries for the display.
     *
     * @see DisplayModeSpecs.aidl for details.
     */
    void setDesiredDisplayModeSpecs(IBinder displayToken, in DisplayModeSpecs specs);

    DisplayModeSpecs getDesiredDisplayModeSpecs(IBinder displayToken);

    /**
     * Gets whether brightness operations are supported on a display.
     *
     * displayToken
     *      The token of the display.
     * outSupport
     *      An output parameter for whether brightness operations are supported.
     *
     * Returns NO_ERROR upon success. Otherwise,
     *      NAME_NOT_FOUND if the display is invalid, or
     *      BAD_VALUE      if the output parameter is invalid.
     */
    boolean getDisplayBrightnessSupport(IBinder displayToken);

    /**
     * Sets the brightness of a display.
     *
     * displayToken
     *      The token of the display whose brightness is set.
     * brightness
     *      The DisplayBrightness info to set on the desired display.
     *
     * Returns NO_ERROR upon success. Otherwise,
     *      NAME_NOT_FOUND    if the display is invalid, or
     *      BAD_VALUE         if the brightness is invalid, or
     *      INVALID_OPERATION if brightness operations are not supported.
     */
    void setDisplayBrightness(IBinder displayToken, in DisplayBrightness brightness);

    /**
     * Adds a listener that receives HDR layer information. This is used in combination
     * with setDisplayBrightness to adjust the display brightness depending on factors such
     * as whether or not HDR is in use.
     *
     * Returns NO_ERROR upon success or NAME_NOT_FOUND if the display is invalid.
     */
    void addHdrLayerInfoListener(IBinder displayToken, IHdrLayerInfoListener listener);

    /**
     * Removes a listener that was added with addHdrLayerInfoListener.
     *
     * Returns NO_ERROR upon success, NAME_NOT_FOUND if the display is invalid, and BAD_VALUE if
     *     the listener wasn't registered.
     *
     */
    void removeHdrLayerInfoListener(IBinder displayToken, IHdrLayerInfoListener listener);

    /**
     * Sends a power boost to the composer. This function is asynchronous.
     *
     * boostId
     *      boost id according to android::hardware::power::Boost
     *
     * Returns NO_ERROR upon success.
     */
    oneway void notifyPowerBoost(int boostId);

    /*
     * Sets the global configuration for all the shadows drawn by SurfaceFlinger. Shadow follows
     * material design guidelines.
     *
     * ambientColor
     *      Color to the ambient shadow. The alpha is premultiplied.
     *
     * spotColor
     *      Color to the spot shadow. The alpha is premultiplied. The position of the spot shadow
     *      depends on the light position.
     *
     * lightPosY/lightPosZ
     *      Position of the light used to cast the spot shadow. The X value is always the display
     *      width / 2.
     *
     * lightRadius
     *      Radius of the light casting the shadow.
     */
    oneway void setGlobalShadowSettings(in Color ambientColor, in Color spotColor, float lightPosY, float lightPosZ, float lightRadius);

    /**
     * Gets whether a display supports DISPLAY_DECORATION layers.
     *
     * displayToken
     *      The token of the display.
     * outSupport
     *      An output parameter for whether/how the display supports
     *      DISPLAY_DECORATION layers.
     *
     * Returns NO_ERROR upon success. Otherwise,
     *      NAME_NOT_FOUND if the display is invalid, or
     *      BAD_VALUE      if the output parameter is invalid.
     */
    @nullable DisplayDecorationSupport getDisplayDecorationSupport(IBinder displayToken);

    /**
     * Set the override frame rate for a specified uid by GameManagerService.
     * This override is controlled by game mode interventions.
     * Passing the frame rate and uid to SurfaceFlinger to update the override mapping
     * in the LayerHistory.
     */
    void setGameModeFrameRateOverride(int uid, float frameRate);

    /**
     * Set the override frame rate for a specified uid by GameManagerService.
     * This override is controlled by game default frame rate sysprop:
     * "ro.surface_flinger.game_default_frame_rate_override" holding the override value,
     * "persisit.graphics.game_default_frame_rate.enabled" to determine if it's enabled.
     * Passing the frame rate and uid to SurfaceFlinger to update the override mapping
     * in the scheduler.
     */
    void setGameDefaultFrameRateOverride(int uid, float frameRate);

    oneway void updateSmallAreaDetection(in int[] appIds, in float[] thresholds);

    /**
     * Set the small area detection threshold for a specified appId by SmallAreaDetectionController.
     * Passing the threshold and appId to SurfaceFlinger to update the appId-threshold mapping
     * in the scheduler.
     */
    oneway void setSmallAreaDetectionThreshold(int appId, float threshold);

    /**
     * Enables or disables the frame rate overlay in the top left corner.
     * Requires root or android.permission.HARDWARE_TEST
     */
    void enableRefreshRateOverlay(boolean active);

    /**
     * Enables or disables the debug flash.
     * Requires root or android.permission.HARDWARE_TEST
     */
    void setDebugFlash(int delay);

    /**
     * Force composite ahead of next VSYNC.
     * Requires root or android.permission.HARDWARE_TEST
     */
    void scheduleComposite();

    /**
     * Force commit ahead of next VSYNC.
     * Requires root or android.permission.HARDWARE_TEST
     */
    void scheduleCommit();

    /**
     * Force all window composition to the GPU (i.e. disable Hardware Overlays).
     * This can help check if there is a bug in HW Composer.
     * Requires root or android.permission.HARDWARE_TEST
     */
    void forceClientComposition(boolean enabled);

    /**
     * Gets priority of the RenderEngine in SurfaceFlinger.
     */
    int getGpuContextPriority();

    /**
     * Gets the number of buffers SurfaceFlinger would need acquire. This number
     * would be propagated to the client via MIN_UNDEQUEUED_BUFFERS so that the
     * client could allocate enough buffers to match SF expectations of the
     * pipeline depth. SurfaceFlinger will make sure that it will give the app at
     * least the time configured as the 'appDuration' before trying to latch
     * the buffer.
     *
     * The total buffers needed for a given configuration is basically the
     * numbers of vsyncs a single buffer is used across the stack. For the default
     * configuration a buffer is held ~1 vsync by the app, ~1 vsync by SurfaceFlinger
     * and 1 vsync by the display. The extra buffers are calculated as the
     * number of additional buffers on top of the 2 buffers already present
     * in MIN_UNDEQUEUED_BUFFERS.
     */
    int getMaxAcquiredBufferCount();

    WindowInfosListenerInfo addWindowInfosListener(IWindowInfosListener windowInfosListener);

    void removeWindowInfosListener(IWindowInfosListener windowInfosListener);

    OverlayProperties getOverlaySupport();

    /**
     * Returns an instance of StalledTransaction if a transaction from the passed pid has not been
     * applied in SurfaceFlinger due to an unsignaled fence. Otherwise, null is returned.
     */
    @nullable StalledTransactionInfo getStalledTransactionInfo(int pid);

    SchedulingPolicy getSchedulingPolicy();
}
