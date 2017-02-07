package com.google.vr.gvr.platform;

import android.os.SystemProperties;

/**
 * Auxiliary class to load the system implementation of the GVR API.
 * @hide
 */
public class Loader {

    private static final String VR_MODE_BOOT = "ro.boot.vr";

    /**
     * Opens a shared library containing the system implementation for the GVR API and returns the
     * handle to it.
     *
     * @return A Long object describing the handle returned by dlopen.
     */
    public static Long loadLibrary() {
        // Note: caller verifications cannot be safely done here. Any app can find and use this API.
        // Any sensitive functions must have appropriate checks on the service side.

        // Load a thin JNI library that runs dlopen on request.
        System.loadLibrary("gvr_system_loader");

        // Performs dlopen on the library and returns the handle.
        return nativeLoadLibrary("libgvr_system.so");
    }

    /**
     * Returns true if this device boots directly in VR mode.
     */
    public static boolean getVrBoot() {
        return SystemProperties.getBoolean(VR_MODE_BOOT, false);
    }

    private static native long nativeLoadLibrary(String library);
}
