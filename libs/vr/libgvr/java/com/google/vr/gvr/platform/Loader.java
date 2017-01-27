package com.google.vr.gvr.platform;

/**
 * Auxiliary class to load the system implementation of the GVR API.
 */
public class Loader {

  /**
   * Opens a shared library containing the system implementation for the GVR
   * API and returns the handle to it.
   *
   * @return A Long object describing the handle returned by dlopen.
   */
  public static Long loadLibrary() {
    // Note: we cannot safely do caller verifications here, so instead we do
    // them in the service side. This means that private API symbols will be
    // visible to any app adding the appropriate <uses-library> in their
    // manifest, but any requests to such APIs will fail if not done from a
    // trusted package like VrCore.
    //
    // Trusted packages are defined by (package name, signature) pairs in within
    // a system service, and both must match.

    // Load a thin JNI library that runs dlopen on request.
    System.loadLibrary("gvr_system_loader");

    // Performs dlopen on the library and returns the handle.
    return nativeLoadLibrary("libgvr_system.so");
  }

  private static native long nativeLoadLibrary(String library);
}
