    // C function EGLDisplay eglGetDisplay ( EGLNativeDisplayType display_id )

    public static native EGLDisplay eglGetDisplay(
        int display_id
    );

    /**
     * {@hide}
     */
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
    public static native EGLDisplay eglGetDisplay(
        long display_id
    );

