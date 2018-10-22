/* EGLDisplay eglGetPlatformDisplay ( EGLenum platform, EGLAttrib native_display, const EGLAttrib *attrib_list ) */
static jobject
android_eglGetPlatformDisplay
  (JNIEnv *_env, jobject _this, jint platform, jlong native_display, jlongArray attrib_list_ref, jint offset) {
    jint _exception = 0;
    const char * _exceptionType = NULL;
    const char * _exceptionMessage = NULL;
    EGLDisplay _returnValue = (EGLDisplay) 0;
    EGLAttrib *attrib_list_base = (EGLAttrib *) 0;
    jint _remaining;
    EGLAttrib *attrib_list = (EGLAttrib *) 0;

    if (!attrib_list_ref) {
        _exception = 1;
        _exceptionType = "java/lang/IllegalArgumentException";
        _exceptionMessage = "attrib_list == null";
        goto exit;
    }
    if (offset < 0) {
        _exception = 1;
        _exceptionType = "java/lang/IllegalArgumentException";
        _exceptionMessage = "offset < 0";
        goto exit;
    }
    _remaining = _env->GetArrayLength(attrib_list_ref) - offset;
    attrib_list_base = (EGLAttrib *)
        _env->GetLongArrayElements(attrib_list_ref, (jboolean *)0);
    attrib_list = attrib_list_base + offset;

    _returnValue = eglGetPlatformDisplay(
        (EGLenum)platform,
        (void *)native_display,
        (EGLAttrib *)attrib_list
    );

exit:
    if (attrib_list_base) {
        _env->ReleaseLongArrayElements(attrib_list_ref, (jlong*)attrib_list_base,
            JNI_ABORT);
    }
    if (_exception) {
        jniThrowException(_env, _exceptionType, _exceptionMessage);
    }
    return toEGLHandle(_env, egldisplayClass, egldisplayConstructor, _returnValue);
}

