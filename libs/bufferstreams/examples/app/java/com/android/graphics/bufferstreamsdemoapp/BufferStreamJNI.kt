package com.android.graphics.bufferstreamsdemoapp

class BufferStreamJNI {
    // Used to load the 'bufferstreamsdemoapp' library on application startup.
    init {
        System.loadLibrary("bufferstreamdemoapp")
    }

    /**
     * A native method that is implemented by the 'bufferstreamsdemoapp' native library, which is
     * packaged with this application.
     */
    external fun stringFromJNI(): String;
    external fun testBufferQueueCreation();

    companion object {
        fun companion_stringFromJNI(): String {
            val instance = BufferStreamJNI()
            return instance.stringFromJNI()
        }

        fun companion_testBufferQueueCreation() {
            val instance = BufferStreamJNI()
            return instance.testBufferQueueCreation()
        }
    }
}