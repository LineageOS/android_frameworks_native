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
    external fun stringFromJNI()
    external fun testBufferQueueCreation()

    companion object {
        fun companion_stringFromJNI() {
            val instance = BufferStreamJNI()
            instance.stringFromJNI()
        }

        fun companion_testBufferQueueCreation() {
            val instance = BufferStreamJNI()
            instance.testBufferQueueCreation()
        }
    }
}