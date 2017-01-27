package com.google.vr.windowmanager;

import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Handler;
import android.os.IBinder;
import android.util.Log;

public class VrWindowManagerService extends Service {
  private static final String TAG = VrWindowManagerService.class.getSimpleName();
  private long nativeVrWindowManager;

  // This is a temporary debugging tool for development only.
  // It allows us to show VrWindowManager in debug mode via command line.
  private final BroadcastReceiver debugReceiver = new BroadcastReceiver() {
    @Override
    public void onReceive(Context context, Intent intent) {
      String action = intent.getAction();
      if (action.equals("com.google.vr.windowmanager.intent.SHOW")) {
        nativeEnableDebug(nativeVrWindowManager);
      } else if (action.equals("com.google.vr.windowmanager.intent.HIDE")) {
        nativeDisableDebug(nativeVrWindowManager);
      } else if (action.equals("com.google.vr.windowmanager.intent.ENTER_VR")) {
        nativeEnterVrMode(nativeVrWindowManager);
      } else if (action.equals("com.google.vr.windowmanager.intent.EXIT_VR")) {
        nativeExitVrMode(nativeVrWindowManager);
      }
    }
  };

  static {
    System.loadLibrary("vr_window_manager_jni");
  }

  @Override
  public void onCreate() {
    super.onCreate();
    destroyRenderer();
    nativeVrWindowManager = nativeCreate(getClass().getClassLoader(), getApplicationContext());
    if (nativeVrWindowManager == 0) {
      Log.e(TAG, "Failed to create native renderer");
    }

    // For development, testing and debugging.
    IntentFilter filter = new IntentFilter();
    filter.addAction("com.google.vr.windowmanager.intent.SHOW");
    filter.addAction("com.google.vr.windowmanager.intent.HIDE");
    filter.addAction("com.google.vr.windowmanager.intent.ENTER_VR");
    filter.addAction("com.google.vr.windowmanager.intent.EXIT_VR");
    registerReceiver(debugReceiver, filter);
  }

  @Override
  public int onStartCommand(Intent intent, int flags, int startId) {
    return START_STICKY;
  }

  @Override
  public IBinder onBind(Intent intent) {
    Log.i(TAG, "Ignoring bind request");
    return null;
  }

  @Override
  public void onDestroy() {
    super.onDestroy();
    unregisterReceiver(debugReceiver);
    destroyRenderer();
  }

  private void destroyRenderer() {
    if (nativeVrWindowManager != 0) {
      nativeDestroy(nativeVrWindowManager);
      nativeVrWindowManager = 0;
    }
  }

  private native long nativeCreate(ClassLoader appClassLoader, Context context);
  private native void nativeDestroy(long nativeVrWindowManager);
  private native void nativeEnableDebug(long nativeVrWindowManager);
  private native void nativeDisableDebug(long nativeVrWindowManager);
  private native void nativeEnterVrMode(long nativeVrWindowManager);
  private native void nativeExitVrMode(long nativeVrWindowManager);
}
