package com.google.vr.windowmanager;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class BootCompletedReceiver extends BroadcastReceiver {
  private static final String TAG = BootCompletedReceiver.class.getSimpleName();

  @Override
  public void onReceive(Context context, Intent intent) {
    Log.i(TAG, "Starting VRWindowManager");
    Intent vrWindowManagerIntent = new Intent(context, VrWindowManagerService.class);
    context.startService(vrWindowManagerIntent);
  }
}
