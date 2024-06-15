/*
 * Copyright (C) 2023 The Android Open Source Project
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
import parcelables.SingleDataParcelable;

interface IBinderRecordReplayTest {
    void setByte(byte input);
    byte getByte();

    void setChar(char input);
    char getChar();

    void setBoolean(boolean input);
    boolean getBoolean();

    void setInt(int input);
    int getInt();

    void setFloat(float input);
    float getFloat();

    void setLong(long input);
    long getLong();

    void setDouble(double input);
    double getDouble();

    void setString(String input);
    String getString();

    void setSingleDataParcelable(in SingleDataParcelable p);
    SingleDataParcelable getSingleDataParcelable();

    void setByteArray(in byte[] input);
    byte[] getByteArray();

    void setCharArray(in char[] input);
    char[] getCharArray();

    void setBooleanArray(in boolean[] input);
    boolean[] getBooleanArray();

    void setIntArray(in int[] input);
    int[] getIntArray();

    void setFloatArray(in float[] input);
    float[] getFloatArray();

    void setLongArray(in long[] input);
    long[] getLongArray();

    void setDoubleArray(in double[] input);
    double[] getDoubleArray();

    void setStringArray(in String[] input);
    String[] getStringArray();

    void setSingleDataParcelableArray(in SingleDataParcelable[] input);
    SingleDataParcelable[] getSingleDataParcelableArray();

    void setBinder(in IBinder binder);
    IBinder getBinder();

    void setFileDescriptor(in FileDescriptor fd);
    FileDescriptor getFileDescriptor();
}
