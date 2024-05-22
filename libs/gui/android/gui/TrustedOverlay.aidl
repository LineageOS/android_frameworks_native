/**
 * Copyright (c) 2024, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.gui;


/**
  * Trusted overlay state prevents layers from being considered as obscuring for
  * input occlusion detection purposes.
  *
  * @hide
  */
@Backing(type="int")
enum TrustedOverlay {
    /**
      * The default, layer will inherit the state from its parents. If the parent state is also
      * unset, the layer will be considered as untrusted.
      */
    UNSET,

    /**
      * Treats this layer and all its children as an untrusted overlay. This will override any
      * state set by its parent layers.
      */
    DISABLED,

    /**
      * Treats this layer and all its children as a trusted overlay unless the child layer
      * explicitly disables its trusted state.
      */
    ENABLED
}
