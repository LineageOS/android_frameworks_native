/*
 * Copyright 2022 The Android Open Source Project
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

#include <ftl/shared_mutex.h>
#include <gtest/gtest.h>
#include <ftl/fake_guard.h>

namespace android::test {

TEST(SharedMutex, SharedLock) {
  ftl::SharedMutex mutex;
  std::shared_lock shared_lock(mutex);

  { std::shared_lock shared_lock2(mutex); }
}

TEST(SharedMutex, ExclusiveLock) {
  ftl::SharedMutex mutex;
  std::unique_lock unique_lock(mutex);
}

TEST(SharedMutex, Annotations) {
  struct {
    void foo() FTL_ATTRIBUTE(requires_shared_capability(mutex)) { num++; }
    void bar() FTL_ATTRIBUTE(requires_capability(mutex)) { num++; }
    void baz() {
      std::shared_lock shared_lock(mutex);
      num++;
    }
    ftl::SharedMutex mutex;
    int num = 0;

  } s;

  {
    // TODO(b/257958323): Use an RAII class instead of locking manually.
    s.mutex.lock_shared();
    s.foo();
    s.baz();
    s.mutex.unlock_shared();
  }
  s.mutex.lock();
  s.bar();
  s.mutex.unlock();
}

}  // namespace android::test
