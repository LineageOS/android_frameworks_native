/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef _UI_INPUT_INPUTDISPATCHER_QUEUE_H
#define _UI_INPUT_INPUTDISPATCHER_QUEUE_H

namespace android::inputdispatcher {

// Generic queue implementation.
template <typename T>
struct Queue {
    T* head;
    T* tail;
    uint32_t entryCount;

    inline Queue() : head(nullptr), tail(nullptr), entryCount(0) {}

    inline bool isEmpty() const { return !head; }

    inline void enqueueAtTail(T* entry) {
        entryCount++;
        entry->prev = tail;
        if (tail) {
            tail->next = entry;
        } else {
            head = entry;
        }
        entry->next = nullptr;
        tail = entry;
    }

    inline void enqueueAtHead(T* entry) {
        entryCount++;
        entry->next = head;
        if (head) {
            head->prev = entry;
        } else {
            tail = entry;
        }
        entry->prev = nullptr;
        head = entry;
    }

    inline void dequeue(T* entry) {
        entryCount--;
        if (entry->prev) {
            entry->prev->next = entry->next;
        } else {
            head = entry->next;
        }
        if (entry->next) {
            entry->next->prev = entry->prev;
        } else {
            tail = entry->prev;
        }
    }

    inline T* dequeueAtHead() {
        entryCount--;
        T* entry = head;
        head = entry->next;
        if (head) {
            head->prev = nullptr;
        } else {
            tail = nullptr;
        }
        return entry;
    }

    uint32_t count() const { return entryCount; }
};

} // namespace android::inputdispatcher

#endif // _UI_INPUT_INPUTDISPATCHER_QUEUE_H
