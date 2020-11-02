/*
 * Copyright 2020 The Android Open Source Project
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
// Authors: corbin.souffrant@leviathansecurity.com
//          brian.balling@leviathansecurity.com

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <fuzzer/FuzzedDataProvider.h>
#include <pdx/rpc/argument_encoder.h>
#include <pdx/rpc/array_wrapper.h>
#include <pdx/rpc/default_initialization_allocator.h>
#include <pdx/rpc/payload.h>
#include <pdx/rpc/serializable.h>
#include <pdx/rpc/serialization.h>
#include <pdx/rpc/string_wrapper.h>
#include <pdx/utility.h>

using namespace android::pdx;
using namespace android::pdx::rpc;

struct FuzzType {
  int a;
  float b;
  std::string c;

  FuzzType() {}
  FuzzType(int a, float b, const std::string& c) : a(a), b(b), c(c) {}

 private:
  PDX_SERIALIZABLE_MEMBERS(FuzzType, a, b, c);
};

// Fuzzer for Serialization operations, this is mostly just lifted from the
// existing test cases to use fuzzed values as inputs.
void FuzzSerializeDeserialize(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload result;

  // Currently, only fuzzing subset of types. In the future, may want
  // to add more difficult to generate types like array, map, enum, etc...
  bool b_val = fdp.ConsumeBool();
  uint8_t u8_val = fdp.ConsumeIntegral<uint8_t>();
  uint16_t u16_val = fdp.ConsumeIntegral<uint16_t>();
  uint32_t u32_val = fdp.ConsumeIntegral<uint32_t>();
  uint64_t u64_val = fdp.ConsumeIntegral<uint64_t>();
  int8_t i8_val = fdp.ConsumeIntegral<int8_t>();
  int16_t i16_val = fdp.ConsumeIntegral<uint16_t>();
  int32_t i32_val = fdp.ConsumeIntegral<uint32_t>();
  int64_t i64_val = fdp.ConsumeIntegral<uint64_t>();
  float f_val = fdp.ConsumeFloatingPoint<float>();
  double d_val = fdp.ConsumeFloatingPoint<double>();
  std::string s_val = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
  std::vector<uint8_t> vec_val =
      fdp.ConsumeBytes<uint8_t>(fdp.remaining_bytes());
  FuzzType t1_val{reinterpret_cast<int>(i32_val), f_val, s_val};

  // Types need to be individually fuzzed because code path changes depending
  // on which type is being serialized/deserialized.
  Serialize(b_val, &result);
  Deserialize(&b_val, &result);
  Serialize(u8_val, &result);
  Deserialize(&u8_val, &result);
  Serialize(u16_val, &result);
  Deserialize(&u16_val, &result);
  Serialize(u32_val, &result);
  Deserialize(&u32_val, &result);
  Serialize(u64_val, &result);
  Deserialize(&u64_val, &result);
  Serialize(i8_val, &result);
  Deserialize(&i8_val, &result);
  Serialize(i16_val, &result);
  Deserialize(&i16_val, &result);
  Serialize(i32_val, &result);
  Deserialize(&i32_val, &result);
  Serialize(i64_val, &result);
  Deserialize(&i64_val, &result);
  Serialize(f_val, &result);
  Deserialize(&f_val, &result);
  Serialize(d_val, &result);
  Deserialize(&d_val, &result);
  Serialize(s_val, &result);
  Deserialize(&s_val, &result);
  Serialize(WrapString(s_val), &result);
  Deserialize(&s_val, &result);
  Serialize(vec_val, &result);
  Deserialize(&vec_val, &result);
  Serialize(t1_val, &result);
  Deserialize(&t1_val, &result);
}

void FuzzDeserializeUint8(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {ENCODING_TYPE_UINT8, fdp.ConsumeIntegral<uint8_t>()};
  std::uint8_t result;
  Deserialize(&result, &buffer);
}

void FuzzDeserializeUint16(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {ENCODING_TYPE_UINT16, fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>()};
  std::uint16_t result;
  Deserialize(&result, &buffer);
}

void FuzzDeserializeUint32(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {ENCODING_TYPE_UINT32, fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>()};
  std::uint32_t result;
  Deserialize(&result, &buffer);
}

void FuzzDeserializeUint64(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {
      ENCODING_TYPE_UINT64,           fdp.ConsumeIntegral<uint8_t>(),
      fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>(),
      fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>(),
      fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>(),
      fdp.ConsumeIntegral<uint8_t>()};
  std::uint64_t result;
  Deserialize(&result, &buffer);
}

void FuzzDeserializeInt8(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {ENCODING_TYPE_INT8, fdp.ConsumeIntegral<uint8_t>()};
  std::int8_t result;
  Deserialize(&result, &buffer);
}

void FuzzDeserializeInt16(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {ENCODING_TYPE_INT16, fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>()};
  std::int16_t result;
  Deserialize(&result, &buffer);
}

void FuzzDeserializeInt32(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {ENCODING_TYPE_INT32, fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>()};
  std::int32_t result;
  Deserialize(&result, &buffer);
}

void FuzzDeserializeInt64(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {ENCODING_TYPE_INT64,
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>()};
  std::int64_t result;
  Deserialize(&result, &buffer);
}

void FuzzDeserializeFloat32(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {ENCODING_TYPE_FLOAT32, fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>()};
  float floatResult;
  Deserialize(&floatResult, &buffer);

  buffer.Rewind();
  double doubleResult;
  Deserialize(&doubleResult, &buffer);
}

void FuzzDeserializeFloat64(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {
      ENCODING_TYPE_FLOAT64,          fdp.ConsumeIntegral<uint8_t>(),
      fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>(),
      fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>(),
      fdp.ConsumeIntegral<uint8_t>(), fdp.ConsumeIntegral<uint8_t>(),
      fdp.ConsumeIntegral<uint8_t>()};
  double result;
  Deserialize(&result, &buffer);
}

void FuzzDeserializeFixstr(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  std::string s_val = fdp.ConsumeRemainingBytesAsString();
  Payload buffer = {ENCODING_TYPE_FIXSTR_MAX};
  for (std::string::iterator iter = s_val.begin(); iter != s_val.end();
       iter++) {
    buffer.Append(1, *iter);
  }
  std::string result;
  Deserialize(&result, &buffer);
}

void FuzzDeserializeFixmap(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {ENCODING_TYPE_FIXMAP_MAX};
  // Fill the map with the fuzzed data, not attempting to
  // make a valid map
  while (fdp.remaining_bytes() > 0) {
    buffer.Append(1, fdp.ConsumeIntegral<uint8_t>());
  }

  std::map<std::uint32_t, std::uint32_t> result;
  Deserialize(&result, &buffer);

  buffer.Rewind();
  std::unordered_map<std::uint32_t, std::uint32_t> unorderedResult;
  Deserialize(&unorderedResult, &buffer);
}

void FuzzDeserializeVariant(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  Payload buffer = {ENCODING_TYPE_INT16,
                    ENCODING_TYPE_FLOAT32,
                    ENCODING_TYPE_FIXSTR_MAX,
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>(),
                    fdp.ConsumeIntegral<uint8_t>()};
  // Add the rest of the data as a string
  std::string s_val = fdp.ConsumeRemainingBytesAsString();
  for (std::string::iterator iter = s_val.begin(); iter != s_val.end();
       iter++) {
    buffer.Append(1, *iter);
  }
  Variant<int, float, std::string> result;
  Deserialize(&result, &buffer);
}

// Attempts to deserialize fuzzed data as various types
void FuzzDeserialize(const uint8_t* data, size_t size) {
  FuzzDeserializeUint8(data, size);
  FuzzDeserializeUint16(data, size);
  FuzzDeserializeUint32(data, size);
  FuzzDeserializeUint64(data, size);
  FuzzDeserializeInt8(data, size);
  FuzzDeserializeInt16(data, size);
  FuzzDeserializeInt32(data, size);
  FuzzDeserializeInt64(data, size);
  FuzzDeserializeFloat32(data, size);
  FuzzDeserializeFloat64(data, size);
  FuzzDeserializeFixstr(data, size);
  FuzzDeserializeFixmap(data, size);
  FuzzDeserializeVariant(data, size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzSerializeDeserialize(data, size);
  FuzzDeserialize(data, size);

  return 0;
}
