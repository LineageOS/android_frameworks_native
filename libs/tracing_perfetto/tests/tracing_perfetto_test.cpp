/*
 * Copyright 2024 The Android Open Source Project
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

#include "tracing_perfetto.h"

#include <thread>

#include <android_os.h>
#include <flag_macros.h>

#include "gtest/gtest.h"
#include "perfetto/public/abi/data_source_abi.h"
#include "perfetto/public/abi/heap_buffer.h"
#include "perfetto/public/abi/pb_decoder_abi.h"
#include "perfetto/public/abi/tracing_session_abi.h"
#include "perfetto/public/abi/track_event_abi.h"
#include "perfetto/public/data_source.h"
#include "perfetto/public/pb_decoder.h"
#include "perfetto/public/producer.h"
#include "perfetto/public/protos/config/trace_config.pzc.h"
#include "perfetto/public/protos/trace/interned_data/interned_data.pzc.h"
#include "perfetto/public/protos/trace/test_event.pzc.h"
#include "perfetto/public/protos/trace/trace.pzc.h"
#include "perfetto/public/protos/trace/trace_packet.pzc.h"
#include "perfetto/public/protos/trace/track_event/debug_annotation.pzc.h"
#include "perfetto/public/protos/trace/track_event/track_descriptor.pzc.h"
#include "perfetto/public/protos/trace/track_event/track_event.pzc.h"
#include "perfetto/public/protos/trace/trigger.pzc.h"
#include "perfetto/public/te_category_macros.h"
#include "perfetto/public/te_macros.h"
#include "perfetto/public/track_event.h"
#include "trace_categories.h"
#include "utils.h"

namespace tracing_perfetto {

using ::perfetto::shlib::test_utils::AllFieldsWithId;
using ::perfetto::shlib::test_utils::FieldView;
using ::perfetto::shlib::test_utils::IdFieldView;
using ::perfetto::shlib::test_utils::MsgField;
using ::perfetto::shlib::test_utils::PbField;
using ::perfetto::shlib::test_utils::StringField;
using ::perfetto::shlib::test_utils::TracingSession;
using ::perfetto::shlib::test_utils::VarIntField;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::UnorderedElementsAre;

const auto PERFETTO_SDK_TRACING = ACONFIG_FLAG(android::os, perfetto_sdk_tracing);

class TracingPerfettoTest : public testing::Test {
 protected:
  void SetUp() override {
    tracing_perfetto::registerWithPerfetto(true /* test */);
  }
};

// TODO(b/303199244): Add tests for all the library functions.

TEST_F_WITH_FLAGS(TracingPerfettoTest, traceInstant,
                  REQUIRES_FLAGS_ENABLED(PERFETTO_SDK_TRACING)) {
  TracingSession tracing_session =
      TracingSession::Builder().set_data_source_name("track_event").Build();
  tracing_perfetto::traceInstant(TRACE_CATEGORY_INPUT, "");

  tracing_session.StopBlocking();
  std::vector<uint8_t> data = tracing_session.ReadBlocking();
  bool found = false;
  for (struct PerfettoPbDecoderField trace_field : FieldView(data)) {
    ASSERT_THAT(trace_field, PbField(perfetto_protos_Trace_packet_field_number,
                                     MsgField(_)));
    IdFieldView track_event(
        trace_field, perfetto_protos_TracePacket_track_event_field_number);
    if (track_event.size() == 0) {
      continue;
    }
    found = true;
    IdFieldView cat_iid_fields(
        track_event.front(),
        perfetto_protos_TrackEvent_category_iids_field_number);
    ASSERT_THAT(cat_iid_fields, ElementsAre(VarIntField(_)));
    uint64_t cat_iid = cat_iid_fields.front().value.integer64;
    EXPECT_THAT(
        trace_field,
        AllFieldsWithId(
            perfetto_protos_TracePacket_interned_data_field_number,
            ElementsAre(AllFieldsWithId(
                perfetto_protos_InternedData_event_categories_field_number,
                ElementsAre(MsgField(UnorderedElementsAre(
                    PbField(perfetto_protos_EventCategory_iid_field_number,
                            VarIntField(cat_iid)),
                    PbField(perfetto_protos_EventCategory_name_field_number,
                            StringField("input")))))))));
  }
  EXPECT_TRUE(found);
}

}  // namespace tracing_perfetto