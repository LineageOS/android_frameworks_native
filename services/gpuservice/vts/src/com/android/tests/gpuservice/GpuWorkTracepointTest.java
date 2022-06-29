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
package com.android.tests.gpuservice;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import com.android.tradefed.util.CommandResult;
import com.android.tradefed.util.CommandStatus;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.stream.Collectors;


@RunWith(DeviceJUnit4ClassRunner.class)
public class GpuWorkTracepointTest extends BaseHostJUnit4Test {

    private static final String CPU_FREQUENCY_TRACEPOINT_FORMAT_PATH =
            "/sys/kernel/tracing/events/power/cpu_frequency/format";
    private static final String GPU_WORK_PERIOD_TRACEPOINT_FORMAT_PATH =
            "/sys/kernel/tracing/events/power/gpu_work_period/format";

    @Test
    public void testReadTracingEvents() throws Exception {
        // Test |testGpuWorkPeriodTracepointFormat| is dependent on whether certain tracepoint
        // paths exist. This means the test will vacuously pass if the tracepoint file system is
        // inaccessible. Thus, as a basic check, we make sure the CPU frequency tracepoint format
        // is accessible. If not, something is probably fundamentally broken about the tracing
        // file system.
        CommandResult commandResult = getDevice().executeShellV2Command(
                String.format("cat %s", CPU_FREQUENCY_TRACEPOINT_FORMAT_PATH));

        assertEquals(String.format(
                        "Failed to read \"%s\". This probably means that the tracing file system "
                                + "is fundamentally broken in some way, possibly due to bad "
                                + "permissions.",
                        CPU_FREQUENCY_TRACEPOINT_FORMAT_PATH),
                commandResult.getStatus(), CommandStatus.SUCCESS);
    }

    @Test
    public void testGpuWorkPeriodTracepointFormat() throws Exception {
        CommandResult commandResult = getDevice().executeShellV2Command(
                String.format("cat %s", GPU_WORK_PERIOD_TRACEPOINT_FORMAT_PATH));

        // If we failed to cat the tracepoint format then the test ends here.
        assumeTrue(String.format("Failed to cat the gpu_work_period tracepoint format at %s",
                        GPU_WORK_PERIOD_TRACEPOINT_FORMAT_PATH),
                commandResult.getStatus().equals(CommandStatus.SUCCESS));

        // Otherwise, we check that the fields match the expected fields.
        String actualFields = Arrays.stream(
                commandResult.getStdout().trim().split("\n")).filter(
                s -> s.startsWith("\tfield:")).collect(
                Collectors.joining("\n"));

        String expectedFields = String.join("\n",
                "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;",
                "\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;",
                "\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;",
                "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;",
                "\tfield:u32 gpu_id;\toffset:8;\tsize:4;\tsigned:0;",
                "\tfield:u32 uid;\toffset:12;\tsize:4;\tsigned:0;",
                "\tfield:u64 start_time_ns;\toffset:16;\tsize:8;\tsigned:0;",
                "\tfield:u64 end_time_ns;\toffset:24;\tsize:8;\tsigned:0;",
                "\tfield:u64 total_active_duration_ns;\toffset:32;\tsize:8;\tsigned:0;"
        );

        // We use |fail| rather than |assertEquals| because it allows us to give a clearer message.
        if (!expectedFields.equals(actualFields)) {
            String message = String.format(
                    "Tracepoint format given by \"%s\" does not match the expected format.\n"
                            + "Expected fields:\n%s\n\nActual fields:\n%s\n\n",
                    GPU_WORK_PERIOD_TRACEPOINT_FORMAT_PATH, expectedFields, actualFields);
            fail(message);
        }
    }
}
