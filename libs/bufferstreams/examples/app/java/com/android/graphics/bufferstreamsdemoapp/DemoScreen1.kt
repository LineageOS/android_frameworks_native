package com.android.graphics.bufferstreamsdemoapp

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun DemoScreen1(modifier: Modifier = Modifier) {
    Column(modifier = modifier, verticalArrangement = Arrangement.SpaceBetween) {
        LogOutput.getInstance().LogOutputComposable()
        Row(modifier = Modifier.weight(1f, false).padding(16.dp)) {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Button(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = { BufferStreamJNI.companion_testBufferQueueCreation() }) {
                        Text("Run")
                    }

                OutlinedButton(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = { LogOutput.getInstance().clearText() }) {
                        Text("Clear")
                    }
            }
        }
    }
}
