package com.android.graphics.bufferstreamsdemoapp

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.util.Collections

/*
LogOutput centralizes logging: storing, displaying, adding, and clearing log messages with
thread safety. It is a singleton that's also accessed from C++. The private constructor will
not allow this class to be initialized, limiting it to getInstance().
 */
class LogOutput private constructor() {
    val logs = Collections.synchronizedList(mutableStateListOf<String>())

    @Composable
    fun LogOutputComposable() {
        val rlogs = remember { logs }

        Card(modifier = Modifier.fillMaxWidth().padding(16.dp).height(400.dp)) {
            Column(
                modifier =
                    Modifier.padding(10.dp).size(380.dp).verticalScroll(rememberScrollState())) {
                    for (log in rlogs) {
                        Text(log, modifier = Modifier.padding(0.dp))
                    }
                }
        }
    }

    fun clearText() {
        logs.clear()
    }

    fun addLog(log: String) {
        logs.add(log)
    }

    companion object {
        @Volatile private var instance: LogOutput? = null

        @JvmStatic
        fun getInstance(): LogOutput {
            if (instance == null) {
                synchronized(this) {
                    if (instance == null) {
                        instance = LogOutput()
                    }
                }
            }
            return instance!!
        }
    }
}
