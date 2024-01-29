package com.android.graphics.bufferstreamsdemoapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.android.graphics.bufferstreamsdemoapp.ui.theme.JetpackTheme
import java.util.*

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            JetpackTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background) {
                        BufferDemosApp()
                    }
            }
        }
    }
}

enum class BufferDemoScreen(val route: String, @StringRes val title: Int) {
    Start(route = "start", title = R.string.start),
    Demo1(route = "demo1", title = R.string.demo1),
    Demo2(route = "demo2", title = R.string.demo2),
    Demo3(route = "demo3", title = R.string.demo3);

    companion object {
        fun findByRoute(route: String): BufferDemoScreen {
            return values().find { it.route == route }!!
        }
    }
}

@Composable
fun BufferDemosApp() {
    var navController: NavHostController = rememberNavController()
    // Get current back stack entry
    val backStackEntry by navController.currentBackStackEntryAsState()
    // Get the name of the current screen
    val currentScreen =
        BufferDemoScreen.findByRoute(
            backStackEntry?.destination?.route ?: BufferDemoScreen.Start.route)

    Scaffold(
        topBar = {
            BufferDemosAppBar(
                currentScreen = currentScreen,
                canNavigateBack = navController.previousBackStackEntry != null,
                navigateUp = { navController.navigateUp() })
        }) {
            NavHost(
                navController = navController,
                startDestination = BufferDemoScreen.Start.route,
                modifier = Modifier.padding(10.dp)) {
                    composable(route = BufferDemoScreen.Start.route) {
                        DemoList(
                            onButtonClicked = { navController.navigate(it) },
                        )
                    }
                    composable(route = BufferDemoScreen.Demo1.route) {
                        DemoScreen1(modifier = Modifier.fillMaxHeight().padding(top = 100.dp))
                    }
                    composable(route = BufferDemoScreen.Demo2.route) { DemoScreen2() }
                    composable(route = BufferDemoScreen.Demo3.route) { DemoScreen3() }
                }
        }
}

@Composable
fun DemoList(onButtonClicked: (String) -> Unit) {
    var modifier = Modifier.fillMaxSize().padding(16.dp)

    Column(modifier = modifier, verticalArrangement = Arrangement.SpaceBetween) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Spacer(modifier = Modifier.height(100.dp))
                Text(text = "Buffer Demos", style = MaterialTheme.typography.titleLarge)
                Spacer(modifier = Modifier.height(8.dp))
            }
        Row(modifier = Modifier.weight(2f, false)) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    for (item in BufferDemoScreen.values()) {
                        if (item.route != BufferDemoScreen.Start.route)
                            SelectDemoButton(
                                name = stringResource(item.title),
                                onClick = { onButtonClicked(item.route) })
                    }
                }
        }
    }
}

@Composable
fun SelectDemoButton(name: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Button(onClick = onClick, modifier = modifier.widthIn(min = 250.dp)) { Text(name) }
}
