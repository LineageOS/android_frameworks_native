// pose is a utility to query and manipulate the current pose via the pose
// service.

#include <cmath>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <regex>
#include <vector>

#include <private/dvr/types.h>
#include <dvr/pose_client.h>

using android::dvr::vec3;
using android::dvr::quat;

namespace {

// Prints usage information to stderr.
void PrintUsage(const char* executable_name) {
  std::cerr << "Usage: " << executable_name
            << " [--identity|--set=...|--unfreeze]\n"
            << "\n"
            << "  no arguments: display the current pose.\n"
            << "  --identity: freeze the pose to the identity pose.\n"
            << "  --set=rx,ry,rz,rw[,px,py,pz]: freeze the pose to the given "
               "state. rx,ry,rz,rw are interpreted as rotation quaternion. "
               " px, py, pz as position (0,0,0 if omitted).\n"
            << "  --mode=mode: sets mode to one of normal, head_turn:slow, "
               "head_turn:fast, rotate:slow, rotate:medium, rotate:fast, "
               "circle_strafe.\n"
            << "  --unfreeze: sets the mode to normal.\n"
            << "  --log_controller=[true|false]: starts and stops controller"
               " logs\n"
            << std::endl;
}

// If return_code is negative, print out its corresponding string description
// and exit the program with a non-zero exit code.
void ExitIfNegative(int return_code) {
  if (return_code < 0) {
    std::cerr << "Error: " << strerror(-return_code) << std::endl;
    std::exit(1);
  }
}

// Parses the following command line flags:
// --identity
// --set=rx,ry,rz,rw[,px,py,pz]
// Returns false if parsing fails.
bool ParseState(const std::string& arg, DvrPoseState* out_state) {
  if (arg == "--identity") {
    *out_state = {.head_from_start_rotation = {0.f, 0.f, 0.f, 1.f},
                  .head_from_start_translation = {0.f, 0.f, 0.f},
                  .timestamp_ns = 0,
                  .sensor_from_start_rotation_velocity = {0.f, 0.f, 0.f}};
    return true;
  }

  const std::string prefix("--set=");
  if (arg.size() < 6 || arg.compare(0, prefix.size(), prefix) != 0) {
    return false;
  }

  // Tokenize by ','.
  std::regex split_by_comma("[,]+");
  std::sregex_token_iterator token_it(arg.begin() + prefix.size(), arg.end(),
                                      split_by_comma,
                                      -1 /* return inbetween parts */);
  std::sregex_token_iterator token_end;

  // Convert to float and store values.
  std::vector<float> values;
  for (; token_it != token_end; ++token_it) {
    std::string token = *(token_it);
    float value = 0.f;
    if (sscanf(token.c_str(), "%f", &value) != 1) {
      std::cerr << "Unable to parse --set value as float: " << token
                << std::endl;
      return false;
    } else {
      values.push_back(value);
    }
  }

  if (values.size() != 4 && values.size() != 7) {
    std::cerr << "Unable to parse --set, expected either 4 or 7 of values."
              << std::endl;
    return false;
  }

  float norm2 = values[0] * values[0] + values[1] * values[1] +
                values[2] * values[2] + values[3] * values[3];
  if (std::abs(norm2 - 1.f) > 1e-4) {
    if (norm2 < 1e-8) {
      std::cerr << "--set quaternion norm close to zero." << std::endl;
      return false;
    }
    float norm = std::sqrt(norm2);
    values[0] /= norm;
    values[1] /= norm;
    values[2] /= norm;
    values[3] /= norm;
  }

  out_state->head_from_start_rotation = {values[0], values[1], values[2],
                                         values[3]};

  if (values.size() == 7) {
    out_state->head_from_start_translation = {values[4], values[5], values[6]};
  } else {
    out_state->head_from_start_translation = {0.f, 0.f, 0.f};
  }

  out_state->timestamp_ns = 0;
  out_state->sensor_from_start_rotation_velocity = {0.f, 0.f, 0.f};

  return true;
}

// Parses the command line flag --mode.
// Returns false if parsing fails.
bool ParseSetMode(const std::string& arg, DvrPoseMode* mode) {
  const std::string prefix("--mode=");
  if (arg.size() < prefix.size() ||
      arg.compare(0, prefix.size(), prefix) != 0) {
    return false;
  }

  std::string value = arg.substr(prefix.size());

  if (value == "normal") {
    *mode = DVR_POSE_MODE_6DOF;
    return true;
  } else if (value == "head_turn:slow") {
    *mode = DVR_POSE_MODE_MOCK_HEAD_TURN_SLOW;
    return true;
  } else if (value == "head_turn:fast") {
    *mode = DVR_POSE_MODE_MOCK_HEAD_TURN_FAST;
    return true;
  } else if (value == "rotate:slow") {
    *mode = DVR_POSE_MODE_MOCK_ROTATE_SLOW;
    return true;
  } else if (value == "rotate:medium") {
    *mode = DVR_POSE_MODE_MOCK_ROTATE_MEDIUM;
    return true;
  } else if (value == "rotate:fast") {
    *mode = DVR_POSE_MODE_MOCK_ROTATE_FAST;
    return true;
  } else if (value == "circle_strafe") {
    *mode = DVR_POSE_MODE_MOCK_CIRCLE_STRAFE;
    return true;
  } else {
    return false;
  }
}

// Parses the command line flag --controller_log.
// Returns false if parsing fails.
bool ParseLogController(const std::string& arg, bool* log_enabled) {
  const std::string prefix("--log_controller=");
  if (arg.size() < prefix.size() ||
      arg.compare(0, prefix.size(), prefix) != 0) {
    return false;
  }

  std::string value = arg.substr(prefix.size());

  if (value == "false") {
    *log_enabled = false;
    return true;
  } else if (value == "true") {
    *log_enabled = true;
    return true;
  } else {
    return false;
  }
}

// The different actions that the tool can perform.
enum class Action {
  Query,                 // Query the current pose.
  Set,                   // Set the pose and freeze.
  Unfreeze,              // Set the pose mode to normal.
  SetMode,               // Sets the pose mode.
  LogController,         // Start/stop controller logging in sensord.
};

// The action to perform when no arguments are passed to the tool.
constexpr Action kDefaultAction = Action::Query;

}  // namespace

int main(int argc, char** argv) {
  Action action = kDefaultAction;
  DvrPoseState state;
  DvrPoseMode pose_mode = DVR_POSE_MODE_6DOF;
  bool log_controller = false;

  // Parse command-line arguments.
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (ParseState(arg, &state) && action == kDefaultAction) {
      action = Action::Set;
    } else if (arg == "--unfreeze" && action == kDefaultAction) {
      action = Action::Unfreeze;
    } else if (ParseSetMode(arg, &pose_mode) && action == kDefaultAction) {
      action = Action::SetMode;
    } else if (ParseLogController(arg, &log_controller)) {
      action = Action::LogController;
    } else {
      PrintUsage(argv[0]);
      return 1;
    }
  }

  auto pose_client = dvrPoseCreate();
  if (!pose_client) {
    std::cerr << "Unable to create pose client." << std::endl;
    return 1;
  }

  switch (action) {
    case Action::Query: {
      ExitIfNegative(dvrPosePoll(pose_client, &state));
      uint64_t timestamp = state.timestamp_ns;
      const auto& rotation = state.head_from_start_rotation;
      const auto& translation = state.head_from_start_translation;
      const auto& rotation_velocity = state.sensor_from_start_rotation_velocity;
      quat q(rotation.w, rotation.x, rotation.y, rotation.z);
      vec3 angles = q.matrix().eulerAngles(0, 1, 2);
      angles = angles * 180.f / M_PI;
      vec3 x = q * vec3(1.0f, 0.0f, 0.0f);
      vec3 y = q * vec3(0.0f, 1.0f, 0.0f);
      vec3 z = q * vec3(0.0f, 0.0f, 1.0f);

      std::cout << "timestamp_ns: " << timestamp << std::endl
                << "rotation_quaternion: " << rotation.x << ", " << rotation.y
                << ", " << rotation.z << ", " << rotation.w << std::endl
                << "rotation_angles: " << angles.x() << ", " << angles.y()
                << ", " << angles.z() << std::endl
                << "translation: " << translation.x << ", " << translation.y
                << ", " << translation.z << std::endl
                << "rotation_velocity: " << rotation_velocity.x << ", "
                << rotation_velocity.y << ", " << rotation_velocity.z
                << std::endl
                << "axes: " << std::setprecision(3)
                << "x(" << x.x() << ", " << x.y() << ", " << x.z() << "), "
                << "y(" << y.x() << ", " << y.y() << ", " << y.z() << "), "
                << "z(" << z.x() << ", " << z.y() << ", " << z.z() << "), "
                << std::endl;
      break;
    }
    case Action::Set: {
      ExitIfNegative(dvrPoseFreeze(pose_client, &state));
      break;
    }
    case Action::Unfreeze: {
      ExitIfNegative(dvrPoseSetMode(pose_client, DVR_POSE_MODE_6DOF));
      break;
    }
    case Action::SetMode: {
      ExitIfNegative(dvrPoseSetMode(pose_client, pose_mode));
      break;
    }
    case Action::LogController: {
      ExitIfNegative(
          dvrPoseLogController(pose_client, log_controller));
      break;
    }
  }

  dvrPoseDestroy(pose_client);
}
