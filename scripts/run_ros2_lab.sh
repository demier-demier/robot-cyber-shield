#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f /opt/ros/jazzy/setup.bash ]]; then
  set +u
  source /opt/ros/jazzy/setup.bash
  set -u
elif [[ -z "${ROS_DISTRO:-}" ]]; then
  printf '%s\n' 'ROS 2 Jazzy is required. See docs/ROS2.md; this is not a mocked ROS test.' >&2
  exit 2
fi
if [[ "${ROS_DISTRO}" != jazzy ]]; then
  printf '%s\n' 'This integration is validated against ROS 2 Jazzy only.' >&2
  exit 2
fi
python3 "$repo_dir/ros2/run_lab.py" \
  --binary "$repo_dir/target/release/robot-cyber-shield" \
  --output "${SHIELD_ROS2_OUTPUT:-$repo_dir/artifacts/ros2}" "$@"
