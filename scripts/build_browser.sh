#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
# Prerequisites: current Rust, wasm32-unknown-unknown, wasm-bindgen-cli 0.2.130.
# The caller owns toolchain installation; this script never enables paid services.
cargo build --locked
python3 scripts/build_browser_fixtures.py
python3 scripts/build_browser_notices.py
# Panic/source strings must not publish the builder's home or checkout paths.
# Encoded flags preserve paths containing spaces and existing caller flags.
build_flags="$(python3 - "$repo_dir" <<'PYFLAGS'
import os, shlex, sys
from pathlib import Path
flags = os.environ.get("CARGO_ENCODED_RUSTFLAGS", "").split("\x1f") if os.environ.get("CARGO_ENCODED_RUSTFLAGS") else shlex.split(os.environ.get("RUSTFLAGS", ""))
flags += [f"--remap-path-prefix={sys.argv[1]}=/source",
          f"--remap-path-prefix={os.environ.get('CARGO_HOME', str(Path.home()/'.cargo'))}=/cargo",
          f"--remap-path-prefix={Path.home()}=/build-home"]
print("\x1f".join(flags))
PYFLAGS
)"
CARGO_ENCODED_RUSTFLAGS="$build_flags" cargo build --locked -p robot-shield-browser --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/robot_shield_browser.wasm \
  --target web --out-dir web/wasm --out-name robot_shield_browser

python3 - <<'PYSCAN'
from pathlib import Path
binary = Path("web/wasm/robot_shield_browser_bg.wasm").read_bytes()
for marker in [b"/Users/", b"/home/runner/", b"BEGIN PRIVATE KEY", b"github_pat_"]:
    if marker in binary:
        raise SystemExit("Browser artifact publication scan failed")
print("WASM publication scan passed; private build paths are remapped.")
PYSCAN
