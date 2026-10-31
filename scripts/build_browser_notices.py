#!/usr/bin/env python3
"""Bundle licenses for the verifier's resolved Rust dependencies and toolchain."""
from pathlib import Path
import json
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True)


def main():
    tree = output("cargo", "tree", "--locked", "-p", "robot-shield-browser",
                  "--target", "wasm32-unknown-unknown", "--edges", "normal", "--prefix", "none")
    required = set()
    for line in tree.splitlines():
        match = re.match(r"^([A-Za-z0-9_-]+) v([^ ]+)", line)
        if match:
            required.add(match.groups())
    metadata = json.loads(output("cargo", "metadata", "--locked", "--offline", "--no-default-features", "--filter-platform", "wasm32-unknown-unknown", "--format-version", "1"))
    sections = ["ROBOT CYBER SHIELD BROWSER VERIFIER — THIRD-PARTY NOTICES\n\n"
                "Resolved dependency versions are pinned in Cargo.lock. The notices below\n"
                "cover dependencies of the browser verifier, including build-time macros.\n"
                "Original project code is licensed under MIT; dependencies retain their own licenses.\n"]
    count = 0
    for package in sorted(metadata["packages"], key=lambda p:(p["name"],p["version"])):
        if (package["name"],package["version"]) not in required or package["source"] is None:
            continue
        folder = Path(package["manifest_path"]).parent
        files = sorted({p for pattern in ("LICENSE*", "COPYING*") for p in folder.glob(pattern) if p.is_file()})
        if package.get("license_file"):
            files.append(folder / package["license_file"])
        if not files:
            raise RuntimeError("Missing license notice for " + package["name"])
        sections.append(f"\n{'='*72}\n{package['name']} {package['version']}\nLicense expression: {package['license']}\n")
        for path in files:
            sections.append(f"\n--- {path.name} ---\n" + path.read_text())
        count += 1
    toolchain = Path(output("rustc", "--print", "sysroot").strip())
    toolchain_docs = toolchain / "share/doc/rust"
    toolchain_licenses = sorted((toolchain_docs / "licenses").glob("*.txt"))
    if toolchain_licenses:
        sections.append(f"\n{'='*72}\nRust toolchain and standard library\n")
        for path in toolchain_licenses:
            if path.is_file():
                sections.append(f"\n--- {path.name} ---\n" + path.read_text())
    copyright_file = toolchain_docs / "COPYRIGHT-library.html"
    if copyright_file.exists():
        sections.append("Rust Standard Library detailed copyright notices: RUST_STANDARD_LIBRARY_COPYRIGHT.html\n")
        shutil.copyfile(copyright_file, ROOT / "web/wasm/RUST_STANDARD_LIBRARY_COPYRIGHT.html")
    result = "\n".join(sections)
    if str(Path.home()) in result or str(ROOT) in result:
        raise RuntimeError("Private build path in notices")
    (ROOT / "web/wasm/THIRD_PARTY_NOTICES.txt").write_text(result)
    print(f"Bundled license notices for {count} resolved dependency packages.")


if __name__ == "__main__":
    main()
