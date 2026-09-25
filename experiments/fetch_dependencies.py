#!/usr/bin/env python3
"""Fetch the benchmark sources used by the experiment runners.

This downloads upstream repositories at the recorded revisions and applies our
source patches. It does not download our experiment outputs or run models.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess


EXPERIMENTS = Path(__file__).resolve().parent
ROOT = EXPERIMENTS.parent


def main() -> None:
    sources = json.loads((EXPERIMENTS / "upstream_sources.json").read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("names", nargs="*", help="Dependencies to fetch; default: all listed sources.")
    parser.add_argument("--directory", type=Path, default=ROOT / "third_party")
    args = parser.parse_args()
    names = args.names or list(sources)
    unknown = set(names) - set(sources)
    if unknown:
        parser.error("Unknown dependency: " + ", ".join(sorted(unknown)))
    args.directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        info = sources[name]
        destination = args.directory / name
        if destination.exists():
            print(f"Already exists; leaving unchanged: {destination}")
            continue
        subprocess.run(["git", "clone", info["url"], str(destination)], check=True)
        subprocess.run(["git", "-C", str(destination), "checkout", "--detach", info["revision"]], check=True)
        if info.get("patch"):
            subprocess.run(
                ["git", "-C", str(destination), "apply", "--whitespace=nowarn", str(EXPERIMENTS / info["patch"])],
                check=True,
            )
        print(f"Ready: {destination}")


if __name__ == "__main__":
    main()
