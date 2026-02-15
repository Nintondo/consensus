#!/usr/bin/env python3

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


def canonical_entries_bytes(entries):
    return json.dumps(
        entries,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def resolve_core_commit(core_repo, core_commit):
    if core_commit:
        return core_commit
    if core_repo is None:
        raise ValueError("either --core-commit or --core-repo must be provided")
    result = subprocess.run(
        ["git", "-C", str(core_repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(
        description="Generate script_assets_upstream metadata JSON from an upstream corpus file."
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        required=True,
        help="Path to script-assets upstream JSON file.",
    )
    parser.add_argument(
        "--output",
        default="tests/data/script_assets_upstream_metadata.json",
        help="Output metadata JSON path (default: tests/data/script_assets_upstream_metadata.json).",
    )
    parser.add_argument(
        "--core-repo",
        default=None,
        help="Path to a Bitcoin Core git checkout (used to resolve source_core_commit).",
    )
    parser.add_argument(
        "--core-commit",
        default=None,
        help="Explicit Core commit hash (overrides --core-repo).",
    )
    parser.add_argument(
        "--source-generation",
        default="script_assets_test_minimizer",
        help="Value for source_generation metadata key.",
    )
    args = parser.parse_args()

    json_path = pathlib.Path(args.json_path)
    if not json_path.exists():
        raise FileNotFoundError(f"missing JSON file: {json_path}")

    with json_path.open("r", encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, list):
        raise ValueError("script-assets upstream JSON must be a top-level array")

    canonical = canonical_entries_bytes(value)
    artifact_sha256 = hashlib.sha256(canonical).hexdigest()
    artifact_case_count = len(value)
    source_core_commit = resolve_core_commit(args.core_repo, args.core_commit)

    metadata = {
        "source_core_commit": source_core_commit,
        "source_generation": args.source_generation,
        "artifact_case_count": artifact_case_count,
        "artifact_sha256": artifact_sha256,
    }

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
        f.write("\n")

    print(f"wrote {output_path}")
    print(f"source_core_commit={source_core_commit}")
    print(f"artifact_case_count={artifact_case_count}")
    print(f"artifact_sha256={artifact_sha256}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
