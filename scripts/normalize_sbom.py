#!/usr/bin/env python3
"""
Normalize cargo-cyclonedx output to make SBOMs reproducible across machines.

cargo-cyclonedx emits non-deterministic content even when the inputs are
identical:

  - `serialNumber` is a freshly-generated UUID on every invocation.
  - `metadata.timestamp` reflects generation wall-clock time.
  - `bom-ref` values and internal cross-references embed the absolute
    filesystem path of the checkout (so the SBOM differs between a local
    machine at /home/user/proj and a CI runner at /home/runner/work/...).

NIST SP 800-218 SSDF PS.3.2 requires provenance data to be reproducible
so that "the SBOM-for-this-source-tree" is a deterministic artifact. This
script canonicalizes the volatile fields after cargo-cyclonedx runs:

  - Removes `serialNumber` entirely (optional per CycloneDX 1.5).
  - Pins `metadata.timestamp` to a fixed value.
  - Replaces absolute checkout paths in `bom-ref` and references with
    `path+file://./<crate>` form (relative to the workspace root).

Usage:
    python3 scripts/normalize_sbom.py docs/sbom/*.cdx.json
"""

import json
import re
import sys
from pathlib import Path

# Fixed timestamp for reproducibility. The Unix epoch is conventional;
# tooling that wants a real release timestamp can derive it from git.
CANONICAL_TIMESTAMP = "1970-01-01T00:00:00Z"

# Match cargo-cyclonedx's absolute-path bom-ref / reference format:
#   path+file:///abs/path/to/checkout/<crate-name>#<version>[ <suffix>]
# Rewrites the absolute path prefix down to just the crate name.
ABS_PATH_REF = re.compile(r"path\+file:///[^#\"\s]*/([^/#\"\s]+)(#[^\"\s]*)?")


def normalize_string(s: str) -> str:
    """Replace absolute path-based bom-refs with workspace-relative form."""
    return ABS_PATH_REF.sub(r"path+file://./\1\2", s)


def walk_in_place(obj):
    """Recursively rewrite all string values in a JSON object."""
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if isinstance(v, str):
                obj[k] = normalize_string(v)
            else:
                walk_in_place(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                obj[i] = normalize_string(v)
            else:
                walk_in_place(v)


def normalize_sbom(path: Path) -> None:
    data = json.loads(path.read_text())

    # Strip non-deterministic identifier (optional field per CycloneDX 1.5).
    data.pop("serialNumber", None)

    # Pin timestamp.
    if "metadata" in data:
        data["metadata"]["timestamp"] = CANONICAL_TIMESTAMP

    # Rewrite all string values containing absolute checkout paths.
    walk_in_place(data)

    # Emit with stable formatting. `ensure_ascii=False` keeps UTF-8
    # characters (author names, package descriptions) human-readable
    # rather than emitting `é` escape sequences.
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: normalize_sbom.py <sbom.cdx.json> [...]", file=sys.stderr)
        return 1
    for arg in sys.argv[1:]:
        p = Path(arg)
        if not p.exists():
            print(f"warning: {p} does not exist; skipping", file=sys.stderr)
            continue
        normalize_sbom(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
