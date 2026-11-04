#!/usr/bin/env python3
"""Refuse silent divergence while ElX-ui still carries a Control mirror."""
from pathlib import Path
import sys


def normalize(path: Path) -> bytes:
    data = path.read_bytes()
    return data.replace(
        b"github.com/mhsanaei/3x-ui/v3/internal/elxcontrol",
        b"github.com/ElXnet/ElX-control/internal/elxcontrol",
    )


def tracked(root: Path) -> dict[str, Path]:
    files = {}
    for folder in ("cmd/elx-control", "internal/elxcontrol"):
        for path in (root / folder).rglob("*"):
            if path.is_file() and path.suffix in {".go", ".sql", ".proto"}:
                files[path.relative_to(root).as_posix()] = path
    return files


def main() -> int:
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]
    ui = base / "ElX-ui"
    control = base / "ElX-control"
    lhs, rhs = tracked(ui), tracked(control)
    differences = []
    for path in sorted(lhs.keys() | rhs.keys()):
        if path not in lhs or path not in rhs or normalize(lhs[path]) != normalize(rhs[path]):
            differences.append(path)
    if differences:
        print("Control mirrors differ (do not silently deploy an outdated implementation):", file=sys.stderr)
        for path in differences:
            print(" - " + path, file=sys.stderr)
        return 1
    print(f"PASS: Control mirror parity ({len(lhs)} tracked files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
