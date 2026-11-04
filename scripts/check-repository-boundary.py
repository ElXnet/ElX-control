#!/usr/bin/env python3
"""Verify ElX Control is owned by its repository, not vendored into ElX-ui.

Usage: python3 scripts/check-repository-boundary.py /path/to/workspace
Workspace contains sibling ElX-ui and ElX-control repositories.
"""
from pathlib import Path
import re
import sys

DEPRECATED_DIRECTORIES = ("cmd/elx-control", "internal/elxcontrol")
DEPRECATED_UI_FILES = (
    "scripts/elx-policy-smoke.sh",
    "scripts/elx-vless-stop-smoke.py",
    "scripts/elx-test-local.sh",
    "scripts/run-elx-windows.ps1",
    "docs/elx/policy-smoke.ru.md",
)
INVALID_IMPORTS = (
    "github.com/mhsanaei/3x-ui/v3/internal/elxcontrol",
    "github.com/ElXnet/ElX-control/internal/elxcontrol",
)

def check(workspace: Path) -> list[str]:
    ui, control = workspace / "ElX-ui", workspace / "ElX-control"
    errors = []
    for root in (ui, control):
        if not (root / ".git").exists():
            errors.append(f"Expected checked-out Git repository: {root}")
    if errors:
        return errors

    for rel in DEPRECATED_DIRECTORIES:
        if (ui / rel).exists():
            errors.append(f"Duplicated Control implementation in UI: {rel}")
        if not (control / rel).is_dir():
            errors.append(f"Missing canonical Control implementation: {rel}")

    for rel in DEPRECATED_UI_FILES:
        if (ui / rel).exists():
            errors.append(f"Obsolete standalone Control asset in UI: {rel}")
        if not (control / rel).is_file():
            errors.append(f"Missing canonical Control asset: {rel}")

    for source_root in (ui / "internal", ui / "cmd"):
        if not source_root.is_dir():
            continue
        for path in source_root.rglob("*.go"):
            text = path.read_text(encoding="utf-8")
            for candidate in INVALID_IMPORTS:
                if candidate in text:
                    errors.append(f"UI imports private Control implementation: {path.relative_to(ui)}")
                    break

    # Avoid reintroducing compilation of the old embedded module from
    # future UI scripts or Actions jobs, even if its files were deleted.
    stale_compile = re.compile(
        r"go\\s+(?:test|build|run)\\b[^\\n]*(?:\\./cmd/elx-control|\\./internal/elxcontrol)"
    )
    sources = (ui / "scripts", ui / ".github" / "workflows")
    for source_root in sources:
        if not source_root.is_dir():
            continue
        for path in source_root.rglob("*"):
            if not path.is_file() or path.suffix not in {".sh", ".ps1", ".py", ".yml", ".yaml"}:
                continue
            if stale_compile.search(path.read_text(encoding="utf-8")):
                errors.append(f"UI still builds embedded Control: {path.relative_to(ui)}")

    for rel in (
        "internal/web/controller/elx_management.go",
        "internal/web/controller/lk_proxy.go",
        "frontend/src/pages/elx/ElxManagementPage.tsx",
        "frontend/src/entries/lk.tsx",
    ):
        if not (ui / rel).is_file():
            errors.append(f"Missing UI-owned Control adapter or page: {rel}")
    return errors

def main() -> int:
    workspace = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]
    errors = check(workspace)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if errors:
        return 1
    print("PASS: Control source is standalone, UI contains only integration adapters")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
