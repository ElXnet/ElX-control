"""Resolve the exact sibling ElXray Go module used by Stage-4 E2E tests.

Control and ElXray are siblings in GitHub Actions, NOT nested.
ELXRAY_SOURCE refers to the same module that the local suite builds.
"""
import os
from pathlib import Path


def stage4_core_source(test_script, source_override=None):
    control_root = Path(test_script).resolve().parents[2]
    configured = source_override
    if configured is None:
        configured = os.environ.get("ELXRAY_SOURCE", "")
    core = (Path(configured).expanduser() if configured
            else control_root.parent / "ElXray").resolve()
    if core == control_root or core == control_root / "ElXray":
        raise AssertionError("Stage-4 ElXray checkout must be a separate source repository")
    module = core / "go.mod"
    if not module.is_file():
        raise AssertionError(
            f"missing paired Stage-4 ElXray module at {module}; "
            "clone ElXray beside ElX-control or set ELXRAY_SOURCE")
    header = module.read_text(encoding="utf-8", errors="strict").splitlines()
    if not any(line.strip() == "module github.com/xtls/xray-core" for line in header):
        raise AssertionError("unexpected ElXray Go module path in paired checkout")
    return core
