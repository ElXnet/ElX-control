"""Resolve the exact sibling ElXray Go module used by Stage-4 E2E tests.

Control and ElXray are siblings in GitHub Actions, NOT nested.
ELXRAY_SOURCE refers to the same module that the local suite builds.
"""
import json
import os
from pathlib import Path
import subprocess


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


def ensure_disposable_technical_inbound_tag(config_file, node):
    """Give exactly one VLESS inbound a stable, nonempty tag before core boot.

    This only rewrites a disposable E2E server JSON. Production config
    parsing remains untouched and rejects an untagged technical inbound.
    """
    if not isinstance(node, int) or node < 0:
        raise AssertionError("invalid technical test node index")
    path = Path(config_file)
    if not path.is_file():
        raise AssertionError("missing disposable VLESS server JSON")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise AssertionError("invalid technical VLESS server JSON") from exc
    if not isinstance(config, dict) or not isinstance(config.get("inbounds"), list):
        raise AssertionError("technical VLESS test requires explicit inbounds")
    inbounds = config["inbounds"]
    vless = [entry for entry in inbounds if isinstance(entry, dict)
             and entry.get("protocol") == "vless"]
    if len(vless) != 1:
        raise AssertionError("technical E2E requires exactly one tagged VLESS inbound")
    chosen = vless[0]
    tag = chosen.get("tag")
    if not isinstance(tag, str) or not tag:
        tag = f"elx-technical-vless-{node}"
        chosen["tag"] = tag
    if len(tag) > 128 or sum(
            isinstance(item, dict) and item.get("tag") == tag
            for item in inbounds) != 1:
        raise AssertionError("technical VLESS inbound tag is ambiguous")
    path.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    return tag


def build_disposable_rate_fixture(folder, control_root, env, *, runner=None):
    """Compile the scheduler fixture in EACH isolated managed-core lab.

    Its binary lives inside the lab's own disposable directory. Never share
    the path from another E2E TemporaryDirectory, which may already be gone.
    The real PostgreSQL/Core acceptance tests use this executable to seed
    and independently inspect durable signed rate commitments.
    """
    folder = Path(folder).resolve()
    source = Path(control_root).resolve()
    if not folder.is_dir():
        raise AssertionError("disposable scheduler fixture directory is missing")
    if not (source / "go.mod").is_file():
        raise AssertionError("scheduler fixture requires a Control Go checkout")
    output = folder / "rate-scheduler-fixture"
    if runner is None:
        runner = subprocess.run
    result = runner(
        ["go", "build", "-o", str(output), "./tests/e2e/rate_scheduler_fixture"],
        cwd=source, env=env, capture_output=True, text=True,
        timeout=120, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"scheduler fixture build failed: {result.stderr[-1600:]}")
    if not output.is_file():
        raise AssertionError("scheduler fixture build reported success without output")
    return output
