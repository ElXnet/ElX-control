#!/usr/bin/env python3
"""Fast isolated structural regression before expensive PostgreSQL/VLESS E2E."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from stage4_workspace import (stage4_core_source,
                              ensure_disposable_technical_inbound_tag,
                              build_disposable_rate_fixture)


class PairedGoCheckoutTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="elx-workspace-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.control = self.root / "ElX-control"
        self.script = self.control / "tests" / "e2e" / "test_live_scheduler.py"
        self.script.parent.mkdir(parents=True)
        self.script.write_text("# disposable fixture\n", encoding="utf-8")
        self.core = self.root / "ElXray"
        self.core.mkdir()
        (self.core / "go.mod").write_text(
            "module github.com/xtls/xray-core\n\ngo 1.27\n", encoding="utf-8")

    def test_sibling_checkout_is_selected_not_nested_control(self):
        with patch.dict(os.environ, {"ELXRAY_SOURCE": ""}):
            self.assertEqual(stage4_core_source(self.script), self.core.resolve())

    def test_explicit_source_matches_compiled_core_checkout(self):
        another = self.root / "custom" / "ElXray"
        another.mkdir(parents=True)
        (another / "go.mod").write_text(
            "module github.com/xtls/xray-core\n", encoding="utf-8")
        with patch.dict(os.environ, {"ELXRAY_SOURCE": str(another)}):
            self.assertEqual(stage4_core_source(self.script), another.resolve())

    def test_missing_or_wrong_module_fails_before_any_mutation(self):
        (self.core / "go.mod").unlink()
        with patch.dict(os.environ, {"ELXRAY_SOURCE": ""}):
            with self.assertRaisesRegex(AssertionError, "missing paired"):
                stage4_core_source(self.script)
        (self.core / "go.mod").write_text(
            "module example.com/unrelated\n", encoding="utf-8")
        with patch.dict(os.environ, {"ELXRAY_SOURCE": ""}):
            with self.assertRaisesRegex(AssertionError, "unexpected ElXray"):
                stage4_core_source(self.script)

    def test_nested_checkout_or_control_module_never_substitutes_for_core(self):
        nested = self.control / "ElXray"
        nested.mkdir()
        (nested / "go.mod").write_text(
            "module github.com/xtls/xray-core\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "separate source"):
            stage4_core_source(self.script, str(nested))
        with self.assertRaisesRegex(AssertionError, "separate source"):
            stage4_core_source(self.script, str(self.control))



class DisposableTaggedVLESSTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="elx-technical-vless-")
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name) / "server.json"

    def test_old_untagged_static_vless_becomes_stably_tagged(self):
        self.config.write_text(json.dumps({"inbounds": [
            {"protocol": "vless", "settings": {"clients": [{"id": "test"}]}}]}),
            encoding="utf-8")
        tag = ensure_disposable_technical_inbound_tag(self.config, 0)
        self.assertEqual(tag, "elx-technical-vless-0")
        self.assertEqual(ensure_disposable_technical_inbound_tag(self.config, 0), tag)
        self.assertEqual(json.loads(self.config.read_text())["inbounds"][0]["tag"], tag)

    def test_preserves_explicit_tag_without_changing_protocol(self):
        self.config.write_text(json.dumps({"inbounds": [
            {"protocol": "vless", "tag": "existing-tag"},
            {"protocol": "socks", "tag": "other-proxy"}]}), encoding="utf-8")
        self.assertEqual(ensure_disposable_technical_inbound_tag(self.config, 1), "existing-tag")

    def test_invalid_or_duplicate_vless_fails_without_static_bypass(self):
        for candidate in (
            {"inbounds": []},
            {"inbounds": [{"protocol": "socks"}]},
            {"inbounds": [{"protocol": "vless"}, {"protocol": "vless"}]},
            {"inbounds": [{"protocol": "vless", "tag": "duplicate"},
                          {"protocol": "socks", "tag": "duplicate"}]},
            {"inbounds": [{"protocol": "vless", "tag": "x" * 129}]},
            {"inbounds": "not-a-list"},
        ):
            self.config.write_text(json.dumps(candidate), encoding="utf-8")
            with self.assertRaises(AssertionError):
                ensure_disposable_technical_inbound_tag(self.config, 0)


class DisposableRateFixtureBuildTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="elx-rate-fixture-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.lab = self.root / "isolated-lab"
        self.lab.mkdir()
        self.control = self.root / "ElX-control"
        self.control.mkdir()
        (self.control / "go.mod").write_text(
            "module github.com/ElXnet/ElX-control\\n", encoding="utf-8")
        self.env = {"ELX_CONTROL_POSTGRES_DSN": "dbname=elx_test"}

    def test_each_lab_compiles_its_own_binary_before_seed(self):
        def successful_build(args, **kw):
            self.assertEqual(args[:3], ["go", "build", "-o"])
            self.assertEqual(args[4], "./tests/e2e/rate_scheduler_fixture")
            self.assertEqual(kw["cwd"], self.control.resolve())
            self.assertEqual(kw["env"], self.env)
            self.assertFalse(kw["check"])
            Path(args[3]).write_bytes(b"disposable test executable")
            return SimpleNamespace(returncode=0, stderr="")

        output = build_disposable_rate_fixture(
            self.lab, self.control, self.env, runner=successful_build)
        self.assertEqual(output.parent, self.lab.resolve())
        self.assertTrue(output.is_file())
        # A different temporary lab must not inherit the first lab's path.
        other = self.root / "second-lab"
        other.mkdir()
        second = build_disposable_rate_fixture(
            other, self.control, self.env, runner=successful_build)
        self.assertNotEqual(output, second)

    def test_failed_compiler_never_starts_managed_fixture(self):
        def fail_build(*_args, **_kwargs):
            return SimpleNamespace(returncode=1, stderr="intentional build failure")
        with self.assertRaisesRegex(AssertionError, "intentional build failure"):
            build_disposable_rate_fixture(
                self.lab, self.control, self.env, runner=fail_build)

    def test_false_success_without_executable_fails_closed(self):
        def missing_output(*_args, **_kwargs):
            return SimpleNamespace(returncode=0, stderr="")
        with self.assertRaisesRegex(AssertionError, "without output"):
            build_disposable_rate_fixture(
                self.lab, self.control, self.env, runner=missing_output)


if __name__ == "__main__":
    unittest.main()
