#!/usr/bin/env python3
"""Fast isolated structural regression before expensive PostgreSQL/VLESS E2E."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from stage4_workspace import stage4_core_source, ensure_disposable_technical_inbound_tag


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

if __name__ == "__main__":
    unittest.main()
