#!/usr/bin/env python3
"""Regression test: local ElX tests can never silently target an operator DB."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().with_name("guard-disposable-postgres.py")
spec = importlib.util.spec_from_file_location("postgres_guard", path)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class DisposablePostgresGuardTests(unittest.TestCase):
    def test_accept_explicit_disposable_loopback(self):
        valid = (
            "host=127.0.0.1 port=5432 user=elx dbname=elx_test password=only_test sslmode=disable",
            "host=::1 port=65432 dbname=elx_test",
            "postgres://user:pw@127.0.0.1:5432/elx_test?sslmode=disable",
            "postgresql://user:pw@[::1]:65432/elx_test",
        )
        for dsn in valid:
            with self.subTest(dsn=dsn):
                self.assertTrue(guard.disposable(dsn))

    def test_reject_production_or_ambiguous_targets(self):
        invalid = (
            "",
            "host=127.0.0.1 port=5432 dbname=elx",
            "host=prod.example port=5432 dbname=elx_test",
            "host=127.0.0.1 port=5432 dbname=production password=elx_test",
            "host=127.0.0.1 port=5432 dbname=elx_test hostaddr=10.0.0.2",
            "host=127.0.0.1 port=5432 dbname=elx_test service=production",
            "host=127.0.0.1 dbname=elx_test",
            "port=5432 dbname=elx_test",
            "host=127.0.0.1 port=0 dbname=elx_test",
            "host=127.0.0.1 port=5432 dbname=elx_test dbname=production",
            "postgres://user:pw@remote.invalid:5432/elx_test",
            "postgres://user:pw@127.0.0.1:5432/production?password=elx_test",
            "postgres://user:pw@127.0.0.1:5432/elx_test?host=10.0.0.2",
            "postgres://user:pw@127.0.0.1:5432/elx_test?service=production",
            "postgres://user:pw@127.0.0.1/elx_test",
            "postgres://user:pw@127.0.0.1:5432/elx_test?port=5433",
        )
        for dsn in invalid:
            with self.subTest(dsn=dsn):
                self.assertFalse(guard.disposable(dsn))


if __name__ == "__main__":
    unittest.main()
