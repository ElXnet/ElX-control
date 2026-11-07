#!/usr/bin/env python3
"""Refuse test-runner database credentials unless they target a local elx_test.

Reads ONLY the named environment variable, never prints its DSN. Supports
standard libpq keyword/value strings and PostgreSQL URLs. A database name
substring in the password, hostname, or options is NOT authorization.
"""
import os
import shlex
import sys
from urllib.parse import parse_qs, unquote, urlsplit


def disposable(dsn):
    if not dsn or "\x00" in dsn:
        return False
    try:
        if dsn.startswith(("postgres://", "postgresql://")):
            url = urlsplit(dsn)
            if url.scheme not in ("postgres", "postgresql"):
                return False
            if not url.hostname or url.hostname not in ("127.0.0.1", "::1"):
                return False
            if url.port is None or not 0 < url.port <= 65535:
                return False
            options = parse_qs(url.query, keep_blank_values=True)
            # libpq query parameters can override the URI authority. Reject
            # any option that redirects the target or uses an external service.
            if set(options).intersection(("host", "hostaddr", "port", "dbname",
                                          "database", "service", "servicefile")):
                return False
            if unquote(url.path.lstrip("/")) != "elx_test":
                return False
            return True
        settings = {}
        for part in shlex.split(dsn):
            if "=" not in part:
                return False
            key, value = part.split("=", 1)
            if not key or key in settings:
                return False
            settings[key] = value
        if any(key in settings for key in ("hostaddr", "service", "servicefile")):
            return False
        if settings.get("host") not in ("127.0.0.1", "::1"):
            return False
        if settings.get("dbname") != "elx_test":
            return False
        port = int(settings.get("port", "0"))
        return 0 < port <= 65535
    except (ValueError, UnicodeError):
        return False


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: guard-disposable-postgres.py ENV_VARIABLE")
    key = sys.argv[1]
    # Never include secret-bearing DSN values in an exception or log.
    if not key.startswith(("ELX_", "XUI_")) or not key.endswith("DSN"):
        sys.exit("FAIL: invalid variable name for disposable database gate")
    if not disposable(os.environ.get(key, "")):
        sys.exit(f"FAIL: {key} must target only 127.0.0.1/::1 with exact dbname elx_test and an explicit port")
    print(f"PASS: {key} is scoped to an explicit loopback disposable elx_test database")


if __name__ == "__main__":
    main()
