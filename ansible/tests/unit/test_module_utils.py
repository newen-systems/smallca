# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for plugins/module_utils/smallca.py against a fake smallca binary."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "plugins", "module_utils"))
import smallca  # noqa: E402

FAKE = textwrap.dedent('''\
    #!PYTHON
    """Fake smallca: echoes what it received, or fails on request."""
    import json, os, sys
    args = sys.argv[1:]
    out = {"schema_version": 1, "args": args, "stdin": sys.stdin.read()}
    if "--password-fd" in args:
        fd = int(args[args.index("--password-fd") + 1])
        with os.fdopen(fd) as f:
            out["password"] = f.read()
    if "--fail" in args:
        sys.stderr.write(json.dumps({"schema_version": 1, "code": "boom", "message": "it broke"}) + "\\n")
        sys.exit(1)
    if "--invalid" in args:
        print(json.dumps({"schema_version": 1, "valid": False}))
        sys.exit(3)
    if "--garbage" in args:
        print("not json")
        sys.exit(0)
    if "--dry-run" in args:
        out["dry_run"] = True
    print(json.dumps(out))
''').replace("PYTHON", sys.executable)


class Failed(Exception):
    pass


class FakeModule:
    """The parts of AnsibleModule that module_utils uses."""

    def __init__(self, binary, params=None, check_mode=False):
        self.params = {"smallca_path": binary, **(params or {})}
        self.check_mode = check_mode

    def fail_json(self, **kwargs):
        raise Failed(kwargs)

    def get_bin_path(self, name, required=False):
        return name

    def run_command(self, args, data=None, binary_data=False, pass_fds=(), check_rc=False, close_fds=True):
        proc = subprocess.run(args, input=(data or "").encode(), capture_output=True, pass_fds=pass_fds,
                              close_fds=close_fds, check=check_rc)
        return proc.returncode, proc.stdout.decode(), proc.stderr.decode()


@pytest.fixture
def fake(tmp_path):
    path = tmp_path / "smallca"
    path.write_text(FAKE)
    path.chmod(0o755)
    return str(path)


def test_flags():
    params = {"a": "x", "n": 3, "b": True, "off": False, "none": None, "l": ["p", "q"], "empty": []}
    mapping = [("a", "--a", "str"), ("n", "--n", "int"), ("b", "--b", "bool"), ("off", "--off", "bool"),
               ("none", "--none", "str"), ("l", "--l", "list"), ("empty", "--empty", "list")]
    assert smallca.flags(params, mapping) == ["--a", "x", "--n", "3", "--b", "--l", "p", "--l", "q"]


def test_root_flags(fake):
    assert smallca.root_flags(FakeModule(fake, {"root_dir": "/r"})) == (["--root-dir", "/r"], None)
    assert smallca.root_flags(FakeModule(fake, {"root_cert": "c", "root_key": "k"})) == (
        ["--root-cert", "c", "--root-key", "k"], None)
    assert smallca.root_flags(FakeModule(fake, {"root_cert": "c", "root_key_content": "PEM"})) == (
        ["--root-cert", "c", "--root-key", "-"], "PEM")
    incomplete = FakeModule(fake, {"root_cert": "c"})
    with pytest.raises(Failed):
        smallca.root_flags(incomplete)


def test_run_passes_password_through_a_pipe_and_stdin(fake):
    rc, out = smallca.run(FakeModule(fake), ["leaf", "create"], password="s3cret", stdin="PEM")
    assert rc == 0
    assert out["password"] == "s3cret"
    assert out["stdin"] == "PEM"
    assert "s3cret" not in out["args"]
    assert "schema_version" not in out


def test_run_check_mode_adds_dry_run(fake):
    out = smallca.run(FakeModule(fake, check_mode=True), ["leaf", "create"])[1]
    assert out["args"][-1] == "--dry-run"
    assert "dry_run" not in out
    out = smallca.run(FakeModule(fake, check_mode=True), ["certificate", "verify"], dry_run=False)[1]
    assert "--dry-run" not in out["args"]


def test_run_errors(fake):
    module = FakeModule(fake)
    with pytest.raises(Failed) as e:
        smallca.run(module, ["--fail"])
    assert e.value.args[0]["msg"] == "it broke"
    assert e.value.args[0]["code"] == "boom"
    with pytest.raises(Failed):
        smallca.run(module, ["--garbage"])
    with pytest.raises(Failed):
        smallca.run(module, ["--invalid"])
    rc, out = smallca.run(module, ["--invalid"], ok_codes=(0, 3))
    assert rc == 3
    assert out["valid"] is False


def test_run_looks_up_a_bare_name(fake, monkeypatch):
    seen = []
    module = FakeModule("smallca")
    module.get_bin_path = lambda name, required=False: seen.append(name) or fake
    smallca.run(module, ["version"])
    assert seen == ["smallca"]
