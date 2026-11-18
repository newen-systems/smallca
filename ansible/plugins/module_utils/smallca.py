# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""Shared runner for the smallca modules: builds the command line from module
parameters, passes secrets through pipes, and returns the binary's JSON."""

from __future__ import annotations

import json
import os


def flags(params, mapping):
    """Turn (param, flag, kind) triples into argv. kind is str, int, bool or list."""
    argv = []
    for name, flag, kind in mapping:
        value = params.get(name)
        if value is None or value is False or value == []:
            continue
        if kind == "bool":
            argv.append(flag)
        elif kind == "list":
            for item in value:
                argv += [flag, str(item)]
        else:
            argv += [flag, str(value)]
    return argv


def root_flags(module):
    """argv for the root location, plus the key content to send on stdin."""
    p = module.params
    if p.get("root_dir"):
        return ["--root-dir", p["root_dir"]], None
    if not p.get("root_cert") or not (p.get("root_key") or p.get("root_key_content")):
        module.fail_json(msg="give root_dir, or root_cert with root_key or root_key_content")
    if p.get("root_key_content"):
        return ["--root-cert", p["root_cert"], "--root-key", "-"], p["root_key_content"]
    return ["--root-cert", p["root_cert"], "--root-key", p["root_key"]], None


def run(module, args, password=None, stdin=None, ok_codes=(0,), dry_run=True):
    """Run smallca with args and return (rc, parsed stdout). The password goes
    through an inherited pipe (--password-fd), never argv or a file. With
    check mode and dry_run, --dry-run is added so nothing is written."""
    binary = module.params["smallca_path"]
    if os.sep not in binary:
        binary = module.get_bin_path(binary, required=True)
    argv = [binary] + list(args)
    if dry_run and module.check_mode:
        argv.append("--dry-run")
    pass_fds = ()
    read_fd = None
    if password is not None:
        read_fd, write_fd = os.pipe()
        with os.fdopen(write_fd, "w") as w:  # a password fits the pipe buffer
            w.write(password)
        argv += ["--password-fd", str(read_fd)]
        pass_fds = (read_fd,)
    try:
        rc, stdout, stderr = module.run_command(argv, data=stdin, binary_data=True, pass_fds=pass_fds,
                                                check_rc=False, close_fds=True)
    finally:
        if read_fd is not None:
            try:
                os.close(read_fd)
            except OSError:
                pass
    out = {}
    if stdout.strip():
        try:
            out = json.loads(stdout)
        except ValueError:
            module.fail_json(msg="smallca printed something that is not JSON", stdout=stdout)
    if rc not in ok_codes:
        try:
            err = json.loads(stderr.strip().splitlines()[-1])
        except (ValueError, IndexError):
            err = {"message": stderr}
        module.fail_json(msg=err.get("message", "smallca failed"), code=err.get("code"), rc=rc, **out)
    out.pop("schema_version", None)
    out.pop("dry_run", None)
    return rc, out
