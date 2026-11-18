"""Render ansible/plugins/modules/*.py from scripts/ansible-modules.yml, so each
module's documentation, argument spec and flag mapping cannot drift apart.

Run from the repository root after changing a command's flags:
    python3 scripts/gen-ansible-modules.py
CI fails when the committed modules differ from what this script renders.
Needs PyYAML."""

import os

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "ansible-modules.yml")
COLLECTION = os.path.join(HERE, "..", "ansible")
SANITY_VERSIONS = ("2.16", "2.17", "2.18", "2.19", "2.20", "2.21")
DOC_FIELDS = ("required", "default", "choices", "elements")
SPEC_FIELDS = DOC_FIELDS + ("no_log",)
CHANGED_RETURN = {
    "description": "Whether smallca wrote (or, in check mode, would write) a file.",
    "returned": "always",
    "type": "bool",
}
SMALLCA_PATH_OPTION = {
    "type": "path",
    "default": "smallca",
    "description": "Path to the smallca binary, or a name looked up in PATH.",
}
TARGET_NOTE = ("Runs the smallca binary on the target host, which is usually the control node "
               "through C(delegate_to: localhost).")
FAIL_SWITCH = {"verify": "fail_on_invalid", "mtls_verify": "fail_on_invalid", "match": "fail_on_mismatch"}
FAIL_MESSAGE = {"verify": 'result.get("error") or "check failed"',
                "mtls_verify": '"an mTLS check failed"',
                "match": 'result.get("mismatch") or "keys differ"'}


def to_yaml(data):
    return yaml.safe_dump(data, sort_keys=False, width=100, default_flow_style=False)


def pick(source, fields):
    return {f: source[f] for f in fields if f in source}


def documentation(m, opts):
    readonly = m.get("readonly", False)
    return {
        "module": m["name"],
        "short_description": m["short"],
        "version_added": "0.1.0",
        "description": m["desc"] + [TARGET_NOTE],
        "options": {k: {"description": v["description"], "type": v["type"], **pick(v, DOC_FIELDS)}
                    for k, v in opts.items()},
        "attributes": {
            "check_mode": {"support": "full",
                           "description": "Read-only; always runs." if readonly else
                           "Runs smallca with C(--dry-run): reports the change without writing."},
            "diff_mode": {"support": "none", "description": "Not supported."},
        },
        "author": ["smallca authors (@newen-systems)"],
    }


def returns(m, descriptions):
    out = {} if m.get("readonly") else {"changed": CHANGED_RETURN}
    for name in m["ret"]:
        d = descriptions.get(name, {"type": "str", "description": f"The {name.replace('_', ' ')} reported by smallca."})
        out[name] = {"description": d["description"], "returned": "success", "type": d["type"]}
    return out


def literal(value, indent):
    """Format a dict or list literal one entry per line."""
    pad = " " * indent
    if isinstance(value, dict):
        body = "".join(f"{pad}    {k!r}: {literal(v, indent + 4)},\n" for k, v in value.items())
        return "{\n" + body + pad + "}" if value else "{}"
    if isinstance(value, list) and value and isinstance(value[0], (list, tuple)):
        body = "".join(f"{pad}    {tuple(v)!r},\n" for v in value)
        return "[\n" + body + pad + "]"
    return repr(value)


def main_function(m):
    readonly = m.get("readonly", False)
    password = m.get("password") or ("password" if m.get("root") else None)
    exclusive = m.get("exclusive", [["root_dir", "root_cert"], ["root_key", "root_key_content"]] if m.get("root") else [])
    lines = [
        "def main():",
        "    module = AnsibleModule(",
        "        argument_spec=ARGUMENT_SPEC,",
        "        supports_check_mode=True,",
        f"        mutually_exclusive={exclusive!r},",
        f"        required_one_of={m.get('required_one_of', [])!r},",
        "    )",
        f"    argv = {m['cmd']!r} + flags(module.params, FLAGS)",
        "    stdin = None",
    ]
    if m.get("root"):
        lines += ["    root_argv, stdin = root_flags(module)", "    argv += root_argv"]
    pw = f'module.params.get("{password}")' if password else "None"
    ok = tuple(m.get("ok_codes", (0,)))
    call = f"run(module, argv, password={pw}, stdin=stdin, ok_codes={ok!r}, dry_run={not readonly})"
    lines.append(f"    rc, result = {call}" if m["name"] in FAIL_SWITCH else f"    result = {call}[1]")
    if m["name"] in FAIL_SWITCH:
        lines += [f'    if rc == 3 and module.params["{FAIL_SWITCH[m["name"]]}"]:',
                  f"        module.fail_json(msg={FAIL_MESSAGE[m['name']]}, **result)"]
    lines.append("    module.exit_json(changed=False, **result)" if readonly else "    module.exit_json(**result)")
    return "\n".join(lines) + "\n"


def render(m, descriptions):
    opts = dict(m["opts"])
    opts["smallca_path"] = SMALLCA_PATH_OPTION
    spec = {k: {"type": v["type"], **pick(v, SPEC_FIELDS)} for k, v in opts.items()}
    mapping = [[k, v["flag"], v.get("kind", "int" if v["type"] == "int" else "str")]
               for k, v in m["opts"].items() if "flag" in v]
    imports = "flags, root_flags, run" if m.get("root") else "flags, run"
    command = " ".join(c for c in m["cmd"] if not c.startswith("-"))
    return f'''#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca {command} as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
{to_yaml(documentation(m, opts))}"""

EXAMPLES = r"""
{m["example"]}"""

RETURN = r"""
{to_yaml(returns(m, descriptions))}"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.newen_systems.smallca.plugins.module_utils.smallca import {imports}

ARGUMENT_SPEC = {literal(spec, 0)}

FLAGS = {literal(mapping, 0)}


{main_function(m)}

if __name__ == "__main__":
    main()
'''


def main():
    with open(SPEC) as f:
        spec = yaml.safe_load(f)
    modules = spec["modules"]
    for m in modules:
        with open(os.path.join(COLLECTION, "plugins", "modules", m["name"] + ".py"), "w") as f:
            f.write(render(m, spec["return_descriptions"]))
    ignore = "".join(f"plugins/modules/{m['name']}.py validate-modules:missing-gplv3-license # Apache-2.0 collection\n"
                     for m in modules)
    os.makedirs(os.path.join(COLLECTION, "tests", "sanity"), exist_ok=True)
    for version in SANITY_VERSIONS:
        with open(os.path.join(COLLECTION, "tests", "sanity", f"ignore-{version}.txt"), "w") as f:
            f.write(ignore)
    print("rendered", len(modules))


if __name__ == "__main__":
    main()
