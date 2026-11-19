#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca certificate bundle as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: bundle
short_description: Put certificates into one ordered chain
version_added: 0.1.0
description:
- Orders certificates from several files into leaf-first chain order, drops duplicates and, unless O(include_root),
  the root. Fails on more than one chain.
- 'Runs the smallca binary on the target host, which is usually the control node through C(delegate_to:
  localhost).'
options:
  certs:
    description: Certificate files, any order.
    type: list
    required: true
    elements: path
  fullchain_out:
    description: Ordered chain output.
    type: path
    required: true
  include_root:
    description: Keep the self-signed root at the end.
    type: bool
    default: false
  smallca_path:
    description: Path to the smallca binary, or a name looked up in PATH.
    type: path
    default: smallca
attributes:
  check_mode:
    support: full
    description: 'Runs smallca with C(--dry-run): reports the change without writing.'
  diff_mode:
    support: none
    description: Not supported.
author:
- smallca authors (@newen-systems)
"""

EXAMPLES = r"""
- name: Build the chain a CA sent in pieces
  newen_systems.smallca.bundle:
    certs: [server.crt, intermediate2.crt, intermediate1.crt]
    fullchain_out: server-fullchain.pem
"""

RETURN = r"""
changed:
  description: Whether smallca wrote (or, in check mode, would write) a file.
  returned: always
  type: bool
fullchain:
  description: Path of the fullchain file, when requested.
  returned: success
  type: str
chain:
  description: Chain output path, or the verified chain subjects.
  returned: success
  type: raw
ends_at_root:
  description: Whether the chain ends at a self-signed root.
  returned: success
  type: bool
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.newen_systems.smallca.plugins.module_utils.smallca import flags, run

ARGUMENT_SPEC = {
    'certs': {
        'type': 'list',
        'required': True,
        'elements': 'path',
    },
    'fullchain_out': {
        'type': 'path',
        'required': True,
    },
    'include_root': {
        'type': 'bool',
        'default': False,
    },
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('certs', '--cert', 'list'),
    ('fullchain_out', '--fullchain-out', 'str'),
    ('include_root', '--include-root', 'bool'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[],
        required_one_of=[],
    )
    argv = ['certificate', 'bundle'] + flags(module.params, FLAGS)
    stdin = None
    result = run(module, argv, password=None, stdin=stdin, ok_codes=(0,), dry_run=True)[1]
    module.exit_json(**result)


if __name__ == "__main__":
    main()
