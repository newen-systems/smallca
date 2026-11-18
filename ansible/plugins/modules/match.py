#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca certificate match as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: match
short_description: Check a certificate, key and CSR belong together
version_added: 0.1.0
description:
- Compares the public keys of any two or three of O(cert), O(key) and O(csr). Fails when they differ,
  unless O(fail_on_mismatch=false).
- 'Runs the smallca binary on the target host, which is usually the control node through C(delegate_to:
  localhost).'
options:
  cert:
    description: Certificate file.
    type: path
  key:
    description: Private key file.
    type: path
  csr:
    description: CSR file.
    type: path
  password:
    description: Password of an encrypted key.
    type: str
  fail_on_mismatch:
    description: Fail the task when the keys differ.
    type: bool
    default: true
  smallca_path:
    description: Path to the smallca binary, or a name looked up in PATH.
    type: path
    default: smallca
attributes:
  check_mode:
    support: full
    description: Read-only; always runs.
  diff_mode:
    support: none
    description: Not supported.
author:
- smallca authors (@newen-systems)
"""

EXAMPLES = r"""
- name: Make sure the new certificate goes with the installed key
  newen_systems.smallca.match:
    cert: /etc/nginx/tls/new.crt
    key: /etc/nginx/tls/server.key
"""

RETURN = r"""
match:
  description: Whether the public keys are the same.
  returned: success
  type: bool
mismatch:
  description: Which inputs differ.
  returned: success
  type: str
public_keys:
  description: SHA-256 fingerprint of each input's public key.
  returned: success
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.newen_systems.smallca.plugins.module_utils.smallca import flags, run

ARGUMENT_SPEC = {
    'cert': {
        'type': 'path',
    },
    'key': {
        'type': 'path',
        'no_log': False,
    },
    'csr': {
        'type': 'path',
    },
    'password': {
        'type': 'str',
        'no_log': True,
    },
    'fail_on_mismatch': {
        'type': 'bool',
        'default': True,
    },
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('cert', '--cert', 'str'),
    ('key', '--key', 'str'),
    ('csr', '--csr', 'str'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[],
        required_one_of=[],
    )
    argv = ['certificate', 'match'] + flags(module.params, FLAGS)
    stdin = None
    rc, result = run(module, argv, password=module.params.get("password"), stdin=stdin, ok_codes=(0, 3), dry_run=False)
    if rc == 3 and module.params["fail_on_mismatch"]:
        module.fail_json(msg=result.get("mismatch") or "keys differ", **result)
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()
