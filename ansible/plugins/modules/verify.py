#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca certificate verify as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: verify
short_description: Check a certificate chains to a root and is not about to expire
version_added: 0.1.0
description:
- Verifies O(path) (or a live server at O(url)) against O(roots), optionally for O(host), and that it
  has at least O(min_remaining) left.
- Fails the task when the check fails, unless O(fail_on_invalid=false); the result is in RV(valid) either
  way.
- 'Runs the smallca binary on the target host, which is usually the control node through C(delegate_to:
  localhost).'
options:
  path:
    description: Certificate file; further certificates are intermediates.
    type: path
  url:
    description: Verify the chain a TLS server presents.
    type: str
  servername:
    description: SNI name to send with O(url).
    type: str
  roots:
    description: Trusted root certificate(s). Optional with O(min_remaining).
    type: path
  chain:
    description: Intermediate certificates file.
    type: path
  host:
    description: DNS name the certificate must be valid for.
    type: str
  min_remaining:
    description: Fail when the certificate expires within this duration, for example V(30d).
    type: str
  fail_on_invalid:
    description: Fail the task when the check fails.
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
- name: Fail the deploy if the certificate has under 14 days left
  newen_systems.smallca.verify:
    path: /etc/nginx/tls/fullchain.pem
    roots: /srv/pki/root.crt
    host: www.example.test
    min_remaining: 14d
"""

RETURN = r"""
valid:
  description: Whether every check passed.
  returned: success
  type: bool
error:
  description: Why the check failed.
  returned: success
  type: str
subject:
  description: The subject reported by smallca.
  returned: success
  type: str
days_left:
  description: Whole days until expiry.
  returned: success
  type: int
chain:
  description: Chain output path, or the verified chain subjects.
  returned: success
  type: raw
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.newen_systems.smallca.plugins.module_utils.smallca import flags, run

ARGUMENT_SPEC = {
    'path': {
        'type': 'path',
    },
    'url': {
        'type': 'str',
    },
    'servername': {
        'type': 'str',
    },
    'roots': {
        'type': 'path',
    },
    'chain': {
        'type': 'path',
    },
    'host': {
        'type': 'str',
    },
    'min_remaining': {
        'type': 'str',
    },
    'fail_on_invalid': {
        'type': 'bool',
        'default': True,
    },
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('path', '--cert', 'str'),
    ('url', '--url', 'str'),
    ('servername', '--servername', 'str'),
    ('roots', '--roots', 'str'),
    ('chain', '--chain', 'str'),
    ('host', '--host', 'str'),
    ('min_remaining', '--min-remaining', 'str'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[['path', 'url']],
        required_one_of=[['path', 'url'], ['roots', 'min_remaining']],
    )
    argv = ['certificate', 'verify'] + flags(module.params, FLAGS)
    stdin = None
    rc, result = run(module, argv, password=None, stdin=stdin, ok_codes=(0, 3), dry_run=False)
    if rc == 3 and module.params["fail_on_invalid"]:
        module.fail_json(msg=result.get("error") or "check failed", **result)
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()
