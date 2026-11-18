#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca mtls verify as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: mtls_verify
short_description: Check a server and a client trust each other for mutual TLS
version_added: 0.1.0
description:
- Offline, checks both trust directions, usages, host name and key matches. With O(url), connects to the
  live server as the client and reports whether it accepts the client certificate.
- Fails the task when a check fails, unless O(fail_on_invalid=false); RV(checks) lists each check with
  its reason.
- 'Runs the smallca binary on the target host, which is usually the control node through C(delegate_to:
  localhost).'
options:
  server_cert:
    description: Server certificate, intermediates after it.
    type: path
  server_key:
    description: Server private key, to check it matches.
    type: path
  server_trust:
    description: CA bundle the server trusts client certificates with.
    type: path
  client_cert:
    description: Client certificate, intermediates after it.
    type: path
    required: true
  client_key:
    description: Client private key; required with O(url).
    type: path
  client_trust:
    description: CA bundle the client trusts the server with.
    type: path
    required: true
  host:
    description: Name the client connects to (offline check).
    type: str
  url:
    description: 'Test a live server instead: host, host:port or https://host:port.'
    type: str
  servername:
    description: SNI name to send with O(url).
    type: str
  fail_on_invalid:
    description: Fail the task when a check fails.
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
- name: Will the agent and the API accept each other?
  newen_systems.smallca.mtls_verify:
    server_cert: /srv/pki/api-fullchain.pem
    server_trust: /srv/pki/root.crt
    client_cert: /srv/pki/agent-fullchain.pem
    client_trust: /srv/pki/root.crt
    host: api.example.test
"""

RETURN = r"""
valid:
  description: Whether every check passed.
  returned: success
  type: bool
checks:
  description: Each check with ok and detail.
  returned: success
  type: list
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.newen_systems.smallca.plugins.module_utils.smallca import flags, run

ARGUMENT_SPEC = {
    'server_cert': {
        'type': 'path',
    },
    'server_key': {
        'type': 'path',
        'no_log': False,
    },
    'server_trust': {
        'type': 'path',
    },
    'client_cert': {
        'type': 'path',
        'required': True,
    },
    'client_key': {
        'type': 'path',
        'no_log': False,
    },
    'client_trust': {
        'type': 'path',
        'required': True,
    },
    'host': {
        'type': 'str',
    },
    'url': {
        'type': 'str',
    },
    'servername': {
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
    ('server_cert', '--server-cert', 'str'),
    ('server_key', '--server-key', 'str'),
    ('server_trust', '--server-trust', 'str'),
    ('client_cert', '--client-cert', 'str'),
    ('client_key', '--client-key', 'str'),
    ('client_trust', '--client-trust', 'str'),
    ('host', '--host', 'str'),
    ('url', '--url', 'str'),
    ('servername', '--servername', 'str'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[],
        required_one_of=[],
    )
    argv = ['mtls', 'verify'] + flags(module.params, FLAGS)
    stdin = None
    rc, result = run(module, argv, password=None, stdin=stdin, ok_codes=(0, 3), dry_run=False)
    if rc == 3 and module.params["fail_on_invalid"]:
        module.fail_json(msg="an mTLS check failed", **result)
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()
