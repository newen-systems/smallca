#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca certificate inspect as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: certificate_info
short_description: Read what is in a certificate, chain, CSR or live server
version_added: 0.1.0
description:
- Returns every certificate in O(path) (or the chain a TLS server presents at O(url)), or the CSR, as
  structured data. Never changes anything.
- 'Runs the smallca binary on the target host, which is usually the control node through C(delegate_to:
  localhost).'
options:
  path:
    description: Certificate, chain or CSR file.
    type: path
  url:
    description: 'TLS server to fetch the chain from: host, host:port or https://host:port.'
    type: str
  servername:
    description: SNI name to send with O(url).
    type: str
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
- name: Days left on the web certificate
  newen_systems.smallca.certificate_info:
    path: /etc/nginx/tls/fullchain.pem
  register: cert

- ansible.builtin.debug:
    msg: "{{ cert.certificates[0].days_left }} days left"
"""

RETURN = r"""
certificates:
  description: One entry per certificate, in file order.
  returned: success
  type: list
csr:
  description: The CSR, when the input is a CSR.
  returned: success
  type: dict
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
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('path', '--file', 'str'),
    ('url', '--url', 'str'),
    ('servername', '--servername', 'str'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[['path', 'url']],
        required_one_of=[['path', 'url']],
    )
    argv = ['certificate', 'inspect', '--json'] + flags(module.params, FLAGS)
    stdin = None
    result = run(module, argv, password=None, stdin=stdin, ok_codes=(0,), dry_run=False)[1]
    module.exit_json(changed=False, **result)


if __name__ == "__main__":
    main()
