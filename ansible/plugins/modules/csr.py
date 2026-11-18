#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca csr create as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: csr
short_description: Create a key and a CSR for another CA
version_added: 0.1.0
description:
- Writes an unencrypted key (reused when present) and a CSR for it. An existing CSR for the same key,
  subject and SANs is kept.
- 'Runs the smallca binary on the target host, which is usually the control node through C(delegate_to:
  localhost).'
options:
  subject:
    description: Subject DN, or a bare host name.
    type: str
    required: true
  san:
    description: Subject alternative names. Values that parse as IP addresses become IP SANs, the rest
      DNS SANs.
    type: list
    elements: str
  key_out:
    description: Private key output, mode 0600; reused if present.
    type: path
    required: true
  csr_out:
    description: CSR output.
    type: path
    required: true
  kty:
    description: Key type for a new key. smallca's default is EC.
    type: str
    choices:
    - EC
    - RSA
  crv:
    description: EC curve for a new key.
    type: str
    choices:
    - P-256
    - P-384
  size:
    description: RSA key size for a new key. Default 3072.
    type: int
    choices:
    - 2048
    - 3072
    - 4096
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
- name: Key and CSR for a public CA
  newen_systems.smallca.csr:
    subject: www.example.test
    san: [example.test]
    key_out: /etc/pki/www.key
    csr_out: /etc/pki/www.csr
"""

RETURN = r"""
changed:
  description: Whether smallca wrote (or, in check mode, would write) a file.
  returned: always
  type: bool
key:
  description: The key reported by smallca.
  returned: success
  type: str
csr:
  description: The CSR, when the input is a CSR.
  returned: success
  type: dict
subject:
  description: The subject reported by smallca.
  returned: success
  type: str
dns_names:
  description: DNS SANs of the certificate.
  returned: success
  type: list
ip_addresses:
  description: IP SANs of the certificate.
  returned: success
  type: list
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.newen_systems.smallca.plugins.module_utils.smallca import flags, run

ARGUMENT_SPEC = {
    'subject': {
        'type': 'str',
        'required': True,
    },
    'san': {
        'type': 'list',
        'elements': 'str',
    },
    'key_out': {
        'type': 'path',
        'required': True,
    },
    'csr_out': {
        'type': 'path',
        'required': True,
    },
    'kty': {
        'type': 'str',
        'choices': ['EC', 'RSA'],
    },
    'crv': {
        'type': 'str',
        'choices': ['P-256', 'P-384'],
    },
    'size': {
        'type': 'int',
        'choices': [2048, 3072, 4096],
    },
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('subject', '--subject', 'str'),
    ('san', '--san', 'list'),
    ('key_out', '--key-out', 'str'),
    ('csr_out', '--csr-out', 'str'),
    ('kty', '--kty', 'str'),
    ('crv', '--crv', 'str'),
    ('size', '--size', 'int'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[],
        required_one_of=[],
    )
    argv = ['csr', 'create'] + flags(module.params, FLAGS)
    stdin = None
    result = run(module, argv, password=None, stdin=stdin, ok_codes=(0,), dry_run=True)[1]
    module.exit_json(**result)


if __name__ == "__main__":
    main()
