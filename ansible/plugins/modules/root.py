#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca root create as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: root
short_description: Create a root CA, or check the existing one
version_added: 0.1.0
description:
- Creates C(root.crt) and C(root.key) in O(root_dir), the key encrypted with O(password).
- An existing root is decrypted and checked, never overwritten; a different O(subject) is an error.
- 'Runs the smallca binary on the target host, which is usually the control node through C(delegate_to:
  localhost).'
options:
  root_dir:
    description: Directory for C(root.crt) and C(root.key), created mode 0700.
    type: path
    required: true
  subject:
    description: Root subject DN, for example V(CN=Example Root CA,O=Example).
    type: str
    required: true
  password:
    description: Password that encrypts the root key. Sent through a pipe, never on the command line.
    type: str
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
  not_after:
    description: Validity as a duration (V(90d), V(10y), V(36h)) or an RFC 3339 time. Capped at the issuer's
      expiry. smallca's default is V(20y).
    type: str
  path_len:
    description: Path length constraint. smallca's default is 2.
    type: int
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
- name: Create the lab root once
  newen_systems.smallca.root:
    root_dir: /srv/pki/root
    subject: CN=Example Root CA,O=Example
    password: "{{ lookup('community.hashi_vault.hashi_vault', 'secret=secret/data/pki/root:password') }}"
  delegate_to: localhost
  run_once: true
"""

RETURN = r"""
changed:
  description: Whether smallca wrote (or, in check mode, would write) a file.
  returned: always
  type: bool
root_cert:
  description: Path of the root certificate.
  returned: success
  type: str
root_key:
  description: Path of the encrypted root key.
  returned: success
  type: str
subject:
  description: Subject DN of the certificate.
  returned: success
  type: str
serial:
  description: Certificate serial number, in decimal.
  returned: success
  type: str
fingerprint_sha256:
  description: SHA-256 fingerprint of the certificate, prefixed C(sha256:).
  returned: success
  type: str
not_after:
  description: Expiry time, RFC 3339 in UTC.
  returned: success
  type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.newen_systems.smallca.plugins.module_utils.smallca import flags, run

ARGUMENT_SPEC = {
    'root_dir': {
        'type': 'path',
        'required': True,
    },
    'subject': {
        'type': 'str',
        'required': True,
    },
    'password': {
        'type': 'str',
        'required': True,
        'no_log': True,
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
    'not_after': {
        'type': 'str',
    },
    'path_len': {
        'type': 'int',
    },
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('root_dir', '--root-dir', 'str'),
    ('subject', '--subject', 'str'),
    ('kty', '--kty', 'str'),
    ('crv', '--crv', 'str'),
    ('size', '--size', 'int'),
    ('not_after', '--not-after', 'str'),
    ('path_len', '--path-len', 'int'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[],
        required_one_of=[],
    )
    argv = ['root', 'create'] + flags(module.params, FLAGS)
    stdin = None
    result = run(module, argv, password=module.params.get("password"), stdin=stdin, ok_codes=(0,), dry_run=True)[1]
    module.exit_json(**result)


if __name__ == "__main__":
    main()
