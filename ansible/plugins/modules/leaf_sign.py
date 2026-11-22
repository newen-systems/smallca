#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca leaf sign as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: leaf_sign
short_description: Sign a server or client CSR generated elsewhere
version_added: 0.1.0
description:
- Signs a CSR from an appliance or service that keeps its own key. Only the subject and public key come
  from the CSR; usages are set by O(purpose). SANs come from the CSR unless O(san) replaces them.
- 'Runs the smallca binary on the target host, which is usually the control node through C(delegate_to:
  localhost).'
options:
  issuer_cert:
    description: Issuing intermediate certificate.
    type: path
    required: true
  issuer_key:
    description: Issuing intermediate private key (unencrypted).
    type: path
    required: true
  csr:
    description: CSR file (PEM or DER).
    type: path
    required: true
  san:
    description: Replace the CSR's SANs with these.
    type: list
    elements: str
  purpose:
    description: 'Extended key usage: V(server) (serverAuth), V(client) (clientAuth, for mTLS clients)
      or V(both). smallca''s default is V(server).'
    type: str
    choices:
    - server
    - client
    - both
  cert_out:
    description: Certificate output.
    type: path
    required: true
  chain_out:
    description: Issuer chain output (the intermediate).
    type: path
  fullchain_out:
    description: Certificate then intermediate.
    type: path
  not_after:
    description: Validity as a duration (V(90d), V(10y), V(36h)) or an RFC 3339 time. Capped at the issuer's
      expiry. smallca's default is V(90d).
    type: str
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
- name: Sign the switch's CSR
  newen_systems.smallca.leaf_sign:
    issuer_cert: /srv/pki/issuing.crt
    issuer_key: /srv/pki/issuing.key
    csr: /srv/pki/switch1.csr
    cert_out: /srv/pki/switch1.crt
  delegate_to: localhost
"""

RETURN = r"""
changed:
  description: Whether smallca wrote (or, in check mode, would write) a file.
  returned: always
  type: bool
cert:
  description: Path of the certificate file.
  returned: success
  type: str
chain:
  description: Chain output path, or the verified chain subjects.
  returned: success
  type: raw
fullchain:
  description: Path of the fullchain file, when requested.
  returned: success
  type: str
subject:
  description: Subject DN of the certificate.
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
    'issuer_cert': {
        'type': 'path',
        'required': True,
    },
    'issuer_key': {
        'type': 'path',
        'required': True,
        'no_log': False,
    },
    'csr': {
        'type': 'path',
        'required': True,
    },
    'san': {
        'type': 'list',
        'elements': 'str',
    },
    'purpose': {
        'type': 'str',
        'choices': ['server', 'client', 'both'],
    },
    'cert_out': {
        'type': 'path',
        'required': True,
    },
    'chain_out': {
        'type': 'path',
    },
    'fullchain_out': {
        'type': 'path',
    },
    'not_after': {
        'type': 'str',
    },
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('issuer_cert', '--issuer-cert', 'str'),
    ('issuer_key', '--issuer-key', 'str'),
    ('csr', '--csr', 'str'),
    ('san', '--san', 'list'),
    ('purpose', '--purpose', 'str'),
    ('cert_out', '--cert-out', 'str'),
    ('chain_out', '--chain-out', 'str'),
    ('fullchain_out', '--fullchain-out', 'str'),
    ('not_after', '--not-after', 'str'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[],
        required_one_of=[],
    )
    argv = ['leaf', 'sign'] + flags(module.params, FLAGS)
    stdin = None
    result = run(module, argv, password=None, stdin=stdin, ok_codes=(0,), dry_run=True)[1]
    module.exit_json(**result)


if __name__ == "__main__":
    main()
