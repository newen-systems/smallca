#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca leaf create as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: leaf
short_description: Issue a server, client (mTLS) or dual-use certificate
version_added: 0.1.0
description:
- Issues a certificate from an intermediate whose unencrypted key smallca can read. The key at O(key_out)
  is reused when present.
- A subject common name that is a dotted host name is always included as a DNS SAN.
- The certificate is re-issued when the request changes or it enters its renewal window (30 days, or the
  last third of a shorter lifetime).
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
  subject:
    description: Subject DN, or a bare host name.
    type: str
    required: true
  san:
    description: Subject alternative names. Values that parse as IP addresses become IP SANs, the rest
      DNS SANs.
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
  key_out:
    description: Private key output, mode 0600; reused if present.
    type: path
    required: true
  chain_out:
    description: Issuer chain output (the intermediate).
    type: path
  fullchain_out:
    description: Certificate then intermediate, what a server presents.
    type: path
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
- name: Server certificate for each web host
  newen_systems.smallca.leaf:
    issuer_cert: /srv/pki/issuing.crt
    issuer_key: /srv/pki/issuing.key
    subject: "{{ inventory_hostname }}"
    san: "{{ [ansible_host] + (extra_names | default([])) }}"
    cert_out: "/srv/pki/hosts/{{ inventory_hostname }}.crt"
    key_out: "/srv/pki/hosts/{{ inventory_hostname }}.key"
    fullchain_out: "/srv/pki/hosts/{{ inventory_hostname }}-fullchain.pem"
  delegate_to: localhost

- name: mTLS client certificate
  newen_systems.smallca.leaf:
    issuer_cert: /srv/pki/issuing.crt
    issuer_key: /srv/pki/issuing.key
    subject: CN=backup-agent,O=Example
    purpose: client
    san: [backup-agent.example.test]
    cert_out: /srv/pki/agent.crt
    key_out: /srv/pki/agent.key
  delegate_to: localhost
"""

RETURN = r"""
changed:
  description: Whether smallca wrote (or, in check mode, would write) a file.
  returned: always
  type: bool
cert:
  description: The cert reported by smallca.
  returned: success
  type: str
key:
  description: The key reported by smallca.
  returned: success
  type: str
chain:
  description: Chain output path, or the verified chain subjects.
  returned: success
  type: raw
fullchain:
  description: The fullchain reported by smallca.
  returned: success
  type: str
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
serial:
  description: The serial reported by smallca.
  returned: success
  type: str
fingerprint_sha256:
  description: The fingerprint sha256 reported by smallca.
  returned: success
  type: str
not_after:
  description: The not after reported by smallca.
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
    'subject': {
        'type': 'str',
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
    'key_out': {
        'type': 'path',
        'required': True,
    },
    'chain_out': {
        'type': 'path',
    },
    'fullchain_out': {
        'type': 'path',
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
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('issuer_cert', '--issuer-cert', 'str'),
    ('issuer_key', '--issuer-key', 'str'),
    ('subject', '--subject', 'str'),
    ('san', '--san', 'list'),
    ('purpose', '--purpose', 'str'),
    ('cert_out', '--cert-out', 'str'),
    ('key_out', '--key-out', 'str'),
    ('chain_out', '--chain-out', 'str'),
    ('fullchain_out', '--fullchain-out', 'str'),
    ('kty', '--kty', 'str'),
    ('crv', '--crv', 'str'),
    ('size', '--size', 'int'),
    ('not_after', '--not-after', 'str'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[],
        required_one_of=[],
    )
    argv = ['leaf', 'create'] + flags(module.params, FLAGS)
    stdin = None
    result = run(module, argv, password=None, stdin=stdin, ok_codes=(0,), dry_run=True)[1]
    module.exit_json(**result)


if __name__ == "__main__":
    main()
