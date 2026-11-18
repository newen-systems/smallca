#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca intermediate sign as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: intermediate_sign
short_description: Sign a subordinate-CA CSR generated elsewhere, such as FreeIPA's
version_added: 0.1.0
description:
- Signs a subordinate-CA CSR with the root. The subject is copied byte for byte; the CA profile comes
  from the options, never from the CSR.
- An existing O(cert_out) for the same CSR key, subject and profile, outside its renewal window, is kept.
- 'Runs the smallca binary on the target host, which is usually the control node through C(delegate_to:
  localhost).'
options:
  root_dir:
    description: Directory from M(newen_systems.smallca.root) holding C(root.crt) and C(root.key). Use
      this or O(root_cert) with O(root_key) or O(root_key_content).
    type: path
  root_cert:
    description: Root certificate file, when the root does not live in O(root_dir).
    type: path
  root_key:
    description: Root private key file, when the root does not live in O(root_dir).
    type: path
  root_key_content:
    description: Root private key PEM, for example from a secret manager lookup. Sent to smallca on stdin;
      never written to disk.
    type: str
  password:
    description: Password of an encrypted root key. Sent through a pipe, never on the command line. Omit
      it for a root key stored in clear.
    type: str
  csr:
    description: CSR file (PEM or DER).
    type: path
    required: true
  cert_out:
    description: Signed CA certificate output.
    type: path
    required: true
  chain_out:
    description: Issuer chain output (the root).
    type: path
  fullchain_out:
    description: Certificate then root.
    type: path
  not_after:
    description: Validity as a duration (V(90d), V(10y), V(36h)) or an RFC 3339 time. Capped at the issuer's
      expiry. smallca's default is V(10y).
    type: str
  path_len:
    description: Path length constraint. smallca's default is 0.
    type: int
  permitted_dns:
    description: Permitted DNS domain name constraints.
    type: list
    elements: str
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
- name: Sign the FreeIPA CA CSR
  newen_systems.smallca.intermediate_sign:
    root_dir: /srv/pki/root
    password: "{{ root_password }}"
    csr: /srv/pki/ipa/ipa.csr
    cert_out: /srv/pki/ipa/ipa.crt
    chain_out: /srv/pki/ipa/ipa-chain.pem
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
serial:
  description: The serial reported by smallca.
  returned: success
  type: str
fingerprint_sha256:
  description: The fingerprint sha256 reported by smallca.
  returned: success
  type: str
root_fingerprint_sha256:
  description: The root fingerprint sha256 reported by smallca.
  returned: success
  type: str
not_after:
  description: The not after reported by smallca.
  returned: success
  type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.newen_systems.smallca.plugins.module_utils.smallca import flags, root_flags, run

ARGUMENT_SPEC = {
    'root_dir': {
        'type': 'path',
    },
    'root_cert': {
        'type': 'path',
    },
    'root_key': {
        'type': 'path',
    },
    'root_key_content': {
        'type': 'str',
        'no_log': True,
    },
    'password': {
        'type': 'str',
        'no_log': True,
    },
    'csr': {
        'type': 'path',
        'required': True,
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
    'path_len': {
        'type': 'int',
    },
    'permitted_dns': {
        'type': 'list',
        'elements': 'str',
    },
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('csr', '--csr', 'str'),
    ('cert_out', '--cert-out', 'str'),
    ('chain_out', '--chain-out', 'str'),
    ('fullchain_out', '--fullchain-out', 'str'),
    ('not_after', '--not-after', 'str'),
    ('path_len', '--path-len', 'int'),
    ('permitted_dns', '--permitted-dns', 'list'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[['root_dir', 'root_cert'], ['root_key', 'root_key_content']],
        required_one_of=[],
    )
    argv = ['intermediate', 'sign'] + flags(module.params, FLAGS)
    stdin = None
    root_argv, stdin = root_flags(module)
    argv += root_argv
    result = run(module, argv, password=module.params.get("password"), stdin=stdin, ok_codes=(0,), dry_run=True)[1]
    module.exit_json(**result)


if __name__ == "__main__":
    main()
