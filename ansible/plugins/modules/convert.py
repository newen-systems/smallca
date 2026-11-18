#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca certificate convert as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: convert
short_description: Convert, split or repackage certificates and keys between PEM, DER, PKCS#7 and PKCS#12
version_added: 0.1.0
description:
- Reads certificates and at most one private key from PEM, DER, PKCS#7 and PKCS#12 files, and writes each
  output named. Certificate outputs take their format from O(format), or from the file extension (C(.der)
  and C(.cer) are DER, C(.p7b) and C(.p7c) are PKCS#7, anything else is PEM).
- The end certificate is the one the private key matches, or without a key the one certificate that signed
  none of the others.
- 'Runs the smallca binary on the target host, which is usually the control node through C(delegate_to:
  localhost).'
options:
  inputs:
    description: Input files in any of the supported forms.
    type: list
    required: true
    elements: path
  format:
    description: Format of every certificate output. Default is from each file extension.
    type: str
    choices:
    - pem
    - der
    - p7b
  out:
    description: Every certificate, in input order.
    type: path
  cert_out:
    description: The end certificate.
    type: path
  chain_out:
    description: The issuers of the end certificate.
    type: path
  fullchain_out:
    description: The end certificate, then its issuers.
    type: path
  key_out:
    description: The private key, unencrypted PKCS#8 (mode 0600).
    type: path
  split_dir:
    description: Directory for one file per certificate.
    type: path
  p12_out:
    description: PKCS#12 output with the key, end certificate and issuers.
    type: path
  truststore_out:
    description: PKCS#12 trust store of every certificate, for Java.
    type: path
  password:
    description: Password of a PKCS#12 or encrypted key input, and of O(p12_out) or O(truststore_out).
      Sent through a pipe.
    type: str
  legacy:
    description: Use 3DES for systems that cannot read AES-256 PKCS#12.
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
- name: Split a PFX into PEM files for nginx
  newen_systems.smallca.convert:
    inputs: [/srv/pki/web.pfx]
    cert_out: /etc/nginx/tls/web.crt
    key_out: /etc/nginx/tls/web.key
    chain_out: /etc/nginx/tls/chain.pem
    password: "{{ pfx_password }}"
"""

RETURN = r"""
changed:
  description: Whether smallca wrote (or, in check mode, would write) a file.
  returned: always
  type: bool
certificates:
  description: One entry per certificate, in file order.
  returned: success
  type: list
has_key:
  description: Whether the input held a private key.
  returned: success
  type: bool
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.newen_systems.smallca.plugins.module_utils.smallca import flags, run

ARGUMENT_SPEC = {
    'inputs': {
        'type': 'list',
        'required': True,
        'elements': 'path',
    },
    'format': {
        'type': 'str',
        'choices': ['pem', 'der', 'p7b'],
    },
    'out': {
        'type': 'path',
    },
    'cert_out': {
        'type': 'path',
    },
    'chain_out': {
        'type': 'path',
    },
    'fullchain_out': {
        'type': 'path',
    },
    'key_out': {
        'type': 'path',
    },
    'split_dir': {
        'type': 'path',
    },
    'p12_out': {
        'type': 'path',
    },
    'truststore_out': {
        'type': 'path',
    },
    'password': {
        'type': 'str',
        'no_log': True,
    },
    'legacy': {
        'type': 'bool',
        'default': False,
    },
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('inputs', '--in', 'list'),
    ('format', '--format', 'str'),
    ('out', '--out', 'str'),
    ('cert_out', '--cert-out', 'str'),
    ('chain_out', '--chain-out', 'str'),
    ('fullchain_out', '--fullchain-out', 'str'),
    ('key_out', '--key-out', 'str'),
    ('split_dir', '--split-dir', 'str'),
    ('p12_out', '--p12-out', 'str'),
    ('truststore_out', '--truststore-out', 'str'),
    ('legacy', '--legacy', 'bool'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[],
        required_one_of=[['out', 'cert_out', 'chain_out', 'fullchain_out', 'key_out', 'split_dir', 'p12_out', 'truststore_out']],
    )
    argv = ['certificate', 'convert'] + flags(module.params, FLAGS)
    stdin = None
    result = run(module, argv, password=module.params.get("password"), stdin=stdin, ok_codes=(0,), dry_run=True)[1]
    module.exit_json(**result)


if __name__ == "__main__":
    main()
