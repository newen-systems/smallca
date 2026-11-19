#!/usr/bin/python
# Copyright 2026 the smallca authors
# SPDX-License-Identifier: Apache-2.0
"""smallca intermediate create as an Ansible module."""

from __future__ import annotations

DOCUMENTATION = r"""
module: intermediate
short_description: Create an intermediate CA key and root-signed certificate
version_added: 0.1.0
description:
- Generates an intermediate key (unencrypted, mode 0600) and a root-signed CA certificate, optionally
  as a kubernetes.io/tls Secret manifest for a cert-manager CA Issuer.
- An existing pair is kept when it matches the request; a mismatching one is an error, never silently
  replaced.
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
  subject:
    description: Intermediate subject DN.
    type: str
    required: true
  cert_out:
    description: Certificate output.
    type: path
    required: true
  key_out:
    description: Unencrypted key output, mode 0600.
    type: path
    required: true
  chain_out:
    description: Issuer chain output (the root).
    type: path
  fullchain_out:
    description: Intermediate then root.
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
      expiry. smallca's default is V(10y).
    type: str
  path_len:
    description: Path length constraint. smallca's default is 0.
    type: int
  permitted_dns:
    description: Permitted DNS domain name constraints.
    type: list
    elements: str
  k8s_secret_out:
    description: Also write a kubernetes.io/tls Secret manifest here, mode 0600.
    type: path
  k8s_secret_name:
    description: Secret metadata.name, with O(k8s_secret_out).
    type: str
  k8s_secret_namespace:
    description: Secret metadata.namespace.
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
- name: Issuing CA for cert-manager, limited to example.test
  newen_systems.smallca.intermediate:
    root_dir: /srv/pki/root
    password: "{{ root_password }}"
    subject: CN=Example Kubernetes Issuing CA
    cert_out: /srv/pki/k8s/issuing.crt
    key_out: /srv/pki/k8s/issuing.key
    permitted_dns: [example.test]
    k8s_secret_out: /srv/pki/k8s/issuing-secret.yaml
    k8s_secret_name: example-issuing-ca
    k8s_secret_namespace: cert-manager
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
key:
  description: Path of the private key file.
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
k8s_secret:
  description: Path of the kubernetes.io/tls Secret manifest, when requested.
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
    'subject': {
        'type': 'str',
        'required': True,
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
    'path_len': {
        'type': 'int',
    },
    'permitted_dns': {
        'type': 'list',
        'elements': 'str',
    },
    'k8s_secret_out': {
        'type': 'path',
    },
    'k8s_secret_name': {
        'type': 'str',
    },
    'k8s_secret_namespace': {
        'type': 'str',
        'no_log': False,
    },
    'smallca_path': {
        'type': 'path',
        'default': 'smallca',
    },
}

FLAGS = [
    ('subject', '--subject', 'str'),
    ('cert_out', '--cert-out', 'str'),
    ('key_out', '--key-out', 'str'),
    ('chain_out', '--chain-out', 'str'),
    ('fullchain_out', '--fullchain-out', 'str'),
    ('kty', '--kty', 'str'),
    ('crv', '--crv', 'str'),
    ('size', '--size', 'int'),
    ('not_after', '--not-after', 'str'),
    ('path_len', '--path-len', 'int'),
    ('permitted_dns', '--permitted-dns', 'list'),
    ('k8s_secret_out', '--k8s-secret-out', 'str'),
    ('k8s_secret_name', '--k8s-secret-name', 'str'),
    ('k8s_secret_namespace', '--k8s-secret-namespace', 'str'),
]


def main():
    module = AnsibleModule(
        argument_spec=ARGUMENT_SPEC,
        supports_check_mode=True,
        mutually_exclusive=[['root_dir', 'root_cert'], ['root_key', 'root_key_content']],
        required_one_of=[],
    )
    argv = ['intermediate', 'create'] + flags(module.params, FLAGS)
    stdin = None
    root_argv, stdin = root_flags(module)
    argv += root_argv
    result = run(module, argv, password=module.params.get("password"), stdin=stdin, ok_codes=(0,), dry_run=True)[1]
    module.exit_json(**result)


if __name__ == "__main__":
    main()
