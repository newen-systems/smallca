# FreeIPA with an external CA in one Ansible run

This guide installs a FreeIPA server whose CA is signed by a smallca root, in a single
`ansible-playbook` run. FreeIPA's external-CA install has two steps: the first writes a
CSR and stops, the second takes the signed certificate. smallca signs between them on
the control node.

## You need

- `smallca` on the Ansible control node (the path is `smallca_bin` below).
- The root password in a variable such as `smallca_root_password`, fetched from your
  secret manager. Never commit it.
- A host with the FreeIPA server packages installed.

## Playbook

```yaml
- name: FreeIPA server signed by smallca
  hosts: ipa_servers
  become: true
  vars:
    smallca_bin: /usr/local/bin/smallca
    ca_dir: "{{ playbook_dir }}/pki/root"
    work: "{{ playbook_dir }}/pki/{{ inventory_hostname }}"
    ipa_common: >-
      --unattended --realm EXAMPLE.TEST --domain example.test
      --ds-password {{ ipa_ds_password }} --admin-password {{ ipa_admin_password }}
  tasks:
    - name: Create the root once (kept on later runs)
      ansible.builtin.command:
        argv: ["{{ smallca_bin }}", root, create, --root-dir, "{{ ca_dir }}",
               --subject, "CN=Example Root CA,O=Example", --password-stdin]
        stdin: "{{ smallca_root_password }}"
      delegate_to: localhost
      become: false
      run_once: true
      register: root
      changed_when: (root.stdout | from_json).changed
      no_log: true

    - name: Step 1, write the CA CSR
      ansible.builtin.shell: "ipa-server-install {{ ipa_common }} --external-ca"
      args:
        creates: /root/ipa.csr
      no_log: true

    - name: Fetch the CSR
      ansible.builtin.fetch:
        src: /root/ipa.csr
        dest: "{{ work }}/ipa.csr"
        flat: true

    - name: Sign it
      ansible.builtin.command:
        argv: ["{{ smallca_bin }}", intermediate, sign, --root-dir, "{{ ca_dir }}",
               --csr, "{{ work }}/ipa.csr", --cert-out, "{{ work }}/ipa.crt",
               --chain-out, "{{ work }}/ipa-chain.pem", --password-stdin]
        stdin: "{{ smallca_root_password }}"
      delegate_to: localhost
      become: false
      register: signed
      changed_when: (signed.stdout | from_json).changed
      no_log: true

    - name: Copy the certificate and chain
      ansible.builtin.copy:
        src: "{{ work }}/{{ item }}"
        dest: "/root/{{ item }}"
        mode: "0644"
      loop: [ipa.crt, ipa-chain.pem]

    - name: Step 2, finish the install
      ansible.builtin.shell: >-
        ipa-server-install {{ ipa_common }}
        --external-cert-file=/root/ipa.crt --external-cert-file=/root/ipa-chain.pem
      args:
        creates: /etc/ipa/default.conf
      no_log: true
```

`no_log: true` keeps the passwords out of the output. The sign task reports `changed`
only when it really signed, so a second run of the playbook is all `ok`.

With the `freeipa.ansible_freeipa` collection, set `ipaserver_external_ca: true` for
the first pass and `ipaserver_external_cert_files: [/root/ipa.crt, /root/ipa-chain.pem]`
for the second, and keep the two smallca tasks between them.

## Choices

- `--chain-out` holds the issuer chain, here the root only, as on every smallca command. `--fullchain-out` gives the certificate then the
  root in one file if you prefer `--external-cert-file=/root/ipa-fullchain.pem`.
- The signed CA gets path length 0 by default, which blocks FreeIPA lightweight sub-CAs
  (`ipa ca-add`). Pass `--path-len 1` if you need them; the root must allow 2 or more
  (the default is 2).
- `--permitted-dns example.test` adds a critical name constraint so the realm CA can
  only issue for that domain.

## Check

```sh
smallca certificate verify --roots pki/root/root.crt --cert pki/ipa1/ipa.crt
```

On the server, `ipa ca-show ipa` shows the issuer as your root. To renew the realm CA
later, see `rotation.md`.
