#!/usr/bin/env bash
# Integration test of the Ansible collection against a freshly built binary.
# Usage: scripts/ansible-test.sh   (needs ansible-core in PATH)
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
go build -o "$tmp/bin/smallca" "$repo/cmd/smallca"
mkdir -p "$tmp/collections/ansible_collections/newen_systems"
ln -s "$repo/ansible" "$tmp/collections/ansible_collections/newen_systems/smallca"
mkdir -p "$tmp/work"
PATH="$tmp/bin:$PATH" ANSIBLE_COLLECTIONS_PATH="$tmp/collections" ANSIBLE_NOCOLOR=1 \
  ansible-playbook -i localhost, "$repo/ansible/tests/integration.yml" -e "work_dir=$tmp/work"
