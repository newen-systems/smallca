#!/usr/bin/env bash
# End-to-end regression test of the built binary: every command once, then
# again to prove the second run changes nothing. Usage: scripts/e2e.sh [binary]
set -euo pipefail

bin=${1:-}
if [ -z "$bin" ]; then
  bin=$(mktemp -d)/smallca
  go build -buildvcs=false -o "$bin" ./cmd/smallca
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
fails=0

# expect CODE CHANGED -- ARGS...: run smallca, check exit code and "changed".
expect() {
  local code=$1 changed=$2; shift 3
  local out rc=0
  out=$("$bin" "$@" 2>err.txt) || rc=$?
  if [ "$rc" != "$code" ]; then
    echo "FAIL rc=$rc want $code: smallca $*"; cat err.txt; fails=$((fails + 1)); return
  fi
  if [ "$changed" != "-" ] && ! grep -q "\"changed\":$changed" <<<"$out"; then
    echo "FAIL changed!=$changed: smallca $*"; echo "$out"; fails=$((fails + 1)); return
  fi
  echo "ok   smallca $*"
}

printf 'e2e-password\n' > root.pass
printf 'pfx-password\n' > pfx.pass
openssl_csr() { openssl req -new -newkey rsa:2048 -nodes -keyout "$1.key" -subj "$2" -out "$1.csr" 2>/dev/null; }

for pass in 1 2; do
  [ "$pass" = 1 ] && c=true || c=false
  expect 0 $c -- root create --root-dir ca --subject "CN=E2E Root,O=Example" --password-file root.pass
  expect 0 $c -- intermediate create --root-dir ca --subject "CN=E2E Issuing" --cert-out i.crt --key-out i.key \
    --fullchain-out i-full.pem --permitted-dns example.test --password-file root.pass
  expect 0 $c -- leaf create --issuer-cert i.crt --issuer-key i.key --subject api.example.test --san 192.0.2.40 \
    --cert-out s.crt --key-out s.key --fullchain-out s-full.pem
  expect 0 $c -- leaf create --issuer-cert i.crt --issuer-key i.key --subject "CN=agent" --san agent.example.test \
    --purpose client --cert-out c.crt --key-out c.key --fullchain-out c-full.pem
  expect 0 $c -- csr create --subject app.example.test --key-out app.key --csr-out app.csr
  expect 0 $c -- leaf sign --issuer-cert i.crt --issuer-key i.key --csr app.csr --cert-out app.crt
  expect 0 $c -- certificate bundle --cert ca/root.crt --cert s.crt --cert i.crt --fullchain-out bundle.pem
  expect 0 $c -- certificate convert --in s.crt --in s.key --in i.crt --p12-out s.pfx --password-file pfx.pass
  expect 0 $c -- certificate convert --in s.pfx --password-file pfx.pass --cert-out s-from-p12.der --key-out s-from-p12.key \
    --chain-out s-from-p12-chain.pem
  expect 0 $c -- certificate convert --in bundle.pem --out bundle.p7b --split-dir split --format pem
  expect 0 $c -- certificate convert --in i.crt --in ca/root.crt --truststore-out trust.p12 --password-file pfx.pass
  if command -v openssl >/dev/null; then
    [ "$pass" = 1 ] && openssl_csr ipa "/O=EXAMPLE.TEST/CN=Certificate Authority"
    expect 0 $c -- intermediate sign --root-dir ca --csr ipa.csr --cert-out ipa.crt --chain-out ipa-chain.pem \
      --password-file root.pass
  fi
done

expect 0 false -- leaf create --issuer-cert i.crt --issuer-key i.key --subject api.example.test --san 192.0.2.40 \
  --cert-out s.crt --key-out s.key --fullchain-out s-full.pem --dry-run
expect 0 true -- leaf create --issuer-cert i.crt --issuer-key i.key --subject new.example.test \
  --cert-out new.crt --key-out new.key --dry-run
[ ! -e new.crt ] && echo "ok   dry run wrote nothing" || { echo "FAIL dry run wrote new.crt"; fails=$((fails + 1)); }
expect 0 - -- certificate verify --roots ca/root.crt --cert s-full.pem --host api.example.test --min-remaining 30d
expect 3 - -- certificate verify --roots ca/root.crt --cert s-full.pem --host wrong.example.test
expect 0 - -- certificate match --cert app.crt --key app.key --csr app.csr
expect 3 - -- certificate match --cert app.crt --key s.key
expect 0 - -- mtls verify --server-cert s-full.pem --server-key s.key --server-trust ca/root.crt \
  --client-cert c-full.pem --client-key c.key --client-trust ca/root.crt --host api.example.test
expect 3 - -- mtls verify --server-cert s-full.pem --server-trust ca/root.crt \
  --client-cert s-full.pem --client-trust ca/root.crt
expect 0 - -- certificate inspect --file bundle.pem --json
expect 2 - -- root create --root-dir ca
expect 2 - -- no such command
text=$("$bin" certificate inspect --file s-full.pem)
if grep -q "Certificate 2 of 2" <<<"$text"; then echo "ok   inspect text"; else echo "FAIL inspect text"; fails=$((fails + 1)); fi

if [ "$fails" -gt 0 ]; then echo "$fails check(s) failed"; exit 1; fi
echo "all end-to-end checks passed"
