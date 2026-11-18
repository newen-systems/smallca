# Project name

Status: decided 2026-11-17: **smallca**.

## Requirements

- No existing CA project, Homebrew formula or Go module with the same name, so the
  binary does not collide on `$PATH` or in package managers.
- Plain enough to type in a playbook.

## Candidates

Checked on 2026-11-17 against GitHub repository names, Homebrew formulae and the Go
module proxy.

| Name | Taken by | Result |
|---|---|---|
| minica | jsha/minica: Go CA, about 3,300 stars, Homebrew formula `minica` | rejected |
| nanoca | brandonweeks/nanoca: active Go ACME CA | rejected |
| tinyca | TinyCA2: Perl CA, packaged as `tinyca` in Linux distributions | rejected |
| picoca | april/picoca: Python CA with the same pitch | rejected |
| littleca | dushitaoyuan/littleca: Java CA library | rejected |
| microca | eight small CA scripts with the exact name | rejected: crowded search |
| idemca, certwright | nothing | viable, coined words |
| **smallca** | nothing | **chosen**: plain English and unused |
