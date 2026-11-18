# Contributing

Bug reports and pull requests are welcome. For a security issue, follow `SECURITY.md`
instead of opening an issue.

## Before you open a pull request

1. Open an issue first for anything larger than a bug fix, so the design can be agreed
   before you write code.
2. Keep the CLI contract in `docs/design/cli-conventions.md`: noun-verb commands, long
   kebab-case flags, one JSON object on stdout, idempotent re-runs, no prompts.
3. Run the checks CI runs:

   ```sh
   go vet ./...
   go test -race ./...
   staticcheck ./...
   govulncheck ./...
   ```

   The tests that cross-check with `openssl` skip themselves when it is not installed.

4. If you change any help text, regenerate the reference and commit it:

   ```sh
   go test ./internal/smallca -run TestReferenceDocs -update
   ```

5. Add an entry under `Unreleased` in `CHANGELOG.md`.

## Style

- Standard library first. A new dependency needs a reason in the pull request.
- Tests use `example.test`, `EXAMPLE.TEST` and the `192.0.2.0/24` documentation range,
  never real names or addresses.
- Commit subjects are short and imperative ("Add --foo to leaf create").

By contributing you agree that your contribution is licensed under the Apache License
2.0.
