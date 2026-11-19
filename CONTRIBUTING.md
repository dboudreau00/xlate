# Contributing to xlate

Issues and pull requests are welcome. xlate is a small gateway with a narrow job, so read [Deliberately out of scope](README.md#deliberately-out-of-scope) and [Architecture, design trade-offs and known limitations](README.md#architecture-design-trade-offs-and-known-limitations) before building a feature. Standard library only is a design rule: a change that needs a third-party dependency does not fit.

## Set up

The Go toolchain version is pinned in `go.mod`. The Makefile uses POSIX shell syntax, so on Windows run it from Git Bash or WSL, or run the commands by hand.

```sh
make check       # gofmt, vet, race tests and end-to-end: what CI gates on
make test        # unit, validation and regression tests
make lint        # staticcheck
make vuln        # govulncheck
make docs-check  # replays TUTORIAL.md against a real server
```

By hand: `gofmt -l .` must print nothing, then `go vet ./...`, `go test -race -count=1 ./...` and `go test -tags e2e -count=1 -timeout 10m ./...`.

## What a change needs

- **A test that fails without it.** A defect gets a regression test in `regression_test.go` or beside the code it touches. The data plane is reachable by partners, so anything that reads their input also gets a hostile-input case in `adversarial_test.go`.
- **No new dependencies.** `go.mod` has none, and CI runs staticcheck and govulncheck.
- **No payload value or credential in a log line, the audit trail or an error response.** At most a field name. The end-to-end suite checks that no payload or credential reaches a log.
- **Documentation that stays true.** When behavior a user can see changes, update the README and `TUTORIAL.md`, run `make docs-check`, and add a line under Unreleased in [CHANGELOG.md](CHANGELOG.md).

## Commits and pull requests

- Conventional commit subjects (`feat:`, `fix:`, `docs:`), imperative mood, one logical change per commit. The body says why.
- Open a pull request against `main`, say what changed and what you ran, and wait for CI.
