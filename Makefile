BIN ?= xlate
GO  ?= go

.PHONY: all build run fmt fmt-check vet lint test test-race e2e cover bench load docs-check docker demo demo-stop vuln check clean

all: check build

build:
	$(GO) build -o $(BIN) .

run: build
	./$(BIN) -listen :8080

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt required:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

# staticcheck is not vendored; install with
#   go install honnef.co/go/tools/cmd/staticcheck@latest
lint:
	staticcheck -checks=all ./...

# Unit, validation and regression tests.
test:
	$(GO) test ./...

test-race:
	$(GO) test -race -count=1 ./...

# End-to-end: builds the binary and drives it as a subprocess.
e2e:
	$(GO) test -tags e2e -count=1 -timeout 10m ./...

cover:
	$(GO) test -covermode=atomic -coverprofile=cover.out ./...
	$(GO) tool cover -func=cover.out | tail -n 1

bench:
	$(GO) test -bench . -benchmem -benchtime 2s -run '^$$' ./...

# Replays TUTORIAL.md against a real server and prints the actual
# responses, so the documented output cannot drift from reality.
docs-check:
	$(GO) test -tags tutorial -run TestTutorialTranscript -v ./...

# Sustained throughput and latency spread at several concurrency levels.
load:
	XLATE_LOAD=1 $(GO) test -run TestLoadProfile -v -timeout 10m ./...

# A fully populated demo: gateway, mock destination, dummy accounts and
# traffic. MINUTES=5 spreads the traffic so the dashboard chart has a
# profile instead of one spike. See demo/README.md.
VERSION := $(shell sed -n 's/^const version = "\(.*\)"/\1/p' main.go)

docker:
	docker build -t xlate:$(VERSION) -t xlate:latest .

demo:
	MINUTES=$(or $(MINUTES),1) ./demo/demo.sh

demo-stop:
	./demo/stop.sh --purge

# govulncheck is not vendored; install with
#   go install golang.org/x/vuln/cmd/govulncheck@latest
vuln:
	govulncheck ./...

# The gate CI runs.
check: fmt-check vet test-race e2e

clean:
	rm -f $(BIN) $(BIN).exe cover.out
