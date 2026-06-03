# agents/Makefile — builds all PMX-Cloud fleet agents.
# Run: make -C agents all

.PHONY: all go-shared rust-shared lint test clean \
        build-agents build-go-agents build-rust-agents

GO_SHARED := shared
RUST_SHARED := shared-rust

all: go-shared rust-shared

# ── Reproducible agent binaries ──────────────────────────────────────────────
# Builds every deployable agent with the SAME deterministic flags as
# release.yml, into $(BIN_DIR). Used by reproducible-build-verify.yml to compare
# a host build against a Docker build. Override VERSION/COMMIT/SOURCE_DATE_EPOCH
# to pin identical inputs across builders (the verifier passes the same values
# to both), otherwise reproducibility cannot hold.
GO_AGENTS   := core telemetry hypervisor storage security backup console-broker hardware-installer
RUST_AGENTS := network updater
BIN_DIR           ?= $(CURDIR)/bin
GOARCH            ?= amd64
VERSION           ?= dev
COMMIT            ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
SOURCE_DATE_EPOCH ?= 0
# Default to cargo's real home so the path-prefix remap below is never an empty
# "--remap-path-prefix==/cargo" (rustc rejects an empty from-prefix).
CARGO_HOME        ?= $(HOME)/.cargo

build-agents: build-go-agents build-rust-agents

build-go-agents:
	@mkdir -p "$(BIN_DIR)"
	@for a in $(GO_AGENTS); do \
		echo "==> building pmx-$$a (go/$(GOARCH))"; \
		( cd "$$a" && GOOS=linux GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
			-trimpath -buildvcs=false \
			-ldflags="-s -w -buildid= -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildDate=$(SOURCE_DATE_EPOCH)" \
			-o "$(BIN_DIR)/pmx-$$a" "./cmd/pmx-$$a" ) || exit 1; \
	done

build-rust-agents:
	@mkdir -p "$(BIN_DIR)"
	@for a in $(RUST_AGENTS); do \
		echo "==> building pmx-$$a (rust)"; \
		( cd "$$a" && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
			RUSTFLAGS="--remap-path-prefix=$(HOME)=~ --remap-path-prefix=$(CARGO_HOME)=/cargo -C strip=symbols" \
			cargo build --release --locked ) || exit 1; \
		cp "$$a/target/release/pmx-$$a" "$(BIN_DIR)/pmx-$$a"; \
	done

## Go shared library
go-shared:
	@echo "==> Building Go shared library"
	cd $(GO_SHARED) && go build ./...

## Rust shared crate
rust-shared:
	@echo "==> Building Rust shared crate"
	cd $(RUST_SHARED) && cargo build --release

## Lint (Go)
lint-go:
	@echo "==> Linting Go"
	cd $(GO_SHARED) && go vet ./...
	cd $(GO_SHARED) && golangci-lint run

## Lint (Rust)
lint-rust:
	@echo "==> Linting Rust"
	cd $(RUST_SHARED) && cargo clippy -- -D warnings

lint: lint-go lint-rust

## Test (Go, with race detector)
test-go:
	@echo "==> Testing Go"
	cd $(GO_SHARED) && go test -race -cover ./...

## Test (Rust)
test-rust:
	@echo "==> Testing Rust"
	cd $(RUST_SHARED) && cargo test

test: test-go test-rust

## House-rule gates (same checks as CI)
gate-no-ipc:
	@echo "==> Checking for inter-agent IPC"
	@! grep -rn 'unix\.Dial\|net\.Dial("unix")' . --include='*.go' || \
		(echo "FAIL: IPC detected" && exit 1)
	@echo "PASS"

gate-no-json-envelope:
	@echo "==> Checking for JSON envelope signing"
	@! grep -rn 'json\.Marshal(envelope' . --include='*.go' || \
		(echo "FAIL: JSON envelope" && exit 1)
	@echo "PASS"

gates: gate-no-ipc gate-no-json-envelope

clean:
	cd $(GO_SHARED) && go clean ./...
	cd $(RUST_SHARED) && cargo clean
