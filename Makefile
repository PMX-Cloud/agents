# agents/Makefile — builds all PMX-Cloud fleet agents.
# Run: make -C agents all

.PHONY: all go-shared rust-shared lint test clean

GO_SHARED := shared
RUST_SHARED := shared-rust

all: go-shared rust-shared

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
