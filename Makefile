# Local build, tests, lint, benches and fixture generation.
# All targets are idempotent; fixtures live under tests/fixtures/ (gitignored).

CARGO     ?= cargo
FIXTURES  := tests/fixtures
GEN       := target/release/gen_passwd
BIN       := target/release/rspassimpt
TIME      := /usr/bin/time -p

.DEFAULT_GOAL := help

.PHONY: help build release test fmt fmt-check lint clippy clean \
        gen-data gen-1k gen-100k gen-1m \
        bench run-dry-1k run-dry-100k run-dry-1m \
        check full-test

## help: Show the target list
help:
	@awk 'BEGIN {FS=":.*?## "} /^## / {sub(/^## /, "", $$0); split($$0, a, ": "); printf "  \033[36m%-16s\033[0m %s\n", a[1], a[2]}' $(MAKEFILE_LIST)

## build: Build with the debug profile
build:
	$(CARGO) build --all-targets

## release: Build with the release profile (rspassimpt + gen_passwd)
release:
	$(CARGO) build --release --bins

## test: Run unit and integration tests
test:
	$(CARGO) test --all-targets

## fmt: Format the code (cargo fmt)
fmt:
	$(CARGO) fmt --all

## fmt-check: Verify the code is formatted (CI mode)
fmt-check:
	$(CARGO) fmt --all -- --check

## lint: Run clippy with warnings treated as errors
lint clippy:
	$(CARGO) clippy --all-targets -- -D warnings

## clean: Remove build artifacts and fixtures
clean:
	$(CARGO) clean
	rm -rf $(FIXTURES)

$(FIXTURES):
	mkdir -p $@

# Fixtures for benches and load-style dry-runs.
# gen_passwd build is triggered via the release binary dependency.
$(GEN): release

## gen-1k: Generate tests/fixtures/passwd_1k.csv (1,000 rows)
gen-1k: $(FIXTURES) $(GEN)
	$(GEN) 1000 $(FIXTURES)/passwd_1k.csv

## gen-100k: Generate tests/fixtures/passwd_100k.csv (100,000 rows)
gen-100k: $(FIXTURES) $(GEN)
	$(GEN) 100000 $(FIXTURES)/passwd_100k.csv

## gen-1m: Generate tests/fixtures/passwd_1m.csv (1,000,000 rows)
gen-1m: $(FIXTURES) $(GEN)
	$(GEN) 1000000 $(FIXTURES)/passwd_1m.csv

## gen-data: Generate all three fixtures
gen-data: gen-1k gen-100k gen-1m

## bench: Run Criterion benches (generates 1k+100k fixtures if missing)
bench: gen-1k gen-100k
	$(CARGO) bench

# Convenience shortcuts for running a dry-run against a specific fixture.
run-dry-1k: gen-1k release
	$(TIME) $(BIN) $(FIXTURES)/passwd_1k.csv --dry-run --no-progress > /dev/null

run-dry-100k: gen-100k release
	$(TIME) $(BIN) $(FIXTURES)/passwd_100k.csv --dry-run --no-progress > /dev/null

run-dry-1m: gen-1m release
	$(TIME) $(BIN) $(FIXTURES)/passwd_1m.csv --dry-run --no-progress > /dev/null

## check: fmt-check + lint + test (a quick green/red signal)
check: fmt-check lint test

## full-test: Full pipeline — check, fixtures, benches, end-to-end dry-run
full-test: check gen-data bench
	@echo
	@echo "=== end-to-end dry-run (release) ==="
	@for size in 1k 100k 1m; do \
	  f=$(FIXTURES)/passwd_$$size.csv; \
	  echo "--> $$f"; \
	  $(TIME) $(BIN) $$f --dry-run --no-progress > /dev/null; \
	  echo; \
	done
