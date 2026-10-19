SHELL := /bin/bash
export PATH := $(CURDIR)/.tools:$(PATH)
CARGO ?= cargo
PYTHON ?= python3
TERRAFORM ?= terraform

.PHONY: all build test lint fmt iac-validate e2e bench results clean

all: fmt lint test build

build:
	$(CARGO) build --workspace --all-targets

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all -- --check

iac-validate:
	bash scripts/iac-validate.sh

e2e: build
	$(CARGO) run -p fleet-sim --release -- e2e --nodes 20

bench: build
	$(CARGO) run -p fleet-sim --release -- bench --out results

results:
	@test -f results/metrics.json && $(PYTHON) -m json.tool results/metrics.json

clean:
	$(CARGO) clean
	rm -rf out results/*.tmp
