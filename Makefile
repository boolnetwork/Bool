SHELL := /bin/bash
#ENABLE_FEATURES ?= default

default: release

.PHONY: all

all: format build test

build:
	cargo build #--features "${ENABLE_FEATURES}"

release:
	@cargo build --release #--features "${ENABLE_FEATURES}"

wasm:
	export WASM_TARGET_DIRECTORY=$(pwd)\
	cargo build --release -p bool-runtime

test:
	export LOG_LEVEL=DEBUG && \
	export RUST_BACKTRACE=1 && \
	cargo test #--features "${ENABLE_FEATURES}" --all -- --nocapture

unset-override:
	@# unset first in case of any previous overrides
	@if rustup override list | grep `pwd` > /dev/null; then rustup override unset; fi

pre-format: unset-override
	@rustup component add rustfmt-preview

format: pre-format
	@cargo +nightly fmt --all -- --check >/dev/null || \
	cargo +nightly fmt --all

clean:
	@cargo clean
