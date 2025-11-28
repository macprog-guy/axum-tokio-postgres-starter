test:
	cargo test

docs:
	cargo doc --no-deps --open

lint:
	cargo clippy --all-targets --all-features -- -D warnings

audit:
	cargo audit

coverage:
	cargo llvm-cov --html --open --all-features -- tests
