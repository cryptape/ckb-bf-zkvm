
all:
	RUST_LOG=info cargo run --package ckb_bf_prover -- res/hello_world.bf

verifier:
	cargo build --target riscv64imac-unknown-none-elf --release --package ckb_bf_verifier
	riscv64-unknown-elf-strip target/riscv64imac-unknown-none-elf/release/ckb_bf_verifier

ci:
	RUST_LOG=info cargo run --package ckb_bf_prover -- res/hello_world.bf
	cd ckb_bf_prover && cargo test
	cd ckb_bf_vm && cargo test

install:
	rustup target add riscv64imac-unknown-none-elf
