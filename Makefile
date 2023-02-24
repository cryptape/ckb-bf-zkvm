
all: verifier
	RUST_LOG=info cargo run --release --package ckb_bf_prover -- res/hello_world.bf

verifier:
	cargo build --target riscv64imac-unknown-none-elf --release --package ckb_bf_verifier
	ls -l target/riscv64imac-unknown-none-elf/release/ckb_bf_verifier

ci: verifier
	RUST_LOG=info cargo run --release --package ckb_bf_prover -- res/hello_world.bf
	make run-tx | fgrep 'Run result: 0'
	cd ckb_bf_prover && cargo test
	cd ckb_bf_vm && cargo test

bn254_benchmark:
	cargo build --target riscv64imac-unknown-none-elf --release --package bn254_benchmark
	ls -l target/riscv64imac-unknown-none-elf/release/bn254_benchmark
	RUST_LOG=debug ckb-debugger --bin target/riscv64imac-unknown-none-elf/release/bn254_benchmark


run-tx:
	RUST_LOG=debug ckb-debugger --tx-file res/tx.json --cell-index 0 --cell-type input --script-group-type lock --max-cycles 20000000000

install:
	rustup target add riscv64imac-unknown-none-elf
	sudo apt install gcc-riscv64-unknown-elf
	cargo install --git https://github.com/nervosnetwork/ckb-standalone-debugger ckb-debugger

.PHONY: bn254_benchmark