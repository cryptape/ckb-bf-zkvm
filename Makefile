
all: verifier
	RUST_LOG=info cargo run --release --package ckb_bf_prover -- res/hello_world.bf

verifier:
	cargo build --target riscv64imac-unknown-none-elf --release --package ckb_bf_verifier
	ls -l target/riscv64imac-unknown-none-elf/release/ckb_bf_verifier

ci: verifier
	RUST_LOG=info cargo run --release --package ckb_bf_prover -- res/hello_world.bf
	make run-tx
	cd ckb_bf_prover && cargo test
	cd ckb_bf_vm && cargo test

run-tx:
	RUST_LOG=debug ckb-debugger --tx-file res/tx.json --cell-index 0 --cell-type input --script-group-type lock --max-cycles 20000000000

install:
	rustup target add riscv64imac-unknown-none-elf
	sudo apt install gcc-riscv64-unknown-elf
	cargo install --git https://github.com/nervosnetwork/ckb-standalone-debugger ckb-debugger
