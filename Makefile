all: verifier
	RUST_LOG=info cargo run --release --package ckb_bf_prover -- res/hello_world.bf

verifier:
	cargo build --target riscv64imac-unknown-none-elf --release --package ckb_bf_verifier
	ls -l target/riscv64imac-unknown-none-elf/release/ckb_bf_verifier

ci: verifier
	RUST_LOG=info cargo run --release --package ckb_bf_prover -- res/neptune_tutorial.bf a
	make run-tx | fgrep 'Run result: 0'
	cd ckb_bf_prover && cargo test
	cd ckb_bf_vm && cargo test

run-tx:
	RUST_LOG=debug ckb-vm-runner target/riscv64imac-unknown-none-elf/release/ckb_bf_verifier

install:
	rustup target add riscv64imac-unknown-none-elf
	sudo apt install gcc-riscv64-unknown-elf
