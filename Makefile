
all:
	RUST_LOG=info cargo run --package ckb_bf_prover -- res/hello_world.bf

ci:
	RUST_LOG=info cargo run --package ckb_bf_prover -- res/hello_world.bf
	cd ckb_bf_prover && cargo test
	cd ckb_bf_vm && cargo test
