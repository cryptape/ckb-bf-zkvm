# ckb-bf-zkvm

A BrainFuck zkVM implementation on CKB, using Halo2.

## Features

* Use [Halo2](https://github.com/scroll-tech/halo2/tree/scroll-dev-1220)(modified version from scroll)
* Use bn254 as pairing
* Use KZG
* Verifier on CKB(RISC-V)
* Implement BrainFuck instructions


## Crates

* ckb_bf_base: shared code between prover and verifier.
* ckb_bf_prover: prover. This is the only crate for `std` only. Run on native machine.
* ckb_bf_verifier: verifier. Run on CKB in RISC-V
* ckb_bf_vm: Virtual Machine. 
* halo2, halo2_gadgets, halo2_proofs, poseidon: halo2 crates.
