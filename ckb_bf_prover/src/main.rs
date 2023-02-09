use ckb_bf_prover::main_config::MyCircuit;
use ckb_bf_prover::utils::DOMAIN;
use ckb_bf_vm::code;
use ckb_bf_vm::interpreter::Interpreter;
use halo2_proofs::dev::MockProver;
// use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::bn256::Fr;
// use halo2_proofs::plonk::create_proof;
// use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
// use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
// use rand::rngs::OsRng;
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() >= 2);
    let mut f = std::fs::File::open(&args[1])?;
    let mut c: Vec<u8> = Vec::new();
    f.read_to_end(&mut c)?;
    let mut i = Interpreter::new();
    i.set_code(code::compile(c));
    i.run();
    let k = i.matrix.instruction_matrix.len().next_power_of_two().trailing_zeros();

    let circuit = MyCircuit::<Fr, { DOMAIN }>::new(i.matrix);
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
    // let mut rng = OsRng;
    // let params: ParamsKZG<Bn256> = ParamsKZG::setup(k as u32, rng);
    Ok(())
}
