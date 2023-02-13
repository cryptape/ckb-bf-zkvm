use ckb_bf_prover::main_config::MyCircuit;
use ckb_bf_prover::utils::DOMAIN;
use ckb_bf_prover::GOD_PRIVATE_KEY;
use ckb_bf_vm::code;
use ckb_bf_vm::interpreter::Interpreter;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::halo2curves::FieldExt;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use log::info;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::io::Read;

fn prove_and_verify(k: u32, circuit: MyCircuit<Fr, DOMAIN>, _public_inputs: &[&[Fr]]) {
    let s = Fr::from_u128(GOD_PRIVATE_KEY);
    info!("Start trusted setup, using unsafe GOD_PRIVATE_KEY (42) ...");
    let general_params = ParamsKZG::<Bn256>::unsafe_setup_with_s(k, s);
    let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
    let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk");
    let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk");
    info!("Trusted setup done");

    let rng = XorShiftRng::from_seed([GOD_PRIVATE_KEY as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    info!("Start create_proof");
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        XorShiftRng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        MyCircuit<Fr, DOMAIN>,
    >(&general_params, &pk, &[circuit], &[], rng, &mut transcript)
    .expect("create_proof");
    info!("create_proof done");

    let proof = transcript.finalize();
    let mut verifier_params_buf = vec![];
    verifier_params.write(&mut verifier_params_buf).expect("write");
    let mut vk_buf = vec![];
    pk.get_vk().write(&mut vk_buf).expect("write");

    info!("proof length : {}", proof.len());
    info!("verifier parameters length : {}", verifier_params_buf.len());
    info!("vk length: {}", vk_buf.len());

    // verifier
    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(&general_params);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&verifier_params, pk.get_vk(), strategy, &[], &mut verifier_transcript)
    .expect("verify_proof");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

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
    prove_and_verify(k, circuit, &[&[]]);
    Ok(())
}
