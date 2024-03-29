use ckb_bf_base::main_config::MyCircuit;
use ckb_bf_base::utils::{read_verifier_params, DOMAIN};
use ckb_bf_base::{GOD_PRIVATE_KEY, SHRINK_K};
use ckb_bf_prover::ckb_tx::build_ckb_tx;

use ckb_bf_vm::code;
use ckb_bf_vm::interpreter::Interpreter;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::halo2curves::FieldExt;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, VerifyingKey};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use log::info;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::io::Read;
use std::fs::{read, write};

fn prove_and_verify(k: u32, circuit: MyCircuit<Fr, DOMAIN>, raw_code: Vec<u8>, raw_input: Vec<u8>) {
    info!("Prepare public_inputs");
    // Code
    let mut code = code::compile(raw_code.clone());
    code.insert(0, Fr::from(code.len() as u64));
    // Input
    let mut input = vec![];
    input.push(Fr::from(raw_input.len() as u64));
    raw_input.iter().for_each(|x| input.push(Fr::from(*x as u64)));
    let public_inputs = [&code[..], &input[..]];

    let s = Fr::from_u128(GOD_PRIVATE_KEY);
    info!("Start trusted setup (k={}), using unsafe GOD_PRIVATE_KEY (42) ...", k);
    let general_params = {
        let r = read(&format!("res/params_{}.bin", k));
        if r.is_err() {
            info!("No local params, generate new one.");
            let params = ParamsKZG::<Bn256>::unsafe_setup_with_s(k, s);
            let mut buf = vec![];
            params.write(&mut buf).expect("Write params to buf failed.");
            write(&format!("res/params_{}.bin", k), buf).expect("Write params to file failed");
            params
        } else {
            info!("Use local params.");
            ParamsKZG::<Bn256>::read(&mut r.unwrap().as_slice()).expect("Read params from file failed.")
        }
    };
    let mut verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
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
    >(
        &general_params,
        &pk,
        &[circuit],
        &[&public_inputs],
        rng,
        &mut transcript,
    )
    .expect("create_proof");
    info!("create_proof done");

    let proof = transcript.finalize();
    let mut vk_buf = vec![];
    // for "hello, world":
    // verifying key can be compressed from 2760
    // bytes to 1832 bytes with cost of cycles from 75M to 83M
    //
    pk.get_vk().write(&mut vk_buf, halo2_proofs::SerdeFormat::RawBytes).expect("write");

    info!("proof length : {}", proof.len());
    info!("vk length: {}", vk_buf.len());

    // verifier
    verifier_params.shrink(SHRINK_K);
    let mut verifier_params_buf = vec![];
    verifier_params.write(&mut verifier_params_buf).expect("write");
    info!("verifier parameters length : {}", verifier_params_buf.len());

    // check verification and serialization
    let verifier_params: ParamsVerifierKZG<Bn256> =
        read_verifier_params(&mut &verifier_params_buf[..verifier_params_buf.len()]).unwrap();
    let vk = VerifyingKey::<G1Affine>::read::<&[u8], MyCircuit<Fr, DOMAIN>>(
        &mut &vk_buf[..vk_buf.len()],
        halo2_proofs::SerdeFormat::RawBytes,
    ).unwrap();
    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(&verifier_params);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        &verifier_params,
        &vk,
        strategy,
        &[&public_inputs],
        &mut verifier_transcript,
    )
    .expect("verify_proof");

    let code_u8: Vec<u8> =
        code::compile_to_u16(raw_code.clone()).into_iter().flat_map(|x| x.to_le_bytes().to_vec()).collect();
    // build ckb tx
    build_ckb_tx(
        &proof[..],
        &verifier_params_buf[..],
        &vk_buf[..],
        &code_u8[..],
        &raw_input[..],
        "target/riscv64imac-unknown-none-elf/release/ckb_bf_verifier",
    );

    // check loading params
    let _loaded_verifier_params: ParamsVerifierKZG<Bn256> =
        read_verifier_params(&mut &verifier_params_buf[..]).expect("ParamsVerifierKZG::<Bn256>::read");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() >= 2);
    let mut f = std::fs::File::open(&args[1])?;
    let mut c: Vec<u8> = Vec::new();
    f.read_to_end(&mut c)?;
    let mut i = Interpreter::new();
    let code = code::compile(c.clone());
    let mut input = String::new();
    if args.len() == 3 {
        input = args[2].clone();
        i.set_input(code::easygen(&input));
    }
    i.set_code(code.clone());
    i.run();
    // the bf lookup table has k=8
    let k = std::cmp::max(
        i.matrix.instruction_matrix.len().next_power_of_two().trailing_zeros(),
        9,
    );

    let circuit = MyCircuit::<Fr, { DOMAIN }>::new(i.matrix);
    prove_and_verify(k, circuit, c, input.into_bytes());
    Ok(())
}
