#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use alloc::format;
use ckb_bf_base::main_config::MyCircuit;
use ckb_bf_base::utils::{read_verifier_params, DOMAIN};
use ckb_std::{
    ckb_constants::Source,
    default_alloc,
    syscalls::{debug, load_witness},
};
use halo2_gadgets::halo2curves::bn256::{Bn256, Fr, G1Affine};

ckb_std::entry!(program_entry);
default_alloc!();

use halo2_proofs::{
    plonk::{verify_proof, VerifyingKey},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsVerifierKZG},
        multiopen::VerifierSHPLONK,
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
};
use halo2curves::io;

pub fn program_entry() -> i8 {
    let mut params_buffer = [0u8; 32 * 1024];
    let params_len = match load_witness(&mut params_buffer, 0, 0, Source::Input) {
        Ok(l) => {
            debug(format!("Loading params length: {:?}", l));
            l
        }
        Err(e) => {
            debug(format!("Loading params error {:?}", e));
            return -1;
        }
    };
    let mut vk_buffer = [0u8; 32 * 1024];
    let vk_len = match load_witness(&mut vk_buffer, 0, 1, Source::Input) {
        Ok(l) => {
            debug(format!("Loading vk length: {:?}", l));
            l
        }
        Err(e) => {
            debug(format!("Loading vk error {:?}", e));
            return -1;
        }
    };
    let mut proof_buffer = [0u8; 32 * 1024];
    let proof_len = match load_witness(&mut proof_buffer, 0, 2, Source::Input) {
        Ok(l) => {
            debug(format!("Loading proof length: {:?}", l));
            l
        }
        Err(e) => {
            debug(format!("Loading proof error {:?}", e));
            return -1;
        }
    };

    let mut code_buffer = [0u8; 2048];
    let raw_code_len = match load_witness(&mut code_buffer, 0, 3, Source::Input) {
        Ok(l) => {
            debug(format!("Loading program length: {:?}", l));
            l
        }
        Err(e) => {
            debug(format!("Loading program error: {:?}", e));
            return -1;
        }
    };
    assert!(raw_code_len % 2 == 0); // san-check
    let code_len = raw_code_len / 2;
    let mut code = [Fr::zero(); 1024];
    code[0] = Fr::from(code_len as u64);
    (0..code_len).for_each(|idx| {
        code[idx + 1] = Fr::from(u16::from_le_bytes([code_buffer[idx * 2], code_buffer[idx * 2 + 1]]) as u64)
    });

    let mut input_buffer = [0u8; 1024];
    let input_len = match load_witness(&mut input_buffer, 0, 4, Source::Input) {
        Ok(l) => {
            debug(format!("Loading input length: {:?}", l));
            l
        }
        Err(e) => {
            debug(format!("Loading input error: {:?}", e));
            return -1;
        }
    };
    let mut input = [Fr::zero(); 1024];
    input[0] = Fr::from(input_len as u64);
    (0..input_len).for_each(|idx| {
        input[idx+1] = Fr::from(input_buffer[idx] as u64);
    });

    let verifier_params = {
        let r: io::Result<ParamsVerifierKZG<Bn256>> = read_verifier_params(&mut &params_buffer[..params_len]);
        if r.is_err() {
            debug(format!("Error on ParamsVerifierKZG::<Bn256>::read: {:?}", r.err()));
            return -1;
        }
        r.unwrap()
    };

    let vk = {
        let r = VerifyingKey::<G1Affine>::read::<&[u8], MyCircuit<Fr, DOMAIN>>(
            &mut &vk_buffer[..vk_len],
            halo2_proofs::SerdeFormat::RawBytes,
        );
        if r.is_err() {
            debug(format!("Error on VerifyingKey::read: {:?}", r.err()));
            return -1;
        };
        r.unwrap()
    };

    // Prepare instances
    let instances = [&code[0..(code_len + 1)], &input[0..(input_len + 1)]];

    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_buffer[..proof_len]);
    let strategy = SingleStrategy::new(&verifier_params);
    let res = verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&verifier_params, &vk, strategy, &[&instances], &mut verifier_transcript);
    if res.is_err() {
        debug(format!("Error on verify_proof: {:?}", res.err()));
        return -2;
    };
    debug(format!("Verifying successfully"));
    0
}
