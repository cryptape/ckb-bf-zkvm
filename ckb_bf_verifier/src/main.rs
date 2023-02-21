#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use alloc::format;
use ckb_bf_base::main_config::MyCircuit;
use ckb_bf_base::utils::{DOMAIN, read_verifier_params};
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
    poly::{
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsVerifierKZG},
            multiopen::VerifierSHPLONK,
            strategy::SingleStrategy,
        },
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
        },
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
        },
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
        },
        Err(e) => {
            debug(format!("Loading proof error {:?}", e));
            return -1;
        }
    };

    let verifier_params = {
        let r : io::Result<ParamsVerifierKZG<Bn256>> = read_verifier_params(&mut &params_buffer[..params_len]);
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

    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_buffer[..proof_len]);
    let strategy = SingleStrategy::new(&verifier_params);
    let res = verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&verifier_params, &vk, strategy, &[], &mut verifier_transcript);
    if res.is_err() {
        debug(format!("Error on verify_proof: {:?}", res.err()));
        return -2;
    };
    debug(format!("Verifying successfully"));
    0
}