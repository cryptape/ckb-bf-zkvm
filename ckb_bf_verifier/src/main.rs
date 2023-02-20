#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use alloc::format;
use ckb_bf_base::main_config::MyCircuit;
use ckb_bf_base::utils::DOMAIN;
use ckb_std::{
    ckb_constants::Source,
    default_alloc,
    syscalls::{debug, load_witness},
};
use core::arch::asm;
use halo2_gadgets::halo2curves::bn256::{Bn256, Fr, G1Affine};

ckb_std::entry!(program_entry);
default_alloc!();

use halo2_proofs::{
    plonk::{verify_proof, VerifyingKey},
    poly::{
        commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsVerifierKZG},
            multiopen::VerifierSHPLONK,
            strategy::SingleStrategy,
        },
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
};

pub fn program_entry(_argc: u64, _argv: *const *const u8) -> i8 {
    let mut params_buffer = [0u8; 32 * 1024];
    let params_length = match load_witness(&mut params_buffer, 0, 0, Source::Input) {
        Ok(l) => l,
        Err(e) => {
            debug(format!("Loading params error {:?}", e));
            return -1;
        }
    };
    let mut vk_buffer = [0u8; 32 * 1024];
    let vk_length = match load_witness(&mut vk_buffer, 0, 1, Source::Input) {
        Ok(l) => l,
        Err(e) => {
            debug(format!("Loading vk error {:?}", e));
            return -1;
        }
    };
    let mut proof_buffer = [0u8; 32 * 1024];
    let proof_length = match load_witness(&mut proof_buffer, 0, 2, Source::Input) {
        Ok(l) => l,
        Err(e) => {
            debug(format!("Loading proof error {:?}", e));
            return -1;
        }
    };

    let mut verifier_params = ParamsVerifierKZG::<Bn256>::read(&mut &params_buffer[..]).expect("read");
    let mut vk = VerifyingKey::<G1Affine>::read::<&[u8], MyCircuit<Fr, DOMAIN>>(
        &mut &vk_buffer[..],
        halo2_proofs::SerdeFormat::RawBytes,
    )
    .expect("read");

    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_buffer[..]);
    let strategy = SingleStrategy::new(&verifier_params);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&verifier_params, &vk, strategy, &[], &mut verifier_transcript)
    .expect("verify_proof");

    0
}
