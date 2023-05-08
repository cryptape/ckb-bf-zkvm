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
use core::convert::TryInto;
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
    let raw_bytes = include_bytes!("../../res/raw_input.bin");
    let params_start = 4;
    let params_end = params_start + u32::from_be_bytes(raw_bytes[0..params_start].try_into().unwrap()) as usize;
    debug(format!("params len:{:?}", params_end - params_start));
    let vk_start = params_end + 4;
    let vk_end = vk_start + u32::from_be_bytes(raw_bytes[vk_start - 4..vk_start].try_into().unwrap()) as usize;
    debug(format!("vk len:{:?}", vk_end - vk_start));
    let proof_start = vk_end + 4;
    let proof_end =
        proof_start + u32::from_be_bytes(raw_bytes[proof_start - 4..proof_start].try_into().unwrap()) as usize;
    debug(format!("proof len:{:?}", proof_end - proof_start));
    let hash_raw = raw_bytes[proof_end..proof_end + 32].try_into().unwrap();
    let hash_message = Fr::from_bytes(hash_raw).unwrap();
    debug(format!("hash message: {:?}", hash_message));

    let verifier_params = {
        let r: io::Result<ParamsVerifierKZG<Bn256>> = read_verifier_params(&mut &raw_bytes[params_start..params_end]);
        if r.is_err() {
            debug(format!("Error on ParamsVerifierKZG::<Bn256>::read: {:?}", r.err()));
            return -1;
        }
        r.unwrap()
    };

    let vk = {
        let r = VerifyingKey::<G1Affine>::read::<&[u8], MyCircuit<Fr, DOMAIN>>(
            &mut &raw_bytes[vk_start..vk_end],
            halo2_proofs::SerdeFormat::RawBytes,
        );
        if r.is_err() {
            debug(format!("Error on VerifyingKey::read: {:?}", r.err()));
            return -1;
        };
        r.unwrap()
    };

    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&raw_bytes[proof_start..proof_end]);
    let strategy = SingleStrategy::new(&verifier_params);
    let res = verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        &verifier_params,
        &vk,
        strategy,
        &[&[&[hash_message]]],
        &mut verifier_transcript,
    );
    if res.is_err() {
        debug(format!("Error on verify_proof: {:?}", res.err()));
        return -2;
    };
    debug(format!("Verifying successfully"));
    0
}
