extern crate alloc;

use alloc::vec::Vec;
use ckb_bf_vm::code;
use halo2_gadgets::halo2curves::pairing::Engine;
use halo2_proofs::circuit::AssignedCell;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::helpers::SerdeCurveAffine;
use halo2_proofs::poly::kzg::commitment::ParamsVerifierKZG;
use halo2_proofs::{plonk::*, SerdeFormat};
use halo2curves::io;

use crate::SHRINK_K;

pub const OPCODES: [u8; 8] = [
    code::SHL,
    code::SHR,
    code::ADD,
    code::SUB,
    code::GETCHAR,
    code::PUTCHAR,
    code::LB,
    code::RB,
];

pub const SHL: usize = 0;
pub const SHR: usize = 1;
pub const ADD: usize = 2;
pub const SUB: usize = 3;
pub const GETCHAR: usize = 4;
pub const PUTCHAR: usize = 5;
pub const LB: usize = 6;
pub const RB: usize = 7;

pub const DOMAIN: usize = 256;

pub type BFCell = AssignedCell<Fr, Fr>;

#[derive(Clone, Copy, Debug)]
pub struct BFChallenge {
    pub(crate) mem_prp_init: Fr,
    pub(crate) inst_prp_init: Fr,
    challenges: [Challenge; 11],
}

impl BFChallenge {
    pub(crate) fn init(cs: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            // TODO: make it random
            mem_prp_init: Fr::from(3),
            inst_prp_init: Fr::from(9),
            challenges: [(); 11].map(|_| cs.challenge_usable_after(FirstPhase)),
        }
    }

    pub(crate) fn get_mem_prp_challenges(self: Self) -> [Challenge; 4] {
        self.challenges[0..4].try_into().expect("Challenges should have correct length")
    }

    pub(crate) fn get_inst_prp_challenges(self: Self) -> [Challenge; 4] {
        self.challenges[4..8].try_into().expect("Challenges should have correct length")
    }

    // Not used, see main_config TODOs
    // pub(crate) fn get_inst_rs_challenges(self: Self) -> Challenge {
    //     self.challenges[8]
    // }

    pub(crate) fn get_output_rs_challenge(self: Self) -> Challenge {
        self.challenges[9]
    }

    pub(crate) fn get_input_rs_challenge(self: Self) -> Challenge {
        self.challenges[10]
    }
}

pub fn read_verifier_params<E: Engine, R: io::Read>(reader: &mut R) -> io::Result<ParamsVerifierKZG<E>>
where
    E::G1Affine: SerdeCurveAffine,
    E::G2Affine: SerdeCurveAffine,
{
    let shrink_k = SHRINK_K;
    let mut k = [0u8; 4];
    reader.read_exact(&mut k[..])?;
    let k = u32::from_le_bytes(k);
    let n = 1 << k;
    let shrink_n = 1 << shrink_k;

    let format = SerdeFormat::RawBytes;

    let g = (0..shrink_n).map(|_| E::G1Affine::read(reader, format)).collect::<Result<Vec<_>, _>>()?;
    let g_lagrange = (0..shrink_n).map(|_| E::G1Affine::read(reader, format)).collect::<Result<Vec<_>, _>>()?;

    let g2 = E::G2Affine::read(reader, format)?;
    let s_g2 = E::G2Affine::read(reader, format)?;

    Ok(ParamsVerifierKZG {
        k,
        n: n as u64,
        g,
        g_lagrange,
        g2,
        s_g2,
    })
}
