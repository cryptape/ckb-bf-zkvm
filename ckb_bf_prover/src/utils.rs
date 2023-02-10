use ckb_bf_vm::code;
use ckb_bf_vm::matrix::Matrix;
use halo2_proofs::circuit::{AssignedCell, Layouter};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;

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
pub struct PrpArg {
    pub(crate) init: Fr,
    pub(crate) challenges: [Challenge; 4],
}

pub trait Config {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix) -> Result<(), Error>;
}
