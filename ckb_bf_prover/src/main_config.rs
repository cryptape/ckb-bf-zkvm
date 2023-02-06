use crate::instruction_table::InstructionTableConfig;
use crate::memory_table::MemoryTableConfig;
use crate::processor_table::ProcessorTableConfig;
use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use std::marker::PhantomData;
/**
 * TODO: What's Misssing?
 * 1. permutation running product (prp) to link processor table and memory table
 * 2. running evaluation (re) to link processor table and output table
 * 3. re to link processor table and input table
 * 4. link processor table and instruction table
 * 4. read public input and expose public output
 */

#[derive(Clone, Debug, Copy)]
pub struct MainConfig<const RANGE: usize> {
    p_config: ProcessorTableConfig<RANGE>,
    m_config: MemoryTableConfig,
    i_config: InstructionTableConfig,
}

impl<const RANGE: usize> Config for MainConfig<RANGE> {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            p_config: ProcessorTableConfig::configure(cs),
            m_config: MemoryTableConfig::configure(cs),
            i_config: InstructionTableConfig::configure(cs),
        }
    }

    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix) -> Result<(), Error> {
        self.p_config.load_table(layouter, matrix)?;
        self.m_config.load_table(layouter, matrix)?;
        self.i_config.load_table(layouter, matrix)
    }
}

#[derive(Default)]
pub struct MyCircuit<F: Field, const RANGE: usize> {
    _marker: PhantomData<F>,
    matrix: Matrix,
}

impl<const RANGE: usize> MyCircuit<Fr, RANGE> {
    pub fn new(matrix: Matrix) -> Self {
        Self {
            _marker: PhantomData,
            matrix,
        }
    }
}

// It would be nice if we can use generic type here
// impl <F:Field> Circuit<F> for MyCircuit<F> {...}
impl<const RANGE: usize> Circuit<Fr> for MyCircuit<Fr, RANGE> {
    type Config = MainConfig<RANGE>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        MainConfig::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        config.load_table(&mut layouter, &self.matrix)?;
        Ok(())
    }
}
