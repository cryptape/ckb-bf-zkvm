use crate::instruction_table::InstructionTableConfig;
use crate::memory_table::{MemoryTable, MemoryTableConfig};
use crate::processor_table::{ProcessorTable, ProcessorTableConfig};
use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;
use rand::rngs::OsRng;
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
    prp_arg: PrpArg,
    processor_prp: Column<Advice>,
    memory_prp: Column<Advice>,
    s_prp: Selector, // Check prp final state
}

impl<const RANGE: usize> Config for MainConfig<RANGE> {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        let p_config = ProcessorTableConfig::configure(cs);
        let m_config = MemoryTableConfig::configure(cs);
        let i_config = InstructionTableConfig::configure(cs);
        let prp_arg = PrpArg {
            init: Fr::random(OsRng),
            challenges: [(); 4].map(|_| cs.challenge_usable_after(FirstPhase)),
        };
        m_config.configure_prp(cs, prp_arg);
        p_config.configure_prp(cs, prp_arg);
        let processor_prp = cs.advice_column();
        let memory_prp = cs.advice_column();
        cs.enable_equality(processor_prp);
        cs.enable_equality(memory_prp);
        let s_prp = cs.selector();
        cs.create_gate("Memory and processor prp should have same terminal state", |vc| {
            let processor_prp = vc.query_advice(processor_prp, Rotation::cur());
            let memory_prp = vc.query_advice(memory_prp, Rotation::cur());
            let s_prp = vc.query_selector(s_prp);
            vec![s_prp * (processor_prp - memory_prp)]
        });
        Self {
            p_config,
            m_config,
            i_config,
            prp_arg,
            processor_prp,
            memory_prp,
            s_prp,
        }
    }

    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix) -> Result<(), Error> {
        let processor_prp = self.p_config.load_table(layouter, matrix, self.prp_arg)?;
        let memory_prp = self.m_config.load_table(layouter, matrix, self.prp_arg)?;
        self.i_config.load_table(layouter, matrix)?;
        layouter.assign_region(
            || "Extension Column",
            |mut region| {
                processor_prp.copy_advice(|| "processor prp final state", &mut region, self.processor_prp, 0)?;
                memory_prp.copy_advice(|| "memory prp final state", &mut region, self.memory_prp, 0)?;
                self.s_prp.enable(&mut region, 0)?;
                Ok(())
            },
        )
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
