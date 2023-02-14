use crate::input_table::{InputTable, InputTableConfig};
use crate::instruction_table::{InstructionTable, InstructionTableConfig};
use crate::memory_table::{MemoryTable, MemoryTableConfig};
use crate::output_table::{OutputTable, OutputTableConfig};
use crate::processor_table::{ProcessorTable, ProcessorTableConfig};
use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;
/**
 * TODO: What's Misssing?
 * All proofs from the original tut are implemented except one
 * We need to prove the instruction table contains the original program
 * This require us to have another program table (which contains the program, sorted by ip)
 * After that, we can finish the last evaluation argument and prove program + trace = instruction table.
 */

pub trait MainTable {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix) -> Result<(), Error>;
}

#[derive(Clone, Debug, Copy)]
pub struct MainConfig<const RANGE: usize> {
    p_config: ProcessorTableConfig<RANGE>,
    m_config: MemoryTableConfig,
    i_config: InstructionTableConfig,
    output_config: OutputTableConfig,
    input_config: InputTableConfig,
    challenges: BFChallenge,
    final_states: [Column<Advice>; 8],
    s_final: Selector,
}

impl<const RANGE: usize> MainTable for MainConfig<RANGE> {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        // First phase gates and tables
        let p_config = ProcessorTableConfig::configure(cs);
        let m_config = MemoryTableConfig::configure(cs);
        let i_config = InstructionTableConfig::configure(cs);
        let output_config = OutputTableConfig::configure(cs);
        let input_config = InputTableConfig::configure(cs);
        // Second phase tables
        let challenges = BFChallenge::init(cs);
        m_config.configure_second_phase(cs, challenges);
        p_config.configure_second_phase(cs, challenges);
        i_config.configure_second_phase(cs, challenges);
        output_config.configure_second_phase(cs, challenges);
        input_config.configure_second_phase(cs, challenges);
        // main gates and columns
        let final_states = [(); 8].map(|_| cs.advice_column());
        final_states.map(|col| cs.enable_equality(col));
        let s_final = cs.selector();
        cs.create_gate("Memory and processor prp should have same terminal state", |vc| {
            let processor_prp = vc.query_advice(final_states[0], Rotation::cur());
            let memory_prp = vc.query_advice(final_states[1], Rotation::cur());
            let s_final = vc.query_selector(s_final);
            vec![s_final * (processor_prp - memory_prp)]
        });
        cs.create_gate(
            "Output and processor table should have same terminal state for output rs",
            |vc| {
                let output_rs = vc.query_advice(final_states[2], Rotation::cur());
                let processor_rs = vc.query_advice(final_states[3], Rotation::cur());
                let s_final = vc.query_selector(s_final);
                vec![s_final * (processor_rs - output_rs)]
            },
        );
        cs.create_gate(
            "Input and processor table should have same terminal state for input rs",
            |vc| {
                let input_rs = vc.query_advice(final_states[4], Rotation::cur());
                let processor_rs = vc.query_advice(final_states[5], Rotation::cur());
                let s_final = vc.query_selector(s_final);
                vec![s_final * (processor_rs - input_rs)]
            },
        );
        cs.create_gate("instruction and processor prp should have same terminal state", |vc| {
            let processor_inst_prp = vc.query_advice(final_states[6], Rotation::cur());
            let inst_prp = vc.query_advice(final_states[7], Rotation::cur());
            let s_final = vc.query_selector(s_final);
            vec![s_final * (processor_inst_prp - inst_prp)]
        });

        Self {
            p_config,
            m_config,
            i_config,
            output_config,
            input_config,
            challenges,
            final_states,
            s_final,
        }
    }

    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix) -> Result<(), Error> {
        let (processor_mem_prp, processor_output_rs, processor_input_rs, processor_inst_prp) =
            self.p_config.load_table(layouter, matrix, self.challenges)?;
        let memory_prp = self.m_config.load_table(layouter, matrix, self.challenges)?;
        let inst_prp = self.i_config.load_table(layouter, matrix, self.challenges)?;
        let output_rs = self.output_config.load_table(layouter, matrix, self.challenges)?;
        let input_rs = self.input_config.load_table(layouter, matrix, self.challenges)?;
        layouter.assign_region(
            || "Extension Column",
            |mut region| {
                self.s_final.enable(&mut region, 0)?;
                processor_mem_prp.copy_advice(
                    || "processor mem prp final state",
                    &mut region,
                    self.final_states[0],
                    0,
                )?;
                memory_prp.copy_advice(|| "memory prp final state", &mut region, self.final_states[1], 0)?;
                output_rs.copy_advice(|| "output table rs", &mut region, self.final_states[2], 0)?;
                processor_output_rs.copy_advice(
                    || "processor table output rs",
                    &mut region,
                    self.final_states[3],
                    0,
                )?;
                input_rs.copy_advice(|| "input table rs", &mut region, self.final_states[4], 0)?;
                processor_input_rs.copy_advice(|| "processor table input rs", &mut region, self.final_states[5], 0)?;
                processor_inst_prp.copy_advice(
                    || "processor inst prp final state",
                    &mut region,
                    self.final_states[6],
                    0,
                )?;
                inst_prp.copy_advice(|| "inst prp final state", &mut region, self.final_states[7], 0)?;
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
