use crate::input_table::{InputTable, InputTableConfig};
use crate::instruction_table::{InstructionTable, InstructionTableConfig};
use crate::memory_table::{MemoryTable, MemoryTableConfig};
use crate::output_table::{OutputTable, OutputTableConfig};
use crate::processor_table::{ProcessorTable, ProcessorTableConfig};
use crate::program_table::{ProgramTable, ProgramTableConfig};
use crate::poseidon_hash::hash_message;
use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;
use core::marker::PhantomData;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use poseidon_circuit::poseidon::PermuteChip;

pub trait MainTable {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
pub struct MainConfig<const RANGE: usize> {
    p_config: ProcessorTableConfig<RANGE>,
    m_config: MemoryTableConfig,
    i_config: InstructionTableConfig,
    output_config: OutputTableConfig,
    input_config: InputTableConfig,
    program_config: ProgramTableConfig,
    expected_hash: Column<Instance>,
    hash_config: HashConfig,
    challenges: BFChallenge,
}

impl<const RANGE: usize> MainTable for MainConfig<RANGE> {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        // Instance Column
        let expected_hash = cs.instance_column();
        cs.enable_equality(expected_hash);
        // First phase gates and tables
        let p_config = ProcessorTableConfig::configure(cs);
        let m_config = MemoryTableConfig::configure(cs);
        let i_config = InstructionTableConfig::configure(cs);
        let output_config = OutputTableConfig::configure(cs);
        let input_config = InputTableConfig::configure(cs);
        let program_config = ProgramTableConfig::configure(cs);
        // Second phase tables
        let challenges = BFChallenge::init(cs);
        m_config.configure_second_phase(cs, challenges);
        p_config.configure_second_phase(cs, challenges);
        i_config.configure_second_phase(cs, challenges);
        output_config.configure_second_phase(cs, challenges);
        input_config.configure_second_phase(cs, challenges);
        program_config.configure_second_phase(cs, challenges);

        Self {
            p_config,
            m_config,
            i_config,
            output_config,
            input_config,
            program_config,
            expected_hash,
            challenges,
            hash_config: <HashChip as PermuteChip<Fr>>::configure(cs),
        }
    }

    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix) -> Result<(), Error> {
        let (processor_mem_prp, processor_output_rs, processor_input_rs, processor_inst_prp) =
            self.p_config.load_table(layouter, matrix, self.challenges)?;
        let memory_prp = self.m_config.load_table(layouter, matrix, self.challenges)?;
        let (inst_code_rs, inst_prp) = self.i_config.load_table(layouter, matrix, self.challenges)?;
        let output_rs = self.output_config.load_table(layouter, matrix, self.challenges)?;
        let (input_hash, input_rs) = self.input_config.load_table(layouter, matrix, self.challenges)?;
        let (code_hash, code_rs) = self.program_config.load_table(layouter, matrix, self.challenges)?;
        let hash = hash_message(vec![code_hash, input_hash], self.hash_config.clone(), layouter)?;
        layouter.constrain_instance(hash.cell(), self.expected_hash, 0)?;
        layouter.assign_region(
            || "Extension Column",
            |mut region| {
                region.constrain_equal(processor_mem_prp.cell(), memory_prp.cell())?;
                region.constrain_equal(output_rs.cell(), processor_output_rs.cell())?;
                region.constrain_equal(input_rs.cell(), processor_input_rs.cell())?;
                region.constrain_equal(processor_inst_prp.cell(), inst_prp.cell())?;
                region.constrain_equal(code_rs.cell(), inst_code_rs.cell())?;
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
