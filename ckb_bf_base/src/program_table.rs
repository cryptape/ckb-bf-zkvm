use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;

pub trait ProgramTable {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    fn configure_second_phase(self, cs: &mut ConstraintSystem<Fr>, challenges: BFChallenge);
    // Load program code from public instance, constraint them to be equal
    fn load_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
        program: &Column<Instance>,
        matrix: &Matrix,
        challenges: BFChallenge,
    ) -> Result<(BFCell, BFCell), Error>;
}

#[derive(Clone, Debug, Copy)]
pub struct ProgramTableConfig {
    program_len: Column<Advice>,
    code: Column<Advice>,
    code_rs: Column<Advice>,
    s_rs: Selector,
}

impl ProgramTable for ProgramTableConfig {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        let code = cs.advice_column_in(FirstPhase);
        let program_len = cs.advice_column_in(FirstPhase);
        let code_rs = cs.advice_column_in(SecondPhase);
        let s_rs = cs.selector();
        cs.enable_equality(program_len);
        cs.enable_equality(code);
        cs.enable_equality(code_rs);
        Self {
            program_len,
            code,
            code_rs,
            s_rs,
        }
    }
    fn configure_second_phase(self, cs: &mut ConstraintSystem<Fr>, challenges: BFChallenge) {
        cs.create_gate("Program table rs should have valid transition", |vc| {
            let code = vc.query_advice(self.code, Rotation::cur());
            let gamma = vc.query_challenge(challenges.get_inst_rs_challenges());
            let s_rs = vc.query_selector(self.s_rs);
            let rs_cur = vc.query_advice(self.code_rs, Rotation::cur());
            let rs_next = vc.query_advice(self.code_rs, Rotation::next());
            vec![s_rs * (rs_next - (rs_cur * gamma + code))]
        });
    }

    fn load_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
        program: &Column<Instance>,
        matrix: &Matrix,
        challenges: BFChallenge,
    ) -> Result<(BFCell, BFCell), Error> {
        let gamma = layouter.get_challenge(challenges.get_inst_rs_challenges());
        layouter.assign_region(
            || "Load program",
            |mut region| {
                // Halo2 does not have _true_ variable length instance
                // So we have to know the length of the program to copy code instance into advice
                // The solution here is to let prover provide the program length, expose the
                // program length as public
                // And use constraint_instance to make sure the length is correct
                let len = region.assign_advice(
                    || "Program length",
                    self.program_len,
                    0,
                    || Value::known(Fr::from(matrix.program.len() as u64)),
                )?;

                let mut rs_prev = region.assign_advice(|| "rs", self.code_rs, 0, || Value::known(Fr::zero()))?;
                for idx in 0..matrix.program.len() {
                    self.s_rs.enable(&mut region, idx)?;
                    let code =
                        region.assign_advice_from_instance(|| "program code", *program, idx + 1, self.code, idx)?;
                    let rs = gamma * rs_prev.value() + code.value();
                    rs_prev = region.assign_advice(|| "code rs", self.code_rs, idx + 1, || rs)?;
                }
                Ok((len, rs_prev))
            },
        )
    }
}
