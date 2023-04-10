use crate::poseidon_hash::hash_message;
use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;
use poseidon_circuit::poseidon::PermuteChip;

pub trait ProgramTable {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    fn configure_second_phase(&self, cs: &mut ConstraintSystem<Fr>, challenges: BFChallenge);
    // Load program code from public instance, constraint them to be equal
    fn load_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
        matrix: &Matrix,
        challenges: BFChallenge,
    ) -> Result<(BFCell, BFCell), Error>;
}

#[derive(Clone, Debug)]
pub struct ProgramTableConfig {
    code: Column<Advice>,
    code_rs: Column<Advice>,
    s_rs: Selector,
    hash_config: HashConfig,
}

impl ProgramTable for ProgramTableConfig {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        let code = cs.advice_column_in(FirstPhase);
        let code_rs = cs.advice_column_in(SecondPhase);
        let s_rs = cs.selector();
        cs.enable_equality(code);
        cs.enable_equality(code_rs);
        Self {
            code,
            code_rs,
            s_rs,
            hash_config: <HashChip as PermuteChip<Fr>>::configure(cs),
        }
    }
    fn configure_second_phase(&self, cs: &mut ConstraintSystem<Fr>, challenges: BFChallenge) {
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
        matrix: &Matrix,
        challenges: BFChallenge,
    ) -> Result<(BFCell, BFCell), Error> {
        let gamma = layouter.get_challenge(challenges.get_inst_rs_challenges());
        let (message, rs_prev) = layouter.assign_region(
            || "Load program",
            |mut region| {
                let mut rs_prev = region.assign_advice(|| "rs", self.code_rs, 0, || Value::known(Fr::zero()))?;
                let mut message = vec![];
                for (idx, code) in matrix.program.iter().enumerate() {
                    self.s_rs.enable(&mut region, idx)?;
                    let code = region.assign_advice(|| "program code", self.code, idx, || Value::known(*code))?;
                    message.push(code.clone());
                    let rs = gamma * rs_prev.value() + code.value();
                    rs_prev = region.assign_advice(|| "code rs", self.code_rs, idx + 1, || rs)?;
                }
                Ok((message, rs_prev))
            },
        )?;
        let output = hash_message(message, self.hash_config.clone(), layouter)?;
        Ok((output, rs_prev))
    }
}
