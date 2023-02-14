use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;

pub trait InputTable {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    fn configure_second_phase(self, cs: &mut ConstraintSystem<Fr>, challenge: BFChallenge);
    fn load_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
        matrix: &Matrix,
        challenge: BFChallenge,
    ) -> Result<BFCell, Error>;
}

#[derive(Clone, Debug, Copy)]
pub struct InputTableConfig {
    val: Column<Advice>,
    rs: Column<Advice>, // running sum
    s_rs: Selector,
}

impl InputTable for InputTableConfig {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        let val = cs.advice_column_in(FirstPhase);
        let rs = cs.advice_column_in(SecondPhase);
        cs.enable_equality(rs);
        let s_rs = cs.selector();
        Self { val, rs, s_rs }
    }

    fn configure_second_phase(self, cs: &mut ConstraintSystem<Fr>, challenge: BFChallenge) {
        cs.create_gate("Input table should have correct running sum transition", |vc| {
            let val = vc.query_advice(self.val, Rotation::cur());
            let rs_cur = vc.query_advice(self.rs, Rotation::cur());
            let rs_next = vc.query_advice(self.rs, Rotation::next());
            let gamma = vc.query_challenge(challenge.get_input_rs_challenge());
            let s_rs = vc.query_selector(self.s_rs);
            vec![s_rs * (rs_next - (rs_cur * gamma + val))]
        });
    }

    fn load_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
        matrix: &Matrix,
        challenge: BFChallenge,
    ) -> Result<BFCell, Error> {
        let gamma = layouter.get_challenge(challenge.get_input_rs_challenge());
        layouter.assign_region(
            || "Load input table",
            |mut region| {
                // init rs_0
                let mut rs_prev = region.assign_advice(|| "rs", self.rs, 0, || Value::known(Fr::zero()))?;
                let input_matrix = &matrix.input_matrix;
                for (idx, v) in input_matrix.iter().enumerate() {
                    self.s_rs.enable(&mut region, idx)?;
                    let val = region.assign_advice(|| "Output val", self.val, idx, || Value::known(*v))?;
                    let rs = gamma * rs_prev.value() + val.value();
                    rs_prev = region.assign_advice(|| "rs", self.rs, idx + 1, || rs)?;
                }
                Ok(rs_prev)
            },
        )
    }
}
