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
        input: &Column<Instance>,
        matrix: &Matrix,
        challenge: BFChallenge,
    ) -> Result<(BFCell, BFCell), Error>;
}

#[derive(Clone, Debug, Copy)]
pub struct InputTableConfig {
    val: Column<Advice>,
    input_len: Column<Advice>,
    rs: Column<Advice>, // running sum
    s_rs: Selector,
}

impl InputTable for InputTableConfig {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        let val = cs.advice_column_in(FirstPhase);
        let input_len = cs.advice_column_in(FirstPhase);
        let rs = cs.advice_column_in(SecondPhase);
        cs.enable_equality(val);
        cs.enable_equality(rs);
        cs.enable_equality(input_len);
        let s_rs = cs.selector();
        Self {
            val,
            input_len,
            rs,
            s_rs,
        }
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
        inputs: &Column<Instance>,
        matrix: &Matrix,
        challenge: BFChallenge,
    ) -> Result<(BFCell, BFCell), Error> {
        let gamma = layouter.get_challenge(challenge.get_input_rs_challenge());
        layouter.assign_region(
            || "Load input table",
            |mut region| {
                // init rs_0
                let mut rs_prev = region.assign_advice(|| "rs", self.rs, 0, || Value::known(Fr::zero()))?;
                let len = region.assign_advice(
                    || "Input length",
                    self.input_len,
                    0,
                    || Value::known(Fr::from(matrix.input_matrix.len() as u64)),
                )?;
                for idx in 0..matrix.input_matrix.len() {
                    self.s_rs.enable(&mut region, idx)?;
                    // copy from instance
                    let input =
                        region.assign_advice_from_instance(|| "input value", *inputs, idx + 1, self.val, idx)?;
                    let rs = gamma * rs_prev.value() + input.value();
                    rs_prev = region.assign_advice(|| "rs", self.rs, idx + 1, || rs)?;
                }
                Ok((len, rs_prev))
            },
        )
    }
}
