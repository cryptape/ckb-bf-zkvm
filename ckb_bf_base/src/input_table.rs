use crate::poseidon_hash::hash_message;
use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;
use poseidon_circuit::poseidon::PermuteChip;

pub trait InputTable {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    fn configure_second_phase(&self, cs: &mut ConstraintSystem<Fr>, challenge: BFChallenge);
    fn load_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
        matrix: &Matrix,
        challenge: BFChallenge,
    ) -> Result<(BFCell, BFCell), Error>;
}

#[derive(Clone, Debug)]
pub struct InputTableConfig {
    val: Column<Advice>,
    rs: Column<Advice>, // running sum
    // This is an ad-hoc solution for hashing empty inputs, which is not correct.
    // A more proper approach is to concatenate a new table consisting of program and input
    // (which requires extra proof using permutation)
    // or use a hash gadget that supports a default nil_input_hash internally.
    nil_input_hash: Column<Advice>,
    s_rs: Selector,
    hash_config: HashConfig,
}

impl InputTable for InputTableConfig {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        let val = cs.advice_column_in(FirstPhase);
        let nil_input_hash = cs.advice_column_in(FirstPhase);
        let rs = cs.advice_column_in(SecondPhase);
        cs.enable_equality(val);
        cs.enable_equality(nil_input_hash);
        cs.enable_equality(rs);
        let s_rs = cs.selector();
        Self {
            val,
            rs,
            nil_input_hash,
            s_rs,
            hash_config: <HashChip as PermuteChip<Fr>>::configure(cs),
        }
    }

    fn configure_second_phase(&self, cs: &mut ConstraintSystem<Fr>, challenge: BFChallenge) {
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
    ) -> Result<(BFCell, BFCell), Error> {
        let gamma = layouter.get_challenge(challenge.get_input_rs_challenge());
        let (message, rs_prev) = layouter.assign_region(
            || "Load input table",
            |mut region| {
                let nil = region.assign_advice(
                    || "nil msg hash",
                    self.nil_input_hash,
                    0,
                    || Value::known(Fr::from(NIL_HASH_MSG)),
                )?;
                // init rs_0
                let mut rs_prev = region.assign_advice(|| "rs", self.rs, 0, || Value::known(Fr::zero()))?;
                let mut message = vec![];
                for (idx, input) in matrix.input_matrix.iter().enumerate() {
                    self.s_rs.enable(&mut region, idx)?;
                    // copy from instance
                    let input = region.assign_advice(|| "input value", self.val, idx, || Value::known(*input))?;
                    message.push(input.clone());
                    let rs = gamma * rs_prev.value() + input.value();
                    rs_prev = region.assign_advice(|| "rs", self.rs, idx + 1, || rs)?;
                }
                if message.len() == 0 {
                    message.push(nil.clone())
                }
                Ok((message, rs_prev))
            },
        )?;
        if message.len() == 0 {}
        let output = hash_message(message, self.hash_config.clone(), layouter)?;
        Ok((output, rs_prev))
    }
}
