use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;

pub trait MemoryTable {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    // Configure the second phase, query the challenges and create gate for prp
    fn configure_prp(self, cs: &mut ConstraintSystem<Fr>, prp_arg: PrpArg);
    // Load the processor table, calculate the prp and returns the final cell
    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix, prp_arg: PrpArg) -> Result<BFCell, Error>;
}

#[derive(Clone, Debug, Copy)]
pub struct MemoryTableConfig {
    clk: Column<Advice>,
    mp: Column<Advice>,
    mv: Column<Advice>,
    prp: Column<Advice>,
    s_m: Selector, // selector for condition m category (memory table)
    s_prp: Selector,
}

impl MemoryTable for MemoryTableConfig {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        let one = Expression::Constant(Fr::one());

        let clk = cs.advice_column_in(FirstPhase);
        let mp = cs.advice_column_in(FirstPhase);
        let mv = cs.advice_column_in(FirstPhase);
        let prp = cs.advice_column_in(SecondPhase);
        cs.enable_equality(prp);
        let s_m = cs.selector();
        let s_prp = cs.selector();

        cs.create_gate("M0: memory pointer either increase by one or by zero", |vc| {
            let cur_mp = vc.query_advice(mp, Rotation::cur());
            let next_mp = vc.query_advice(mp, Rotation::next());
            let s_m = vc.query_selector(s_m);
            vec![s_m * (next_mp.clone() - cur_mp.clone() - one.clone()) * (next_mp.clone() - cur_mp.clone())]
        });

        cs.create_gate(
            "M1: If cur_mp <= next_mp and cur_mv = next_mv, clk must only increase by one.",
            |vc| {
                let cur_mp = vc.query_advice(mp, Rotation::cur());
                let next_mp = vc.query_advice(mp, Rotation::next());
                let cur_mv = vc.query_advice(mv, Rotation::cur());
                let next_mv = vc.query_advice(mv, Rotation::next());
                let cur_clk = vc.query_advice(clk, Rotation::cur());
                let next_clk = vc.query_advice(clk, Rotation::next());
                let s_m = vc.query_selector(s_m);
                vec![
                    s_m * (next_mp.clone() - cur_mp.clone() - one.clone())
                        * (cur_mv.clone() - next_mv.clone())
                        * (next_clk - cur_clk.clone() - one.clone()),
                ]
            },
        );

        cs.create_gate("M2: If mp increases by 1, then mv must be set to zero.", |vc| {
            let cur_mp = vc.query_advice(mp, Rotation::cur());
            let next_mp = vc.query_advice(mp, Rotation::next());
            let next_mv = vc.query_advice(mv, Rotation::next());
            let s_m = vc.query_selector(s_m);
            vec![s_m * (next_mp.clone() - cur_mp.clone()) * (next_mv)]
        });
        Self {
            clk,
            mp,
            mv,
            prp,
            s_m,
            s_prp,
        }
    }

    fn configure_prp(self, cs: &mut ConstraintSystem<Fr>, prp_arg: PrpArg) {
        cs.create_gate("Memory prp should have valid transition", |vc| {
            let clk = vc.query_advice(self.clk, Rotation::cur());
            let mp = vc.query_advice(self.mp, Rotation::cur());
            let mv = vc.query_advice(self.mv, Rotation::cur());
            let prp_cur = vc.query_advice(self.prp, Rotation::cur());
            let prp_next = vc.query_advice(self.prp, Rotation::next());
            let s_prp = vc.query_selector(self.s_prp);
            let [alpha, d, e, f] = prp_arg.challenges.map(|c| vc.query_challenge(c));
            vec![s_prp * (prp_next - prp_cur * (alpha - d * clk - e * mp - f * mv))]
        });
    }

    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix, prp_arg: PrpArg) -> Result<BFCell, Error> {
        // Read challenges
        let [alpha, d, e, f] = prp_arg.challenges.map(|c| layouter.get_challenge(c));
        layouter.assign_region(
            || "Load Memory Table",
            |mut region| {
                // init prp
                let mut prp_prev = region.assign_advice(|| "prp", self.prp, 0, || Value::known(prp_arg.init))?;
                let memory_matrix = &matrix.memory_matrix;
                for (idx, row) in memory_matrix.iter().enumerate() {
                    if idx < memory_matrix.len() - 1 {
                        // M condition is enabled except last row
                        self.s_m.enable(&mut region, idx)?;
                    }
                    self.s_prp.enable(&mut region, idx)?;
                    let clk = region.assign_advice(|| "clk", self.clk, idx, || Value::known(row.cycle))?;
                    let mp = region.assign_advice(|| "mp", self.mp, idx, || Value::known(row.memory_pointer))?;
                    let mv = region.assign_advice(|| "mv", self.mv, idx, || Value::known(row.memory_value))?;
                    let prp = prp_prev.value() * (alpha - d * clk.value() - e * mp.value() - f * mv.value());
                    prp_prev = region.assign_advice(|| "prp", self.prp, idx + 1, || prp)?;
                }
                Ok(prp_prev)
            },
        )
    }
}
