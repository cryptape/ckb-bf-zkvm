use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fq;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;

#[derive(Clone, Debug, Copy)]
pub struct MemoryTableConfig {
    clk: Column<Advice>,
    mp: Column<Advice>,
    mv: Column<Advice>,
    s_m: Selector, // Selector for condition M category (Memory Table)
}

impl Config for MemoryTableConfig {
    fn configure(cs: &mut ConstraintSystem<Fq>) -> Self {
        let one = Expression::Constant(Fq::one());

        let clk = cs.advice_column();
        let mp = cs.advice_column();
        let mv = cs.advice_column();
        let s_m = cs.selector();

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
        Self { clk, mp, mv, s_m }
    }

    fn load_table(&self, layouter: &mut impl Layouter<Fq>, matrix: &Matrix) -> Result<(), Error> {
        layouter.assign_region(
            || "Load Memory Table",
            |mut region| {
                let memory_matrix = &matrix.memory_matrix;
                for (idx, row) in memory_matrix.iter().enumerate() {
                    if idx < memory_matrix.len() - 1 {
                        // M condition is enabled except last row
                        self.s_m.enable(&mut region, idx)?;
                    }
                    region.assign_advice(|| "clk", self.clk, idx, || Value::known(row.cycle))?;
                    region.assign_advice(|| "mp", self.mp, idx, || Value::known(row.memory_pointer))?;
                    region.assign_advice(|| "mv", self.mv, idx, || Value::known(row.memory_value))?;
                }
                Ok(())
            },
        )
    }
}
