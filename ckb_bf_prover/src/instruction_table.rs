use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;

#[derive(Clone, Debug, Copy)]
pub struct InstructionTableConfig {
    ip: Column<Advice>,
    ci: Column<Advice>,
    ni: Column<Advice>,
    s_i: Selector, // Selector for condition I category (Instruction Table)
}

impl Config for InstructionTableConfig {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        let one = Expression::Constant(Fr::one());

        let ip = cs.advice_column();
        let ci = cs.advice_column();
        let ni = cs.advice_column();
        let s_i = cs.selector();

        cs.create_gate("I0: Instruction pointer increases by 0 or 1", |vc| {
            let cur_ip = vc.query_advice(ip, Rotation::cur());
            let next_ip = vc.query_advice(ip, Rotation::next());
            let s_i = vc.query_selector(s_i);
            vec![s_i * (next_ip.clone() - cur_ip.clone()) * (next_ip.clone() - cur_ip.clone() - one.clone())]
        });

        cs.create_gate("I1: If ip is unchanged, then ci is also unchanged.", |vc| {
            let cur_ip = vc.query_advice(ip, Rotation::cur());
            let next_ip = vc.query_advice(ip, Rotation::next());
            let cur_ci = vc.query_advice(ci, Rotation::cur());
            let next_ci = vc.query_advice(ci, Rotation::next());
            let s_i = vc.query_selector(s_i);
            vec![s_i * (next_ip.clone() - cur_ip.clone() - one.clone()) * (next_ci.clone() - cur_ci.clone())]
        });

        cs.create_gate("I2: If ip is unchanged, then ni is also unchanged.", |vc| {
            let cur_ip = vc.query_advice(ip, Rotation::cur());
            let next_ip = vc.query_advice(ip, Rotation::next());
            let cur_ni = vc.query_advice(ni, Rotation::cur());
            let next_ni = vc.query_advice(ni, Rotation::next());
            let s_i = vc.query_selector(s_i);
            vec![s_i * (next_ip.clone() - cur_ip.clone() - one.clone()) * (next_ni.clone() - cur_ni.clone())]
        });
        Self { ip, ci, ni, s_i }
    }

    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix) -> Result<(), Error> {
        layouter.assign_region(
            || "Load Instruction Table",
            |mut region| {
                let instruction_matrix = &matrix.instruction_matrix;
                for (idx, row) in instruction_matrix.iter().enumerate() {
                    if idx < instruction_matrix.len() - 1 {
                        // I condition is enabled except last row
                        self.s_i.enable(&mut region, idx)?;
                    }
                    region.assign_advice(|| "ip", self.ip, idx, || Value::known(row.instruction_pointer))?;
                    region.assign_advice(|| "ci", self.ci, idx, || Value::known(row.current_instruction))?;
                    region.assign_advice(|| "ni", self.ni, idx, || Value::known(row.next_instruction))?;
                }
                Ok(())
            },
        )
    }
}
