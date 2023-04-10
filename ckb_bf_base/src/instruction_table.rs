use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;

pub trait InstructionTable {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    fn configure_second_phase(self, cs: &mut ConstraintSystem<Fr>, challenges: BFChallenge);
    fn load_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
        matrix: &Matrix,
        challenges: BFChallenge,
    ) -> Result<(BFCell, BFCell), Error>;
}

#[derive(Clone, Debug, Copy)]
pub struct InstructionTableConfig {
    ip: Column<Advice>,
    ci: Column<Advice>,
    ni: Column<Advice>,
    prp: Column<Advice>,
    rs: Column<Advice>,
    s_prp: Selector,
    s_prp_adhoc: Selector,
    s_rs: Selector,
    s_i: Selector, // Selector for condition I category (Instruction Table)
}

impl InstructionTable for InstructionTableConfig {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        let one = Expression::Constant(Fr::one());

        let ip = cs.advice_column_in(FirstPhase);
        let ci = cs.advice_column_in(FirstPhase);
        let ni = cs.advice_column_in(FirstPhase);
        let prp = cs.advice_column_in(SecondPhase);
        let rs = cs.advice_column_in(SecondPhase);
        cs.enable_equality(prp);
        cs.enable_equality(rs);
        let s_prp = cs.selector();
        let s_rs = cs.selector();
        let s_prp_adhoc = cs.selector();
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
        Self {
            ip,
            ci,
            ni,
            prp,
            rs,
            s_i,
            s_prp,
            s_prp_adhoc,
            s_rs,
        }
    }

    fn configure_second_phase(self, cs: &mut ConstraintSystem<Fr>, challenges: BFChallenge) {
        let one = Expression::Constant(Fr::one());
        cs.create_gate("Code rs should have valid transition", |vc| {
            let ip_cur = vc.query_advice(self.ip, Rotation::cur());
            let ip_next = vc.query_advice(self.ip, Rotation::next());
            let ci = vc.query_advice(self.ci, Rotation::cur());
            let s_rs = vc.query_selector(self.s_rs);
            let gamma = vc.query_challenge(challenges.get_inst_rs_challenges());
            let rs_cur = vc.query_advice(self.rs, Rotation::cur());
            let rs_next = vc.query_advice(self.rs, Rotation::next());
            vec![
                s_rs * ((ip_next.clone() - ip_cur.clone()) * (rs_next.clone() - (rs_cur.clone() * gamma + ci))
                    + (ip_next - ip_cur - one.clone()) * (rs_next - rs_cur)),
            ]
        });

        cs.create_gate("Instruction prp should have valid transition", |vc| {
            let ip_cur = vc.query_advice(self.ip, Rotation::cur());
            let ip_next = vc.query_advice(self.ip, Rotation::next());
            let ci = vc.query_advice(self.ci, Rotation::cur());
            let ni = vc.query_advice(self.ni, Rotation::cur());
            let prp_next = vc.query_advice(self.prp, Rotation::next());
            let prp_cur = vc.query_advice(self.prp, Rotation::cur());
            let s_prp = vc.query_selector(self.s_prp);
            let [alpha, d, e, f] = challenges.get_inst_prp_challenges().map(|c| vc.query_challenge(c));
            vec![
                s_prp
                    * ((ip_next.clone() - ip_cur.clone() - one.clone())
                        * (prp_next.clone() - prp_cur.clone() * (alpha - d * ip_cur.clone() - e * ci - f * ni))
                        + (ip_cur - ip_next) * (prp_cur - prp_next)),
            ]
        });
        // The definition of the processor table contains a dummy row after termination
        // (ip past program with ci = ni = 0)
        // Therefore, our instruction table contains this dummy row as well.
        // However, the above gate never covers the dummy row, which is at the end of instruction table.
        // When calculating the prp, we include the last row but we would need an ad-hoc gate
        // to check the constraint for the last element.
        cs.create_gate("Instruction prp should have include the dummy row", |vc| {
            let ip_prev = vc.query_advice(self.ip, Rotation::prev());
            let ci_prev = vc.query_advice(self.ci, Rotation::prev());
            let ni_prev = vc.query_advice(self.ni, Rotation::prev());
            let prp_prev = vc.query_advice(self.prp, Rotation::prev());
            let prp_cur = vc.query_advice(self.prp, Rotation::cur());
            let s_prp_adhoc = vc.query_selector(self.s_prp_adhoc);
            let [alpha, d, e, f] = challenges.get_inst_prp_challenges().map(|c| vc.query_challenge(c));
            vec![
                s_prp_adhoc
                    * (prp_cur.clone() - prp_prev.clone() * (alpha - d * ip_prev.clone() - e * ci_prev - f * ni_prev)),
            ]
        });
    }

    fn load_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
        matrix: &Matrix,
        challenges: BFChallenge,
    ) -> Result<(BFCell, BFCell), Error> {
        let [alpha, d, e, f] = challenges.get_inst_prp_challenges().map(|c| layouter.get_challenge(c));
        let gamma = layouter.get_challenge(challenges.get_inst_rs_challenges());
        layouter.assign_region(
            || "Load Instruction Table",
            |mut region| {
                let mut prp_prev =
                    region.assign_advice(|| "prp", self.prp, 0, || Value::known(challenges.inst_prp_init))?;
                let mut rs_prev = region.assign_advice(|| "rs", self.rs, 0, || Value::known(Fr::zero()))?;
                let instruction_matrix = &matrix.instruction_matrix;
                self.s_prp_adhoc.enable(&mut region, instruction_matrix.len())?;
                for (idx, row) in instruction_matrix.iter().enumerate() {
                    if idx < instruction_matrix.len() - 1 {
                        // I condition is enabled except last row
                        self.s_i.enable(&mut region, idx)?;
                        self.s_prp.enable(&mut region, idx)?;
                        self.s_rs.enable(&mut region, idx)?;
                    }

                    region.assign_advice(|| "ip", self.ip, idx, || Value::known(row.instruction_pointer))?;
                    let ci = region.assign_advice(|| "ci", self.ci, idx, || Value::known(row.current_instruction))?;
                    let ni = region.assign_advice(|| "ni", self.ni, idx, || Value::known(row.next_instruction))?;
                    let next_row = instruction_matrix.get(idx + 1);
                    let ip_cur = row.instruction_pointer;
                    // cal and assign rs
                    // ad-hoc solution to include the last dummy row for prp
                    let ip_next = next_row.unwrap_or(row).instruction_pointer;
                    // cal and assign prp
                    let prp = if ip_next == ip_cur {
                        prp_prev.value() * (alpha - d * Value::known(ip_cur) - e * ci.value() - f * ni.value())
                    } else {
                        prp_prev.value().map(|x| *x)
                    };
                    prp_prev = region.assign_advice(|| "prp", self.prp, idx + 1, || prp)?;
                    // cal and assign rs
                    let rs = if ip_next != ip_cur {
                        gamma * rs_prev.value() + ci.value()
                    } else {
                        rs_prev.value().map(|x| *x)
                    };
                    rs_prev = region.assign_advice(|| "code rs", self.rs, idx + 1, || rs)?;
                }
                Ok((rs_prev, prp_prev))
            },
        )
    }
}
