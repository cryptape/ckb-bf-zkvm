use crate::range_table::{RangeTable, RangeTableConfig};
use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;

pub trait ProcessorTable {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    fn configure_second_phase(self, cs: &mut ConstraintSystem<Fr>, challenges: BFChallenge);
    // Load the processor table, returns (mem_prp, output_rs, input_rs, inst_prp)
    fn load_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
        matrix: &Matrix,
        challenges: BFChallenge,
    ) -> Result<(BFCell, BFCell, BFCell, BFCell), Error>;
}

#[derive(Clone, Debug, Copy)]
pub struct ProcessorTableConfig<const RANGE: usize> {
    clk: Column<Advice>,
    ip: Column<Advice>,
    ci: Column<Advice>,
    ni: Column<Advice>,
    mp: Column<Advice>,
    mv: Column<Advice>,
    mvi: Column<Advice>,
    mem_prp: Column<Advice>,
    inst_prp: Column<Advice>,
    output_rs: Column<Advice>,
    input_rs: Column<Advice>,
    lookup_table: RangeTableConfig<RANGE>, // Lookup table ensure mv are within [0-255]
    s_lookup: Selector,                    // Selector for lookup_table
    s_p: Selector,                         // Selector for condition P category (Processor Table)
    s_c: Selector,                         // Selector for condition C category (Consistency Constraints)
    s_b: Selector,                         // Selector for condition B category (Boundary Constraints)
    s_prp: Selector,
    s_rs: Selector,
}

// A deselector for op evalutes to zero iff ci != op (Given legal ops)
fn create_deselector(ci: Expression<Fr>, op: u8) -> Expression<Fr> {
    let one = Expression::Constant(Fr::one());
    OPCODES.iter().fold(one.clone(), |expr, v| {
        if *v == op {
            expr
        } else {
            expr * (ci.clone() - Expression::Constant(Fr::from(*v as u64)))
        }
    })
}

// a selector for op evalutes to zero iff ci == op
fn create_selector(ci: Expression<Fr>, op: u8) -> Expression<Fr> {
    ci.clone() - Expression::Constant(Fr::from(op as u64))
}

impl<const RANGE: usize> ProcessorTable for ProcessorTableConfig<RANGE> {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self {
        let zero = Expression::Constant(Fr::zero());
        let one = Expression::Constant(Fr::one());
        let two = Expression::Constant(Fr::from(2));
        let range_max = Expression::Constant(Fr::from((RANGE - 1) as u64));

        let clk = cs.advice_column_in(FirstPhase);
        let ci = cs.advice_column();
        let ip = cs.advice_column();
        let ni = cs.advice_column();
        let mp = cs.advice_column_in(FirstPhase);
        let mv = cs.advice_column_in(FirstPhase);
        let mvi = cs.advice_column();
        let mem_prp = cs.advice_column_in(SecondPhase);
        cs.enable_equality(mem_prp);
        let inst_prp = cs.advice_column_in(SecondPhase);
        cs.enable_equality(inst_prp);
        let output_rs = cs.advice_column_in(SecondPhase);
        cs.enable_equality(output_rs);
        let input_rs = cs.advice_column_in(SecondPhase);
        cs.enable_equality(input_rs);
        let lookup_table = RangeTableConfig::configure(cs);
        let s_lookup = cs.complex_selector();
        let s_c = cs.selector();
        let s_p = cs.selector();
        let s_b = cs.selector();
        let s_prp = cs.selector();
        let s_rs = cs.selector();

        cs.create_gate("B0: clk_0 = 0", |vc| {
            let s_b = vc.query_selector(s_b);
            let clk = vc.query_advice(clk, Rotation::cur());
            vec![s_b * clk]
        });

        cs.create_gate("B1: ip_0 = 0", |vc| {
            let s_b = vc.query_selector(s_b);
            let ip = vc.query_advice(ip, Rotation::cur());
            vec![s_b * ip]
        });

        cs.create_gate("B3: mp_0 = 0", |vc| {
            let s_b = vc.query_selector(s_b);
            let mp = vc.query_advice(mp, Rotation::cur());
            vec![s_b * mp]
        });

        cs.create_gate("B4: mv_0 = 0", |vc| {
            let s_b = vc.query_selector(s_b);
            let mv = vc.query_advice(mv, Rotation::cur());
            vec![s_b * mv]
        });

        cs.lookup("Range-Check: mv are within 0-255", |vc| {
            let s_lookup = vc.query_selector(s_lookup);
            let mv = vc.query_advice(mv, Rotation::cur());
            vec![(s_lookup * mv, lookup_table.table)]
        });

        cs.create_gate("P0: clk increase one per step", |vc| {
            let s_p = vc.query_selector(s_p);
            let cur_clk = vc.query_advice(clk, Rotation::cur());
            let next_clk = vc.query_advice(clk, Rotation::next());
            vec![s_p * (next_clk - cur_clk - one.clone())]
        });

        cs.create_gate("C0: mv is 0 or mvi is the inverse of mv", |vc| {
            let s_c = vc.query_selector(s_c);
            let mv = vc.query_advice(mv, Rotation::cur());
            let mvi = vc.query_advice(mvi, Rotation::cur());
            vec![s_c * mv.clone() * (mv * mvi - one.clone())]
        });

        cs.create_gate("C1: mvi is 0 or mvi is the inverse of mv", |vc| {
            let s_c = vc.query_selector(s_c);
            let mv = vc.query_advice(mv, Rotation::cur());
            let mvi = vc.query_advice(mvi, Rotation::cur());
            vec![s_c * mvi.clone() * (mv * mvi - one.clone())]
        });

        cs.create_gate("P_1: instruction mutates state(1) correctly ", |vc| {
            let ci = vc.query_advice(ci, Rotation::cur());
            let deselectors = OPCODES.iter().map(|op| create_deselector(ci.clone(), *op)).collect::<Vec<_>>();
            let cur_ip = vc.query_advice(ip, Rotation::cur());
            let next_ip = vc.query_advice(ip, Rotation::next());
            let cur_mv = vc.query_advice(mv, Rotation::cur());
            let cur_mvi = vc.query_advice(mvi, Rotation::cur());
            let cur_ni = vc.query_advice(ni, Rotation::cur());
            let s_p = vc.query_selector(s_p);
            // ADD SUB SHR SHL GETCHAR PUTCHAR share the same p1 condition:
            // ip increases by 1
            let expr1 = (deselectors[ADD].clone()
                + deselectors[SUB].clone()
                + deselectors[SHR].clone()
                + deselectors[SHL].clone()
                + deselectors[GETCHAR].clone()
                + deselectors[PUTCHAR].clone())
                * (next_ip.clone() - cur_ip.clone() - one.clone());
            // LB: if mv != 0 ⇒ ip increases by 2 and if mv == 0 ⇒ ip is set to ni
            let expr_lb = deselectors[LB].clone()
                * (cur_mv.clone() * (next_ip.clone() - cur_ip.clone() - two.clone())
                    + (cur_mv.clone() * cur_mvi.clone() - one.clone()) * (next_ip.clone() - cur_ni.clone()));
            // RB: if mv == 0 ⇒ ip increases by 2 and if mv != 0 ⇒ ip is set to ni
            let expr_rb = deselectors[RB].clone()
                * ((cur_mv.clone() * cur_mvi.clone() - one.clone()) * (next_ip.clone() - cur_ip.clone() - two.clone())
                    + (cur_mv.clone() * (next_ip.clone() - cur_ni.clone())));
            vec![s_p * (expr1 + expr_lb + expr_rb)]
        });

        cs.create_gate("P_2: instruction mutates state(2) correctly", |vc| {
            let ci = vc.query_advice(ci, Rotation::cur());
            let deselectors = OPCODES.iter().map(|op| create_deselector(ci.clone(), *op)).collect::<Vec<_>>();
            let s_p = vc.query_selector(s_p);
            let cur_mp = vc.query_advice(mp, Rotation::cur());
            let next_mp = vc.query_advice(mp, Rotation::next());
            // ADD, SUB, LB, RB, GETCHAR, PUTCHAR share the same p2 condition:
            // memory pointer stay at the same
            let expr1 = (deselectors[ADD].clone()
                + deselectors[SUB].clone()
                + deselectors[LB].clone()
                + deselectors[RB].clone()
                + deselectors[GETCHAR].clone()
                + deselectors[PUTCHAR].clone())
                * (next_mp.clone() - cur_mp.clone());
            // SHL: mp decreases by one
            let expr_shl = deselectors[SHL].clone() * (next_mp.clone() - cur_mp.clone() + one.clone());
            // SHR: mp increases by one
            let expr_shr = deselectors[SHR].clone() * (next_mp.clone() - cur_mp.clone() - one.clone());
            vec![s_p * (expr1 + expr_shl + expr_shr)]
        });

        cs.create_gate("P_3: instruction mutates state(3) correctly", |vc| {
            let ci = vc.query_advice(ci, Rotation::cur());
            let deselectors = OPCODES.iter().map(|op| create_deselector(ci.clone(), *op)).collect::<Vec<_>>();
            let s_p = vc.query_selector(s_p);
            let cur_mv = vc.query_advice(mv, Rotation::cur());
            let next_mv = vc.query_advice(mv, Rotation::next());
            // LB, RB, PUTCHAR share the same p3 condition:
            // memory value stay at the same
            let expr1 = (deselectors[LB].clone() + deselectors[RB].clone() + deselectors[PUTCHAR].clone())
                * (next_mv.clone() - cur_mv.clone());
            // note: we have lookup table to ensure all mvs are within [0-255],
            // therefore, value can only decreases by 255 iff cur_mv=255, next_mv=0
            // same goes for wrapping_sub
            // ADD: mv increases by 1, or decreases by 255
            let expr_add = deselectors[ADD].clone()
                * (next_mv.clone() - cur_mv.clone() - one.clone())
                * (next_mv.clone() - cur_mv.clone() + range_max.clone());
            // sub: mv decreases by 1, or increases by 255
            let expr_sub = deselectors[SUB].clone()
                * (next_mv.clone() - cur_mv.clone() + one.clone())
                * (next_mv.clone() - cur_mv.clone() - range_max.clone());
            // SHL, SHR, GETCHAR: always true (check elsewhere)
            let expr2 =
                (deselectors[SHL].clone() + deselectors[SHR].clone() + deselectors[GETCHAR].clone()) * (zero.clone());
            vec![s_p * (expr1 + expr2 + expr_add + expr_sub)]
        });

        Self {
            clk,
            ip,
            ci,
            ni,
            mp,
            mv,
            mvi,
            mem_prp,
            inst_prp,
            output_rs,
            input_rs,
            lookup_table,
            s_lookup,
            s_p,
            s_c,
            s_b,
            s_prp,
            s_rs,
        }
    }

    fn configure_second_phase(self, cs: &mut ConstraintSystem<Fr>, challenges: BFChallenge) {
        cs.create_gate("Mem prp should have valid transition", |vc| {
            let clk = vc.query_advice(self.clk, Rotation::cur());
            let mp = vc.query_advice(self.mp, Rotation::cur());
            let mv = vc.query_advice(self.mv, Rotation::cur());
            let prp_cur = vc.query_advice(self.mem_prp, Rotation::cur());
            let prp_next = vc.query_advice(self.mem_prp, Rotation::next());
            let s_prp = vc.query_selector(self.s_prp);
            let [alpha, d, e, f] = challenges.get_mem_prp_challenges().map(|c| vc.query_challenge(c));
            vec![s_prp * (prp_next - prp_cur * (alpha - d * clk - e * mp - f * mv))]
        });

        cs.create_gate("Inst prp should have valid transition", |vc| {
            let ip = vc.query_advice(self.ip, Rotation::cur());
            let ci = vc.query_advice(self.ci, Rotation::cur());
            let ni = vc.query_advice(self.ni, Rotation::cur());
            let prp_cur = vc.query_advice(self.inst_prp, Rotation::cur());
            let prp_next = vc.query_advice(self.inst_prp, Rotation::next());
            let s_prp = vc.query_selector(self.s_prp);
            let [alpha, d, e, f] = challenges.get_inst_prp_challenges().map(|c| vc.query_challenge(c));
            vec![s_prp * (prp_next - prp_cur * (alpha - d * ip - e * ci - f * ni))]
        });

        cs.create_gate(
            "proceossor table should have correct running sum transition for output vals",
            |vc| {
                let ci = vc.query_advice(self.ci, Rotation::cur());
                let deselectors = OPCODES.iter().map(|op| create_deselector(ci.clone(), *op)).collect::<Vec<_>>();
                let selectors = OPCODES.iter().map(|op| create_selector(ci.clone(), *op)).collect::<Vec<_>>();
                let mv = vc.query_advice(self.mv, Rotation::cur());
                let rs_cur = vc.query_advice(self.output_rs, Rotation::cur());
                let rs_next = vc.query_advice(self.output_rs, Rotation::next());
                let gamma = vc.query_challenge(challenges.get_output_rs_challenge());
                let s_rs = vc.query_selector(self.s_rs);
                vec![
                    s_rs * (deselectors[PUTCHAR].clone() * (rs_next.clone() - (rs_cur.clone() * gamma + mv))
                        + selectors[PUTCHAR].clone() * (rs_next.clone() - rs_cur)),
                ]
            },
        );

        cs.create_gate(
            "proceossor table should have correct running sum transition for input vals",
            |vc| {
                let ci = vc.query_advice(self.ci, Rotation::cur());
                let deselectors = OPCODES.iter().map(|op| create_deselector(ci.clone(), *op)).collect::<Vec<_>>();
                let selectors = OPCODES.iter().map(|op| create_selector(ci.clone(), *op)).collect::<Vec<_>>();
                // mv at next row is the value read in
                let mv = vc.query_advice(self.mv, Rotation::next());
                let rs_cur = vc.query_advice(self.input_rs, Rotation::cur());
                let rs_next = vc.query_advice(self.input_rs, Rotation::next());
                let gamma = vc.query_challenge(challenges.get_input_rs_challenge());
                let s_rs = vc.query_selector(self.s_rs);
                vec![
                    s_rs * (deselectors[GETCHAR].clone() * (rs_next.clone() - (rs_cur.clone() * gamma + mv))
                        + selectors[GETCHAR].clone() * (rs_next.clone() - rs_cur)),
                ]
            },
        );
    }

    fn load_table(
        &self,
        layouter: &mut impl Layouter<Fr>,
        matrix: &Matrix,
        challenges: BFChallenge,
    ) -> Result<(BFCell, BFCell, BFCell, BFCell), Error> {
        let putchar_fr = Fr::from(OPCODES[PUTCHAR] as u64);
        let getchar_fr = Fr::from(OPCODES[GETCHAR] as u64);
        // Init lookup table
        self.lookup_table.load_table(layouter, matrix)?;
        // Read challenges
        let [m_alpha, m_d, m_e, m_f] = challenges.get_mem_prp_challenges().map(|c| layouter.get_challenge(c));
        let [i_alpha, i_d, i_e, i_f] = challenges.get_inst_prp_challenges().map(|c| layouter.get_challenge(c));
        let out_gamma = layouter.get_challenge(challenges.get_output_rs_challenge());
        let in_gamma = layouter.get_challenge(challenges.get_input_rs_challenge());
        layouter.assign_region(
            || "Load Processor Table",
            |mut region| {
                // init prp and rs
                let mut mem_prp_prev =
                    region.assign_advice(|| "mem prp", self.mem_prp, 0, || Value::known(challenges.mem_prp_init))?;
                let mut inst_prp_prev = region.assign_advice(
                    || "inst prp",
                    self.inst_prp,
                    0,
                    || Value::known(challenges.inst_prp_init),
                )?;
                let mut output_rs_prev =
                    region.assign_advice(|| "output rs", self.output_rs, 0, || Value::known(Fr::zero()))?;
                let mut input_rs_prev =
                    region.assign_advice(|| "input rs", self.input_rs, 0, || Value::known(Fr::zero()))?;
                let processor_matrix = &matrix.processor_matrix;
                // B condition is enabled only for the first row
                self.s_b.enable(&mut region, 0)?;
                for (idx, reg) in processor_matrix.iter().enumerate() {
                    // Selectors that are enabled except last row
                    if idx < processor_matrix.len() - 1 {
                        self.s_p.enable(&mut region, idx)?;
                        self.s_rs.enable(&mut region, idx)?;
                    }
                    // Enable C/Lookup/prp check
                    self.s_c.enable(&mut region, idx)?;
                    self.s_lookup.enable(&mut region, idx)?;
                    self.s_prp.enable(&mut region, idx)?;

                    let clk = region.assign_advice(|| "clk", self.clk, idx, || Value::known(reg.cycle))?;
                    let ip = region.assign_advice(|| "ip", self.ip, idx, || Value::known(reg.instruction_pointer))?;
                    let ci = region.assign_advice(|| "ci", self.ci, idx, || Value::known(reg.current_instruction))?;
                    let ni = region.assign_advice(|| "ni", self.ni, idx, || Value::known(reg.next_instruction))?;
                    let mp = region.assign_advice(|| "mp", self.mp, idx, || Value::known(reg.memory_pointer))?;
                    let mv = region.assign_advice(|| "mv", self.mv, idx, || Value::known(reg.memory_value))?;
                    region.assign_advice(|| "mvi", self.mvi, idx, || Value::known(reg.memory_value_inverse))?;
                    let mem_prp =
                        mem_prp_prev.value() * (m_alpha - m_d * clk.value() - m_e * mp.value() - m_f * mv.value());
                    let inst_prp =
                        inst_prp_prev.value() * (i_alpha - i_d * ip.value() - i_e * ci.value() - i_f * ni.value());
                    let output_rs = if reg.current_instruction == putchar_fr {
                        output_rs_prev.value() * out_gamma + mv.value()
                    } else {
                        output_rs_prev.value().map(|x| *x)
                    };
                    let input_rs = if reg.current_instruction == getchar_fr {
                        let next_mv = processor_matrix
                            .get(idx + 1)
                            .expect("This cannot fail for a valid trace record")
                            .memory_value;
                        input_rs_prev.value() * in_gamma + Value::known(next_mv)
                    } else {
                        input_rs_prev.value().map(|x| *x)
                    };
                    mem_prp_prev = region.assign_advice(|| "mem_prp", self.mem_prp, idx + 1, || mem_prp)?;
                    inst_prp_prev = region.assign_advice(|| "inst prp", self.inst_prp, idx + 1, || inst_prp)?;
                    output_rs_prev = region.assign_advice(|| "output rs", self.output_rs, idx + 1, || output_rs)?;
                    input_rs_prev = region.assign_advice(|| "input rs", self.input_rs, idx + 1, || input_rs)?;
                }
                Ok((mem_prp_prev, output_rs_prev, input_rs_prev, inst_prp_prev))
            },
        )
    }
}
