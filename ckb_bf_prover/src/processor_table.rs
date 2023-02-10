use crate::range_table::RangeTableConfig;
use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::*;
use halo2_proofs::poly::Rotation;

pub trait ProcessorTable {
    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self;
    // Configure the second phase, query the challenges and create gate for prp
    fn configure_prp(self, cs: &mut ConstraintSystem<Fr>, prp_arg: PrpArg);
    // Load the processor table, calculate the prp and returns the final cell
    fn load_table(&self, layouter: &mut impl Layouter<Fr>, matrix: &Matrix, prp_arg: PrpArg) -> Result<BFCell, Error>;
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
    prp: Column<Advice>,
    lookup_table: RangeTableConfig<RANGE>, // Lookup table ensure mv are within [0-255]
    s_lookup: Selector,                    // Selector for lookup_table
    s_p: Selector,                         // Selector for condition P category (Processor Table)
    s_c: Selector,                         // Selector for condition C category (Consistency Constraints)
    s_b: Selector,                         // Selector for condition B category (Boundary Constraints)
    s_prp: Selector,
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
        let prp = cs.advice_column_in(SecondPhase);
        cs.enable_equality(prp);
        let lookup_table = RangeTableConfig::configure(cs);
        let s_lookup = cs.complex_selector();
        let s_c = cs.selector();
        let s_p = cs.selector();
        let s_b = cs.selector();
        let s_prp = cs.selector();

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

        // A deselector for op evalutes to zero iff ci != op
        let create_deselector = |ci: Expression<Fr>, op| {
            OPCODES.iter().fold(ci.clone(), |expr, v| {
                if *v == op {
                    expr
                } else {
                    expr * (ci.clone() - Expression::Constant(Fr::from(*v as u64)))
                }
            })
        };

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
            prp,
            lookup_table,
            s_lookup,
            s_p,
            s_c,
            s_b,
            s_prp,
        }
    }

    fn configure_prp(self, cs: &mut ConstraintSystem<Fr>, prp_arg: PrpArg) {
        cs.create_gate("Processor prp should have valid transition", |vc| {
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
        // Init lookup table
        self.lookup_table.load_table(layouter, matrix)?;
        assert_eq!(matrix.processor_matrix.len(), matrix.memory_matrix.len());
        // Read challenges
        let [alpha, d, e, f] = prp_arg.challenges.map(|c| layouter.get_challenge(c));
        layouter.assign_region(
            || "Load Processor Table",
            |mut region| {
                // init prp
                let mut prp_prev = region.assign_advice(|| "prp", self.prp, 0, || Value::known(prp_arg.init))?;
                let processor_matrix = &matrix.processor_matrix;
                // B condition is enabled only for the first row
                self.s_b.enable(&mut region, 0)?;
                for (idx, reg) in processor_matrix.iter().enumerate() {
                    if idx < processor_matrix.len() - 1 {
                        // P condition is enabled except last row
                        self.s_p.enable(&mut region, idx)?;
                    }
                    // Enable C/Lookup/prp check
                    self.s_c.enable(&mut region, idx)?;
                    self.s_lookup.enable(&mut region, idx)?;
                    self.s_prp.enable(&mut region, idx)?;

                    let clk = region.assign_advice(|| "clk", self.clk, idx, || Value::known(reg.cycle))?;
                    region.assign_advice(|| "ip", self.ip, idx, || Value::known(reg.instruction_pointer))?;
                    region.assign_advice(|| "ci", self.ci, idx, || Value::known(reg.current_instruction))?;
                    region.assign_advice(|| "ni", self.ni, idx, || Value::known(reg.next_instruction))?;
                    let mp = region.assign_advice(|| "mp", self.mp, idx, || Value::known(reg.memory_pointer))?;
                    let mv = region.assign_advice(|| "mv", self.mv, idx, || Value::known(reg.memory_value))?;
                    region.assign_advice(|| "mvi", self.mvi, idx, || Value::known(reg.memory_value_inverse))?;
                    let prp = prp_prev.value() * (alpha - d * clk.value() - e * mp.value() - f * mv.value());
                    prp_prev = region.assign_advice(|| "prp", self.prp, idx + 1, || prp)?;
                }
                Ok(prp_prev)
            },
        )
    }
}
