use crate::utils::*;
use ckb_bf_vm::matrix::Matrix;

use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fq;
use halo2_proofs::plonk::*;

#[derive(Clone, Debug, Copy)]
pub struct RangeTableConfig<const RANGE: usize> {
    pub table: TableColumn,
}

impl<const RANGE: usize> Config for RangeTableConfig<RANGE> {
    fn configure(cs: &mut ConstraintSystem<Fq>) -> Self {
        let table = cs.lookup_table_column();
        Self { table }
    }

    fn load_table(&self, layouter: &mut impl Layouter<Fq>, _: &Matrix) -> Result<(), Error> {
        layouter.assign_table(
            || "load range-check table",
            |mut table| {
                let mut offset = 0;
                for value in 0..RANGE {
                    table.assign_cell(|| "value", self.table, offset, || Value::known(Fq::from(value as u64)))?;
                    offset += 1;
                }

                Ok(())
            },
        )
    }
}
