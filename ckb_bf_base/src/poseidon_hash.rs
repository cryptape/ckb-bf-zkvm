use crate::utils::*;
use alloc::vec::Vec;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::Error;
use poseidon_circuit::hash::Hashable;
use poseidon_circuit::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash};
use poseidon_circuit::poseidon::{Hash as CircuitHash, PermuteChip};

pub fn poseidon_hash<T, F>(inputs: Vec<T>, mut hasher: F) -> Result<T, Error>
where
    T: Clone,
    F: FnMut([T; 2]) -> Result<T, Error>,
{
    assert!(inputs.len() != 0);
    let mut cur_hash = inputs;
    let mut to_hash = vec![];
    while cur_hash.len() > 1 {
        let iter = cur_hash.chunks_exact(2);
        if iter.remainder().len() == 1 {
            to_hash.push(iter.remainder()[0].clone());
        }
        for vals in iter.map(|x| [x[0].clone(), x[1].clone()]).collect::<Vec<_>>() {
            to_hash.push(hasher(vals)?);
        }
        cur_hash = to_hash;
        to_hash = vec![];
    }
    Ok(cur_hash[0].clone())
}

pub fn hash_program(program: Vec<Fr>, input: Vec<Fr>) -> Fr {
    let program_hash = hash_values(program);
    let input_hash = hash_values(if input.len() == 0 {
        vec![Fr::from(NIL_HASH_MSG)]
    } else {
        input
    });
    let result = hash_values(vec![program_hash, input_hash]);
    result
}

fn hash_values(message: Vec<Fr>) -> Fr {
    let hasher = |x| -> Result<Fr, Error> {
        let hasher = PrimitiveHash::<Fr, <Fr as Hashable>::SpecType, ConstantLength<2>, 3, 2>::init();
        Ok(hasher.hash(x))
    };
    poseidon_hash(message, hasher).unwrap()
}

pub fn hash_message(
    message: Vec<BFCell>,
    hash_config: HashConfig,
    layouter: &mut impl Layouter<Fr>,
) -> Result<BFCell, Error> {
    let hasher = |x| -> Result<BFCell, Error> {
        let chip = <HashChip as PermuteChip<Fr>>::construct(hash_config.clone());
        let hasher = CircuitHash::<Fr, HashChip, <Fr as Hashable>::SpecType, ConstantLength<2>, 3, 2>::init(
            chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), x)
    };
    poseidon_hash(message, hasher)
}
