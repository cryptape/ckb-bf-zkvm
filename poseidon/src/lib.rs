//! Poseidon hashing implemention with variable lenght input setting. This crate
//! also exposes constant parameters for circuit implementations

#![cfg_attr(not(test), no_std)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

extern crate alloc;

mod grain;
mod matrix;
mod permutation;
mod poseidon;
mod spec;

pub use crate::poseidon::Poseidon;
pub use crate::spec::{MDSMatrices, MDSMatrix, SparseMDSMatrix, Spec, State};
