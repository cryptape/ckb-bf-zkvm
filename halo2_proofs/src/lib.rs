#![allow(dead_code)]
#![allow(unused_variables)]

//! # halo2_proofs
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), no_std)]
// Build without warnings on stable 1.51 and later.
#![allow(unknown_lints)]
// Disable old lint warnings until our MSRV is at least 1.51.
#![allow(renamed_and_removed_lints)]
// Use the old lint name to build without warnings until our MSRV is at least 1.51.
#![allow(clippy::unknown_clippy_lints)]
// The actual lints we want to disable.
#![allow(
    clippy::op_ref,
    clippy::assign_op_pattern,
    clippy::too_many_arguments,
    clippy::suspicious_arithmetic_impl,
    clippy::many_single_char_names,
    clippy::same_item_push,
    clippy::upper_case_acronyms
)]
#![deny(broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(unsafe_code)]
// Remove this once we update pasta_curves
#![allow(unused_imports)]
#![allow(clippy::derive_partial_eq_without_eq)]

#[macro_export]
macro_rules! maybe_eprintln {
    ( $( $x:expr ),* ) => {{}};
}

#[macro_export]
macro_rules! maybe_eprint {
    ( $( $x:expr ),* ) => {{}};
}

extern crate alloc;
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};

pub mod collections {
    pub use alloc::collections::{BTreeMap, BTreeSet};
    pub use hashbrown::{HashMap, HashSet};
}
pub use halo2curves;
pub use halo2curves::io;

pub mod arithmetic;
pub mod circuit;
pub mod plonk;
pub mod poly;
pub mod transcript;

pub mod dev;
mod helpers;
pub use helpers::SerdeFormat;

pub(crate) fn get_rng() -> rand_chacha::ChaCha20Rng {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    <ChaCha20Rng as SeedableRng>::seed_from_u64(42)
}
