#![no_std]

#[macro_use]
extern crate alloc;

pub mod input_table;
pub mod instruction_table;
pub mod main_config;
pub mod memory_table;
pub mod output_table;
pub mod processor_table;
pub mod range_table;
pub mod program_table;
pub mod utils;
pub mod poseidon_hash;

pub const GOD_PRIVATE_KEY: u128 = 42;
pub const SHRINK_K: u32 = 1;
