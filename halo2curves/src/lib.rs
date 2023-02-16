#![cfg_attr(not(test), no_std)]
#![cfg_attr(feature = "asm", feature(asm_const))]

extern crate alloc;

mod arithmetic;

pub mod bn256;
pub mod io;
pub mod pairing;
pub mod pasta;
pub mod secp256k1;
pub mod serde;

#[macro_use]
mod derive;

pub use arithmetic::CurveAffineExt;
pub use pasta_curves::arithmetic::{Coordinates, CurveAffine, CurveExt, FieldExt, Group};

pub extern crate group;

#[cfg(test)]
pub mod tests;

#[cfg(all(feature = "prefetch", target_arch = "x86_64"))]
#[inline(always)]
pub fn prefetch<T>(data: &[T], offset: usize) {
    use core::arch::x86_64::_mm_prefetch;
    unsafe {
        _mm_prefetch(
            data.as_ptr().offset(offset as isize) as *const i8,
            core::arch::x86_64::_MM_HINT_T0,
        );
    }
}
