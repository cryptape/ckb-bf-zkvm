#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

use alloc::format;
use ckb_std::default_alloc;
use ckb_std::syscalls::debug;
use halo2curves::bn256::{G1Affine, G2Affine, G1, G2};
use halo2curves::group::Group;
use halo2curves::pairing::PairingCurveAffine;
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;

ckb_std::entry!(program_entry);
default_alloc!();

pub fn program_entry() -> i8 {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
    ]);

    let a = G1Affine::from(G1::random(&mut rng));
    let b = G2Affine::from(G2::random(&mut rng));

    if a.pairing_with(&b) == b.pairing_with(&a) {
        debug(format!("Pairing succeeded"));
    } else {
        debug(format!("Pairing failed"));
    };
    return 0;
}
