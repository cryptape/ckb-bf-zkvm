use std::{fs::File, io::Write};

pub mod ckb_tx;

pub fn write_selectors(file_name: String, selectors: &Vec<Vec<bool>>) {    
    let mut writer = File::create(file_name).expect("File::create");
    for selector in selectors {
        for bits in selector.chunks(8) {
            writer.write(&[halo2_proofs::helpers::pack(bits)]).expect("write");
        }
    }
}
