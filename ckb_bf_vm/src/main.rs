use ckb_bf_vm::code;
use ckb_bf_vm::interpreter;
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() >= 2);
    let mut f = std::fs::File::open(&args[1])?;
    let mut c: Vec<u8> = Vec::new();
    f.read_to_end(&mut c)?;
    let mut i = interpreter::Interpreter::new();
    i.set_code(code::compile(c));
    i.run();
    Ok(())
}
