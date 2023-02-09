use halo2_proofs::halo2curves::bn256::Fr;

pub const SHL: u8 = 0x3C;
pub const SHR: u8 = 0x3E;
pub const ADD: u8 = 0x2B;
pub const SUB: u8 = 0x2D;
pub const GETCHAR: u8 = 0x2C;
pub const PUTCHAR: u8 = 0x2E;
pub const LB: u8 = 0x5B;
pub const RB: u8 = 0x5D;

pub fn easygen(code: &str) -> Vec<Fr> {
    code.as_bytes().iter().map(|&x| Fr::from(x as u64)).collect()
}

pub fn compile(code: Vec<u8>) -> Vec<Fr> {
    let filter = vec![SHL, SHR, ADD, SUB, GETCHAR, PUTCHAR, LB, RB];
    let mut instrs = Vec::<Fr>::new();
    let mut jstack = Vec::<usize>::new();
    for i in code {
        if !filter.contains(&i) {
            continue;
        }
        instrs.push(Fr::from(i as u64));
        if i == LB {
            instrs.push(Fr::zero());
            jstack.push(instrs.len() - 1);
        }
        if i == RB {
            instrs.push(Fr::from(*jstack.last().unwrap() as u64 + 1));
            instrs[*jstack.last().unwrap()] = Fr::from(instrs.len() as u64);
            jstack.pop();
        }
    }
    return instrs;
}
