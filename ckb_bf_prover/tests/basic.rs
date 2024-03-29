use ckb_bf_base::main_config::MyCircuit;
use ckb_bf_base::utils::DOMAIN;
use ckb_bf_vm::code;
use ckb_bf_vm::interpreter::Interpreter;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;

#[test]
fn test_prove_hello_world() {
    let mut program = code::compile(include_bytes!("../../res/hello_world.bf").to_vec());
    let mut vm = Interpreter::new();
    vm.set_code(program.clone());
    vm.run();
    program.insert(0, Fr::from(program.len() as u64));
    let instances = vec![program, vec![Fr::zero()]];

    let circuit = MyCircuit::<Fr, { DOMAIN }>::new(vm.matrix);
    let prover = MockProver::run(11, &circuit, instances).unwrap();
    prover.assert_satisfied();
}

#[test]
fn test_prove_neptune() {
    let mut program = code::compile(include_bytes!("../../res/neptune_tutorial.bf").to_vec());
    let mut input = code::easygen("a");
    let mut vm = Interpreter::new();
    vm.set_code(program.clone());
    vm.set_input(input.clone());
    vm.run();

    program.insert(0, Fr::from(program.len() as u64));
    input.insert(0, Fr::from(input.len() as u64));
    let instances = vec![program, input];

    let circuit = MyCircuit::<Fr, { DOMAIN }>::new(vm.matrix);
    let prover = MockProver::run(10, &circuit, instances).unwrap();
    prover.assert_satisfied();
}

#[test]
fn test_prove_wrapping() {
    let mut program = code::compile(include_bytes!("../../res/wrapping_op.bf").to_vec());
    let mut vm = Interpreter::new();
    vm.set_code(program.clone());
    vm.run();

    program.insert(0, Fr::from(program.len() as u64));
    let instances = vec![program, vec![Fr::zero()]];

    let circuit = MyCircuit::<Fr, { DOMAIN }>::new(vm.matrix);
    let prover = MockProver::run(10, &circuit, instances).unwrap();
    prover.assert_satisfied();
}

// #[test]
// Still too slow :(
// fn test_prove_echo() {
//     let program = code::compile(include_bytes!("../../res/echo.bf").to_vec());
//     let mut vm = Interpreter::new();
//     vm.set_code(program);
//     // vm.set_input(code::easygen("The quick brown fox jumps over the lazy dog"));
//     vm.set_input(code::easygen("a"));
//     vm.run();

//     let circuit = MyCircuit::<Fr, { DOMAIN }>::new(vm.matrix);
//     let prover = MockProver::run(10, &circuit, vec![]).unwrap();
//     prover.assert_satisfied();
// }

// This takes a long time
// #[test]
// fn test_prove_pearson() {
//     let program = code::compile(include_bytes!("../../res/pearson.bf").to_vec());
//     let mut vm = Interpreter::new();
//     vm.set_code(program);
//     vm.set_input(code::easygen("a"));
//     vm.run();

//     let circuit = MyCircuit::<Fr, {DOMAIN}>::new(vm.matrix);
//     let prover = MockProver::run(21, &circuit, vec![]).unwrap();
//     prover.assert_satisfied();
// }
