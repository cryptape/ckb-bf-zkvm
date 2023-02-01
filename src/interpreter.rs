use crate::code;
use crate::matrix::{InstructionMatrixRow, Matrix, MemoryMatrixRow};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::{bn256::Fq, FieldExt};
use std::io::{Read, Write};

#[derive(Clone, Debug, Default)]
pub struct Register {
    pub cycle: Fq,
    pub instruction_pointer: Fq,
    pub current_instruction: Fq,
    pub next_instruction: Fq,
    pub memory_pointer: Fq,
    pub memory_value: Fq,
    pub memory_value_inverse: Fq,
}

impl Register {
    fn ip(&self) -> usize {
        self.instruction_pointer.get_lower_128() as usize
    }

    fn mp(&self) -> usize {
        self.memory_pointer.get_lower_128() as usize
    }
}

pub struct Interpreter {
    pub code: Vec<Fq>,
    pub input: Vec<Fq>,
    pub memory: Vec<Fq>,
    pub register: Register,
    pub matrix: Matrix,
}

impl Interpreter {
    pub fn new() -> Self {
        Self {
            code: Vec::new(),
            input: Vec::new(),
            memory: vec![Fq::zero()],
            register: Register::default(),
            matrix: Matrix::default(),
        }
    }

    pub fn set_code(&mut self, code: Vec<Fq>) {
        self.code = code;
    }

    pub fn set_input(&mut self, input: Vec<Fq>) {
        self.input = input;
    }

    pub fn run(&mut self) {
        self.register.current_instruction = self.code[0];
        if self.code.len() == 1 {
            self.register.next_instruction = Fq::zero()
        } else {
            self.register.next_instruction = self.code[1];
        }
        for i in 0..self.code.len() {
            self.matrix.instruction_matrix.push(InstructionMatrixRow {
                instruction_pointer: Fq::from(i as u64),
                current_instruction: self.code[i],
                next_instruction: if i == self.code.len() - 1 {
                    Fq::zero()
                } else {
                    self.code[i + 1]
                },
            });
        }
        loop {
            if self.register.instruction_pointer >= Fq::from(self.code.len() as u64) {
                break;
            }
            self.matrix.processor_matrix.push(self.register.clone());
            self.matrix.instruction_matrix.push(InstructionMatrixRow::from(&self.register));
            self.matrix.memory_matrix.push(MemoryMatrixRow::from(&self.register));
            match self.register.current_instruction.get_lower_128() as u8 {
                code::SHL => {
                    self.register.memory_pointer -= Fq::one();
                    self.register.instruction_pointer += Fq::one();
                }
                code::SHR => {
                    self.register.memory_pointer += Fq::one();
                    if self.register.mp() == self.memory.len() {
                        self.memory.push(Fq::zero())
                    }
                    self.register.instruction_pointer += Fq::one();
                }
                code::ADD => {
                    self.memory[self.register.mp()] += Fq::one();
                    self.register.instruction_pointer += Fq::one();
                }
                code::SUB => {
                    self.memory[self.register.mp()] -= Fq::one();
                    self.register.instruction_pointer += Fq::one();
                }
                code::GETCHAR => {
                    let val = if self.input.is_empty() {
                        let mut buf: Vec<u8> = vec![0; 1];
                        std::io::stdin().read_exact(&mut buf).unwrap();
                        Fq::from(buf[0] as u64)
                    } else {
                        self.input.remove(0)
                    };
                    self.memory[self.register.mp()] = val;
                    self.matrix.input_matrix.push(val);
                    self.register.instruction_pointer += Fq::one();
                }
                code::PUTCHAR => {
                    std::io::stdout().write_all(&[self.register.memory_value.get_lower_128() as u8]).unwrap();
                    self.matrix.output_matrix.push(self.register.memory_value);
                    self.register.instruction_pointer += Fq::one();
                }
                code::LB => {
                    if self.memory[self.register.mp()] == Fq::zero() {
                        self.register.instruction_pointer = self.code[self.register.ip() + 1];
                    } else {
                        self.register.instruction_pointer += Fq::from(2);
                    }
                }
                code::RB => {
                    if self.memory[self.register.mp()] != Fq::zero() {
                        self.register.instruction_pointer = self.code[self.register.ip() + 1];
                    } else {
                        self.register.instruction_pointer += Fq::from(2);
                    }
                }
                _ => unreachable!(),
            }
            self.register.cycle += Fq::one();
            if self.register.instruction_pointer < Fq::from(self.code.len() as u64) {
                self.register.current_instruction = self.code[self.register.ip()];
            } else {
                self.register.current_instruction = Fq::zero();
            }
            if self.register.instruction_pointer < Fq::from(self.code.len() as u64) - Fq::one() {
                self.register.next_instruction = self.code[self.register.ip() + 1];
            } else {
                self.register.next_instruction = Fq::zero()
            }
            self.register.memory_value = self.memory[self.register.mp()];
            self.register.memory_value_inverse = if self.register.memory_value == Fq::zero() {
                Fq::zero()
            } else {
                self.register.memory_value.invert().unwrap()
            };
        }
        self.matrix.processor_matrix.push(self.register.clone());
        self.matrix.instruction_matrix.push(InstructionMatrixRow::from(&self.register));
        self.matrix.instruction_matrix.sort_by_key(|row| row.instruction_pointer);
        self.matrix.memory_matrix.sort_by_key(|row| row.memory_pointer);

        // Append dummy memory rows
        // let mut i = 1;
        // while i < self.matrix.memory_matrix.len() - 1 {
        //     if self.matrix.memory_matrix[i + 1].memory_pointer == self.matrix.memory_matrix[i].memory_pointer
        //         && self.matrix.memory_matrix[i + 1].cycle != self.matrix.memory_matrix[i].cycle + Fq::one()
        //     {
        //         let interleaved_value = MemoryMatrixRow {
        //             cycle: self.matrix.memory_matrix[i].cycle + Fq::one(),
        //             memory_pointer: self.matrix.memory_matrix[i].memory_pointer,
        //             memory_value: self.matrix.memory_matrix[i].memory_value,
        //             interweave_indicator: Fq::one(),
        //         };
        //         self.matrix.memory_matrix.insert(i + 1, interleaved_value);
        //     }
        //     i += 1;
        // }

    }
}
