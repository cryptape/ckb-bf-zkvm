use crate::code;
use crate::matrix::{InstructionMatrixRow, Matrix, MemoryMatrixRow};
use alloc::vec::Vec;
use core::convert::From;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::{bn256::Fr, FieldExt};
use std::io::{Read, Write};

#[derive(Clone, Debug, Default)]
pub struct Register {
    pub cycle: Fr,
    pub instruction_pointer: Fr,
    pub current_instruction: Fr,
    pub next_instruction: Fr,
    pub memory_pointer: Fr,
    pub memory_value: Fr,
    pub memory_value_inverse: Fr,
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
    pub code: Vec<Fr>,
    pub input: Vec<Fr>,
    pub memory: Vec<Fr>,
    pub register: Register,
    pub matrix: Matrix,
    pub bits: u64,
}

impl Interpreter {
    pub fn new() -> Self {
        Self {
            code: Vec::new(),
            input: Vec::new(),
            memory: vec![Fr::zero()],
            register: Register::default(),
            matrix: Matrix::default(),
            bits: 8,
        }
    }

    pub fn set_code(&mut self, code: Vec<Fr>) {
        self.code = code;
    }

    pub fn set_input(&mut self, input: Vec<Fr>) {
        self.input = input;
    }

    pub fn set_bits(&mut self, bits: u64) {
        self.bits = bits
    }

    pub fn run(&mut self) {
        self.register.current_instruction = self.code[0];
        if self.code.len() == 1 {
            self.register.next_instruction = Fr::zero()
        } else {
            self.register.next_instruction = self.code[1];
        }
        for i in 0..self.code.len() {
            self.matrix.instruction_matrix.push(InstructionMatrixRow {
                instruction_pointer: Fr::from(i as u64),
                current_instruction: self.code[i],
                next_instruction: if i == self.code.len() - 1 {
                    Fr::zero()
                } else {
                    self.code[i + 1]
                },
            });
        }
        loop {
            if self.register.instruction_pointer >= Fr::from(self.code.len() as u64) {
                break;
            }
            self.matrix.processor_matrix.push(self.register.clone());
            self.matrix.instruction_matrix.push(InstructionMatrixRow::from(&self.register));
            self.matrix.memory_matrix.push(MemoryMatrixRow::from(&self.register));
            match self.register.current_instruction.get_lower_128() as u8 {
                code::SHL => {
                    self.register.memory_pointer -= Fr::one();
                    self.register.instruction_pointer += Fr::one();
                }
                code::SHR => {
                    self.register.memory_pointer += Fr::one();
                    if self.register.mp() == self.memory.len() {
                        self.memory.push(Fr::zero())
                    }
                    self.register.instruction_pointer += Fr::one();
                }
                code::ADD => {
                    if self.memory[self.register.mp()] == Fr::from((1 << self.bits) - 1) {
                        self.memory[self.register.mp()] = Fr::zero()
                    } else {
                        self.memory[self.register.mp()] = self.memory[self.register.mp()] + Fr::one();
                    }
                    self.register.instruction_pointer += Fr::one();
                }
                code::SUB => {
                    if self.memory[self.register.mp()] == Fr::zero() {
                        self.memory[self.register.mp()] = Fr::from((1 << self.bits) - 1)
                    } else {
                        self.memory[self.register.mp()] = self.memory[self.register.mp()] - Fr::one();
                    }
                    self.register.instruction_pointer += Fr::one();
                }
                code::GETCHAR => {
                    let val = if self.input.is_empty() {
                        let mut buf: Vec<u8> = vec![0; 1];
                        std::io::stdin().read_exact(&mut buf).unwrap();
                        Fr::from(buf[0] as u64)
                    } else {
                        self.input.remove(0)
                    };
                    self.memory[self.register.mp()] = val;
                    self.matrix.input_matrix.push(val);
                    self.register.instruction_pointer += Fr::one();
                }
                code::PUTCHAR => {
                    std::io::stdout().write_all(&[self.register.memory_value.get_lower_128() as u8]).unwrap();
                    self.matrix.output_matrix.push(self.register.memory_value);
                    self.register.instruction_pointer += Fr::one();
                }
                code::LB => {
                    if self.memory[self.register.mp()] == Fr::zero() {
                        self.register.instruction_pointer = self.code[self.register.ip() + 1];
                    } else {
                        self.register.instruction_pointer += Fr::from(2);
                    }
                }
                code::RB => {
                    if self.memory[self.register.mp()] != Fr::zero() {
                        self.register.instruction_pointer = self.code[self.register.ip() + 1];
                    } else {
                        self.register.instruction_pointer += Fr::from(2);
                    }
                }
                _ => unreachable!(),
            }
            self.register.cycle += Fr::one();
            if self.register.instruction_pointer < Fr::from(self.code.len() as u64) {
                self.register.current_instruction = self.code[self.register.ip()];
            } else {
                self.register.current_instruction = Fr::zero();
            }
            if self.register.instruction_pointer < Fr::from(self.code.len() as u64) - Fr::one() {
                self.register.next_instruction = self.code[self.register.ip() + 1];
            } else {
                self.register.next_instruction = Fr::zero()
            }
            self.register.memory_value = self.memory[self.register.mp()];
            self.register.memory_value_inverse = if self.register.memory_value == Fr::zero() {
                Fr::zero()
            } else {
                self.register.memory_value.invert().unwrap()
            };
        }
        self.matrix.processor_matrix.push(self.register.clone());
        self.matrix.memory_matrix.push(MemoryMatrixRow::from(&self.register));
        self.matrix.instruction_matrix.push(InstructionMatrixRow::from(&self.register));
        self.matrix.instruction_matrix.sort_by_key(|row| row.instruction_pointer);
        self.matrix.memory_matrix.sort_by_key(|row| row.memory_pointer);

        // Append dummy memory rows
        // let mut i = 1;
        // while i < self.matrix.memory_matrix.len() - 1 {
        //     if self.matrix.memory_matrix[i + 1].memory_pointer == self.matrix.memory_matrix[i].memory_pointer
        //         && self.matrix.memory_matrix[i + 1].cycle != self.matrix.memory_matrix[i].cycle + Fr::one()
        //     {
        //         let interleaved_value = MemoryMatrixRow {
        //             cycle: self.matrix.memory_matrix[i].cycle + Fr::one(),
        //             memory_pointer: self.matrix.memory_matrix[i].memory_pointer,
        //             memory_value: self.matrix.memory_matrix[i].memory_value,
        //             interweave_indicator: Fr::one(),
        //         };
        //         self.matrix.memory_matrix.insert(i + 1, interleaved_value);
        //     }
        //     i += 1;
        // }
    }
}
