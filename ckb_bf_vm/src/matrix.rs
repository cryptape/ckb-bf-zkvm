use crate::interpreter::Register;
use halo2_proofs::halo2curves::bn256::Fq;

#[derive(Default)]
pub struct Matrix {
    pub processor_matrix: Vec<Register>,
    pub instruction_matrix: Vec<InstructionMatrixRow>,
    pub memory_matrix: Vec<MemoryMatrixRow>,
    pub input_matrix: Vec<Fq>,
    pub output_matrix: Vec<Fq>,
}

pub struct InstructionMatrixRow {
    pub instruction_pointer: Fq,
    pub current_instruction: Fq,
    pub next_instruction: Fq,
}

impl From<&Register> for InstructionMatrixRow {
    fn from(r: &Register) -> Self {
        Self {
            instruction_pointer: r.instruction_pointer,
            current_instruction: r.current_instruction,
            next_instruction: r.next_instruction,
        }
    }
}

pub struct MemoryMatrixRow {
    pub cycle: Fq,
    pub memory_pointer: Fq,
    pub memory_value: Fq,
    pub interweave_indicator: Fq,
}

impl From<&Register> for MemoryMatrixRow {
    fn from(r: &Register) -> Self {
        Self {
            cycle: r.cycle,
            memory_pointer: r.memory_pointer,
            memory_value: r.memory_value,
            interweave_indicator: Fq::zero(),
        }
    }
}
