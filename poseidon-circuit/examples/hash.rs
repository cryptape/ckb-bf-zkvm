use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::{
    bn256::{Bn256, Fr as Fp, G1Affine},
};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{
    KZGCommitmentScheme, ParamsKZG as Params, ParamsVerifierKZG as ParamsVerifier,
};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
};
use poseidon_circuit::poseidon::primitives::{VariableLengthIden3};
use poseidon_circuit::poseidon::Pow5Chip;
use poseidon_circuit::poseidon::*;
use poseidon_circuit::hash::*;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use poseidon::Poseidon;

#[derive(Clone, Debug)]
struct HashCircuitConfig {
    inputs: Column<Advice>,
    expected: Column<Advice>,
    config: Pow5Config<Fp, 3, 2>,
}

#[derive(Default)]
struct HashCircuit {
    inputs: Vec<Fp>,
}

impl HashCircuitConfig {
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let inputs = meta.advice_column();
        let expected = meta.advice_column();
        meta.enable_equality(inputs);
        meta.enable_equality(expected);
        let config = <Pow5Chip<Fp, 3, 2> as PermuteChip<Fp>>::configure(meta);
        Self {
            inputs,
            expected,
            config,
        }
    }
}

impl Circuit<Fp> for HashCircuit {
    type Config = HashCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        HashCircuitConfig::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        // init chip
        let chip = <Pow5Chip<Fp, 3, 2> as PermuteChip<Fp>>::construct(config.config.clone());
        let mut sponge = Sponge::<Fp, _, <Fp as Hashable>::SpecType, _, VariableLengthIden3, 3, 2>::new(
            chip,
            layouter.namespace(|| "hash"),
        )?;
        let messages: Vec<_> = layouter.assign_region(
            || "inputs",
            |mut region| {
                let assign_val = |index| {
                    region.assign_advice(
                        || format!("value_{}", index),
                        config.inputs,
                        index,
                        || Value::known(Fp::from(self.inputs[index])),
                    )
                };
                (0..self.inputs.len()).map(assign_val).collect()
            },
        )?;
        for message in messages {
            sponge.absorb(layouter.namespace(|| "sponge"), PaddedWord::Message(message))?;
        }
        let output = sponge
            .finish_absorbing(layouter.namespace(|| "finish_absorbing"))?
            .squeeze(layouter.namespace(|| "squeeze"))?;

        // check against value
        let hash_msg = Fp::hash_msg(&self.inputs, None);
        println!("output: {:?} hash_msg: {:?}", output.value(), hash_msg);
        let expected = layouter.assign_region(
            || "expected",
            |mut region| region.assign_advice(|| "expected value", config.expected, 0, || Value::known(hash_msg)),
        )?;
        layouter.assign_region(
            || "check",
            |mut region| region.constrain_equal(output.cell(), expected.cell()),
        )?;
        // Try the posedion crate:
        let mut hasher = Poseidon::<Fp, 3, 2>::new(8, 56);
        hasher.update(&self.inputs);
        let r = hasher.squeeze();
        println!("R: {:?}", r);
        Ok(())
    }
}

fn main() {
    let k = 14;

    let params = Params::<Bn256>::unsafe_setup(k);
    let os_rng = ChaCha8Rng::from_seed([101u8; 32]);
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    let len = 2;
    let inputs = (0..len).map(|i| Fp::from(i as u64)).collect();
    let circuit = HashCircuit{inputs};

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied(); // TODO: this cannot pass

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    println!("Creating Proof");
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        os_rng,
        &mut transcript,
    )
    .unwrap();

    let proof_script = transcript.finalize();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_script[..]);
    let verifier_params: ParamsVerifier<Bn256> = params.verifier_params().clone();
    let strategy = SingleStrategy::new(&params);
    let circuit = HashCircuit::default();
    let vk = keygen_vk(&params, &circuit).unwrap();

    println!("Verifiying Proof");
    assert!(
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &verifier_params,
            &vk,
            strategy,
            &[&[]],
            &mut transcript
        )
        .is_ok()
    );
}
