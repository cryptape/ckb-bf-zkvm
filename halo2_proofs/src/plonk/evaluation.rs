use crate::collections::BTreeMap;
use crate::plonk::lookup::prover::Committed;
use crate::plonk::permutation::Argument;
use crate::plonk::{lookup, permutation, AdviceQuery, Any, FixedQuery, InstanceQuery, ProvingKey};
use crate::poly::Basis;
use crate::{
    arithmetic::{eval_polynomial, parallelize, CurveAffine, FieldExt},
    format,
    poly::{
        commitment::Params, Coeff, EvaluationDomain, ExtendedLagrangeCoeff, LagrangeCoeff,
        Polynomial, ProverQuery, Rotation,
    },
    transcript::{EncodedChallenge, TranscriptWrite},
    vec, String, Vec,
};
use core::convert::TryInto;
use core::num::ParseIntError;
use core::slice;
use core::{
    iter,
    ops::{Index, Mul, MulAssign},
};
use group::prime::PrimeCurve;
use group::{
    ff::{BatchInvert, Field},
    Curve,
};

use super::{ConstraintSystem, Expression};

/// Return the index in the polynomial of size `isize` after rotation `rot`.
fn get_rotation_idx(idx: usize, rot: i32, rot_scale: i32, isize: i32) -> usize {
    (((idx as i32) + (rot * rot_scale)).rem_euclid(isize)) as usize
}

/// Value used in a calculation
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum ValueSource {
    /// This is a constant value
    Constant(usize),
    /// This is an intermediate value
    Intermediate(usize),
    /// This is a fixed column
    Fixed(usize, usize),
    /// This is an advice (witness) column
    Advice(usize, usize),
    /// This is an instance (external) column
    Instance(usize, usize),
    /// This is a challenge
    Challenge(usize),
    /// beta
    Beta(),
    /// gamma
    Gamma(),
    /// theta
    Theta(),
    /// y
    Y(),
    /// Previous value
    PreviousValue(),
}

impl Default for ValueSource {
    fn default() -> Self {
        ValueSource::Constant(0)
    }
}

impl ValueSource {
    /// Get the value for this source
    pub fn get<F: Field, B: Basis>(
        &self,
        rotations: &[usize],
        constants: &[F],
        intermediates: &[F],
        fixed_values: &[Polynomial<F, B>],
        advice_values: &[Polynomial<F, B>],
        instance_values: &[Polynomial<F, B>],
        challenges: &[F],
        beta: &F,
        gamma: &F,
        theta: &F,
        y: &F,
        previous_value: &F,
    ) -> F {
        match self {
            ValueSource::Constant(idx) => constants[*idx],
            ValueSource::Intermediate(idx) => intermediates[*idx],
            ValueSource::Fixed(column_index, rotation) => {
                fixed_values[*column_index][rotations[*rotation]]
            }
            ValueSource::Advice(column_index, rotation) => {
                advice_values[*column_index][rotations[*rotation]]
            }
            ValueSource::Instance(column_index, rotation) => {
                instance_values[*column_index][rotations[*rotation]]
            }
            ValueSource::Challenge(index) => challenges[*index],
            ValueSource::Beta() => *beta,
            ValueSource::Gamma() => *gamma,
            ValueSource::Theta() => *theta,
            ValueSource::Y() => *y,
            ValueSource::PreviousValue() => *previous_value,
        }
    }
}

/// Calculation
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Calculation {
    /// This is an addition
    Add(ValueSource, ValueSource),
    /// This is a subtraction
    Sub(ValueSource, ValueSource),
    /// This is a product
    Mul(ValueSource, ValueSource),
    /// This is a square
    Square(ValueSource),
    /// This is a double
    Double(ValueSource),
    /// This is a negation
    Negate(ValueSource),
    /// This is Horner's rule: `val = a; val = val * c + b[]`
    Horner(ValueSource, Vec<ValueSource>, ValueSource),
    /// This is a simple assignment
    Store(ValueSource),
}

impl Calculation {
    /// Get the resulting value of this calculation
    pub fn evaluate<F: Field, B: Basis>(
        &self,
        rotations: &[usize],
        constants: &[F],
        intermediates: &[F],
        fixed_values: &[Polynomial<F, B>],
        advice_values: &[Polynomial<F, B>],
        instance_values: &[Polynomial<F, B>],
        challenges: &[F],
        beta: &F,
        gamma: &F,
        theta: &F,
        y: &F,
        previous_value: &F,
    ) -> F {
        let get_value = |value: &ValueSource| {
            value.get(
                rotations,
                constants,
                intermediates,
                fixed_values,
                advice_values,
                instance_values,
                challenges,
                beta,
                gamma,
                theta,
                y,
                previous_value,
            )
        };
        match self {
            Calculation::Add(a, b) => get_value(a) + get_value(b),
            Calculation::Sub(a, b) => get_value(a) - get_value(b),
            Calculation::Mul(a, b) => get_value(a) * get_value(b),
            Calculation::Square(v) => get_value(v).square(),
            Calculation::Double(v) => get_value(v).double(),
            Calculation::Negate(v) => -get_value(v),
            Calculation::Horner(start_value, parts, factor) => {
                let factor = get_value(factor);
                let mut value = get_value(start_value);
                for part in parts.iter() {
                    value = value * factor + get_value(part);
                }
                value
            }
            Calculation::Store(v) => get_value(v),
        }
    }
}

/// Evaluator
#[derive(Clone, Default, Debug)]
pub struct Evaluator<C: CurveAffine> {
    ///  Custom gates evalution
    pub custom_gates: GraphEvaluator<C>,
    ///  Lookups evalution
    pub lookups: Vec<GraphEvaluator<C>>,
}

/// GraphEvaluator
#[derive(Clone, Debug)]
pub struct GraphEvaluator<C: CurveAffine> {
    /// Constants
    pub constants: Vec<C::ScalarExt>,
    /// Rotations
    pub rotations: Vec<i32>,
    /// Calculations
    pub calculations: Vec<CalculationInfo>,
    /// Number of intermediates
    pub num_intermediates: usize,
}

/// EvaluationData
#[derive(Default, Debug)]
pub struct EvaluationData<C: CurveAffine> {
    /// Intermediates
    pub intermediates: Vec<C::ScalarExt>,
    /// Rotations
    pub rotations: Vec<usize>,
}

/// CaluclationInfo
#[derive(Clone, Debug)]
pub struct CalculationInfo {
    /// Calculation
    pub calculation: Calculation,
    /// Target
    pub target: usize,
}

impl<C: CurveAffine> Evaluator<C> {
    /// Creates a new evaluation structure
    pub fn new(cs: &ConstraintSystem<C::ScalarExt>) -> Self {
        let mut ev = Evaluator::default();

        // Custom gates
        let mut parts = Vec::new();
        for gate in cs.gates.iter() {
            parts.extend(
                gate.polynomials()
                    .iter()
                    .map(|poly| ev.custom_gates.add_expression(poly)),
            );
        }
        ev.custom_gates.add_calculation(Calculation::Horner(
            ValueSource::PreviousValue(),
            parts,
            ValueSource::Y(),
        ));

        // Lookups
        for lookup in cs.lookups.iter() {
            let mut graph = GraphEvaluator::default();

            let mut evaluate_lc = |expressions: &Vec<Expression<_>>| {
                let parts = expressions
                    .iter()
                    .map(|expr| graph.add_expression(expr))
                    .collect();
                graph.add_calculation(Calculation::Horner(
                    ValueSource::Constant(0),
                    parts,
                    ValueSource::Theta(),
                ))
            };

            // Input coset
            let compressed_input_coset = evaluate_lc(&lookup.input_expressions);
            // table coset
            let compressed_table_coset = evaluate_lc(&lookup.table_expressions);
            // z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
            let right_gamma = graph.add_calculation(Calculation::Add(
                compressed_table_coset,
                ValueSource::Gamma(),
            ));
            let lc = graph.add_calculation(Calculation::Add(
                compressed_input_coset,
                ValueSource::Beta(),
            ));
            graph.add_calculation(Calculation::Mul(lc, right_gamma));

            ev.lookups.push(graph);
        }

        ev
    }

    /// Evaluate h poly
    pub(in crate::plonk) fn evaluate_h(
        &self,
        pk: &ProvingKey<C>,
        advice_polys: &[&[Polynomial<C::ScalarExt, Coeff>]],
        instance_polys: &[&[Polynomial<C::ScalarExt, Coeff>]],
        challenges: &[C::ScalarExt],
        y: C::ScalarExt,
        beta: C::ScalarExt,
        gamma: C::ScalarExt,
        theta: C::ScalarExt,
        lookups: &[Vec<lookup::prover::Committed<C>>],
        permutations: &[permutation::prover::Committed<C>],
    ) -> Polynomial<C::ScalarExt, ExtendedLagrangeCoeff> {
        let domain = &pk.vk.domain;
        let size = 1 << domain.k() as usize;
        let rot_scale = 1;
        let extended_omega = domain.get_extended_omega();
        let omega = domain.get_omega();
        let isize = size as i32;
        let one = C::ScalarExt::one();
        let p = &pk.vk.cs.permutation;
        let num_parts = domain.extended_len() >> domain.k();

        // Calculate the quotient polynomial for each part
        let mut current_extended_omega = one;
        let value_parts: Vec<Polynomial<C::ScalarExt, LagrangeCoeff>> = (0..num_parts)
            .map(|_| {
                let fixed: Vec<Polynomial<C::ScalarExt, LagrangeCoeff>> = pk
                    .fixed_polys
                    .iter()
                    .map(|p| domain.coeff_to_extended_part(p.clone(), current_extended_omega))
                    .collect();
                let fixed = &fixed[..];
                let l0 = domain.coeff_to_extended_part(pk.l0.clone(), current_extended_omega);
                let l_last =
                    domain.coeff_to_extended_part(pk.l_last.clone(), current_extended_omega);
                let l_active_row =
                    domain.coeff_to_extended_part(pk.l_active_row.clone(), current_extended_omega);

                // Calculate the advice and instance cosets
                let advice: Vec<Vec<Polynomial<C::Scalar, LagrangeCoeff>>> = advice_polys
                    .iter()
                    .map(|advice_polys| {
                        advice_polys
                            .iter()
                            .map(|poly| {
                                domain.coeff_to_extended_part(poly.clone(), current_extended_omega)
                            })
                            .collect()
                    })
                    .collect();
                let instance: Vec<Vec<Polynomial<C::Scalar, LagrangeCoeff>>> = instance_polys
                    .iter()
                    .map(|instance_polys| {
                        instance_polys
                            .iter()
                            .map(|poly| {
                                domain.coeff_to_extended_part(poly.clone(), current_extended_omega)
                            })
                            .collect()
                    })
                    .collect();

                let mut values = domain.empty_lagrange();

                // Core expression evaluations
                for (((advice, instance), lookups), permutation) in advice
                    .iter()
                    .zip(instance.iter())
                    .zip(lookups.iter())
                    .zip(permutations.iter())
                {
                    // Custom gates
                    let chunk_size = 1;
                    for (thread_idx, values) in values.chunks_mut(chunk_size).enumerate() {
                        let start = thread_idx * chunk_size;
                        let mut eval_data = self.custom_gates.instance();
                        for (i, value) in values.iter_mut().enumerate() {
                            let idx = start + i;
                            *value = self.custom_gates.evaluate(
                                &mut eval_data,
                                fixed,
                                advice,
                                instance,
                                challenges,
                                &beta,
                                &gamma,
                                &theta,
                                &y,
                                value,
                                idx,
                                rot_scale,
                                isize,
                            );
                        }
                    }

                    // Permutations
                    let sets = &permutation.sets;
                    if !sets.is_empty() {
                        let blinding_factors = pk.vk.cs.blinding_factors();
                        let last_rotation = Rotation(-((blinding_factors + 1) as i32));
                        let chunk_len = pk.vk.cs.degree() - 2;
                        let delta_start = beta * &C::Scalar::ZETA;

                        let permutation_product_cosets: Vec<
                            Polynomial<C::ScalarExt, LagrangeCoeff>,
                        > = sets
                            .iter()
                            .map(|set| {
                                domain.coeff_to_extended_part(
                                    set.permutation_product_poly.clone(),
                                    current_extended_omega,
                                )
                            })
                            .collect();
                        let permutation_cosets: Vec<Polynomial<C::ScalarExt, LagrangeCoeff>> = pk
                            .permutation
                            .polys
                            .iter()
                            .map(|p| {
                                domain.coeff_to_extended_part(p.clone(), current_extended_omega)
                            })
                            .collect();

                        let first_set_permutation_product_coset =
                            permutation_product_cosets.first().unwrap();
                        let last_set_permutation_product_coset =
                            permutation_product_cosets.last().unwrap();

                        // Permutation constraints
                        parallelize(&mut values, |values, start| {
                            let mut beta_term = current_extended_omega
                                * omega.pow_vartime(&[start as u64, 0, 0, 0]);
                            for (i, value) in values.iter_mut().enumerate() {
                                let idx = start + i;
                                let r_next = get_rotation_idx(idx, 1, rot_scale, isize);
                                let r_last =
                                    get_rotation_idx(idx, last_rotation.0, rot_scale, isize);

                                // Enforce only for the first set.
                                // l_0(X) * (1 - z_0(X)) = 0
                                *value = *value * y
                                    + ((one - first_set_permutation_product_coset[idx]) * l0[idx]);
                                // Enforce only for the last set.
                                // l_last(X) * (z_l(X)^2 - z_l(X)) = 0
                                *value = *value * y
                                    + ((last_set_permutation_product_coset[idx]
                                        * last_set_permutation_product_coset[idx]
                                        - last_set_permutation_product_coset[idx])
                                        * l_last[idx]);
                                // Except for the first set, enforce.
                                // l_0(X) * (z_i(X) - z_{i-1}(\omega^(last) X)) = 0
                                for (set_idx, permutation_product_coset) in
                                    permutation_product_cosets.iter().enumerate()
                                {
                                    if set_idx != 0 {
                                        *value = *value * y
                                            + ((permutation_product_coset[idx]
                                                - permutation_product_cosets[set_idx - 1][r_last])
                                                * l0[idx]);
                                    }
                                }
                                // And for all the sets we enforce:
                                // (1 - (l_last(X) + l_blind(X))) * (
                                //   z_i(\omega X) \prod_j (p(X) + \beta s_j(X) + \gamma)
                                // - z_i(X) \prod_j (p(X) + \delta^j \beta X + \gamma)
                                // )
                                let mut current_delta = delta_start * beta_term;
                                for (
                                    (columns, permutation_product_coset),
                                    permutation_coset_chunk,
                                ) in p
                                    .columns
                                    .chunks(chunk_len)
                                    .zip(permutation_product_cosets.iter())
                                    .zip(permutation_cosets.chunks(chunk_len))
                                {
                                    let mut left = permutation_product_coset[r_next];
                                    for (values, permutation) in columns
                                        .iter()
                                        .map(|&column| match column.column_type() {
                                            Any::Advice(_) => &advice[column.index()],
                                            Any::Fixed => &fixed[column.index()],
                                            Any::Instance => &instance[column.index()],
                                        })
                                        .zip(permutation_coset_chunk.iter())
                                    {
                                        left *= values[idx] + beta * permutation[idx] + gamma;
                                    }

                                    let mut right = permutation_product_coset[idx];
                                    for values in
                                        columns.iter().map(|&column| match column.column_type() {
                                            Any::Advice(_) => &advice[column.index()],
                                            Any::Fixed => &fixed[column.index()],
                                            Any::Instance => &instance[column.index()],
                                        })
                                    {
                                        right *= values[idx] + current_delta + gamma;
                                        current_delta *= &C::Scalar::DELTA;
                                    }

                                    *value = *value * y + ((left - right) * l_active_row[idx]);
                                }
                                beta_term *= &omega;
                            }
                        });
                    }

                    // Lookups
                    for (n, lookup) in lookups.iter().enumerate() {
                        // Polynomials required for this lookup.
                        // Calculated here so these only have to be kept in memory for the short time
                        // they are actually needed.
                        let product_coset = pk.vk.domain.coeff_to_extended_part(
                            lookup.product_poly.clone(),
                            current_extended_omega,
                        );
                        let permuted_input_coset = pk.vk.domain.coeff_to_extended_part(
                            lookup.permuted_input_poly.clone(),
                            current_extended_omega,
                        );
                        let permuted_table_coset = pk.vk.domain.coeff_to_extended_part(
                            lookup.permuted_table_poly.clone(),
                            current_extended_omega,
                        );

                        // Lookup constraints
                        parallelize(&mut values, |values, start| {
                            let lookup_evaluator = &self.lookups[n];
                            let mut eval_data = lookup_evaluator.instance();
                            for (i, value) in values.iter_mut().enumerate() {
                                let idx = start + i;

                                let table_value = lookup_evaluator.evaluate(
                                    &mut eval_data,
                                    fixed,
                                    advice,
                                    instance,
                                    challenges,
                                    &beta,
                                    &gamma,
                                    &theta,
                                    &y,
                                    &C::ScalarExt::zero(),
                                    idx,
                                    rot_scale,
                                    isize,
                                );

                                let r_next = get_rotation_idx(idx, 1, rot_scale, isize);
                                let r_prev = get_rotation_idx(idx, -1, rot_scale, isize);

                                let a_minus_s =
                                    permuted_input_coset[idx] - permuted_table_coset[idx];
                                // l_0(X) * (1 - z(X)) = 0
                                *value = *value * y + ((one - product_coset[idx]) * l0[idx]);
                                // l_last(X) * (z(X)^2 - z(X)) = 0
                                *value = *value * y
                                    + ((product_coset[idx] * product_coset[idx]
                                        - product_coset[idx])
                                        * l_last[idx]);
                                // (1 - (l_last(X) + l_blind(X))) * (
                                //   z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
                                //   - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta)
                                //          (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
                                // ) = 0
                                *value = *value * y
                                    + ((product_coset[r_next]
                                        * (permuted_input_coset[idx] + beta)
                                        * (permuted_table_coset[idx] + gamma)
                                        - product_coset[idx] * table_value)
                                        * l_active_row[idx]);
                                // Check that the first values in the permuted input expression and permuted
                                // fixed expression are the same.
                                // l_0(X) * (a'(X) - s'(X)) = 0
                                *value = *value * y + (a_minus_s * l0[idx]);
                                // Check that each value in the permuted lookup input expression is either
                                // equal to the value above it, or the value at the same index in the
                                // permuted table expression.
                                // (1 - (l_last + l_blind)) * (a′(X) − s′(X))⋅(a′(X) − a′(\omega^{-1} X)) = 0
                                *value = *value * y
                                    + (a_minus_s
                                        * (permuted_input_coset[idx]
                                            - permuted_input_coset[r_prev])
                                        * l_active_row[idx]);
                            }
                        });
                    }
                }
                current_extended_omega *= extended_omega;
                values
            })
            .collect();

        domain.extended_from_lagrange_vec(value_parts)
    }
}

impl<C: CurveAffine> Default for GraphEvaluator<C> {
    fn default() -> Self {
        Self {
            // Fixed positions to allow easy access
            constants: vec![
                C::ScalarExt::zero(),
                C::ScalarExt::one(),
                C::ScalarExt::from(2u64),
            ],
            rotations: Vec::new(),
            calculations: Vec::new(),
            num_intermediates: 0,
        }
    }
}

impl<C: CurveAffine> GraphEvaluator<C> {
    /// Adds a rotation
    fn add_rotation(&mut self, rotation: &Rotation) -> usize {
        let position = self.rotations.iter().position(|&c| c == rotation.0);
        match position {
            Some(pos) => pos,
            None => {
                self.rotations.push(rotation.0);
                self.rotations.len() - 1
            }
        }
    }

    /// Adds a constant
    fn add_constant(&mut self, constant: &C::ScalarExt) -> ValueSource {
        let position = self.constants.iter().position(|&c| c == *constant);
        ValueSource::Constant(match position {
            Some(pos) => pos,
            None => {
                self.constants.push(*constant);
                self.constants.len() - 1
            }
        })
    }

    /// Adds a calculation.
    /// Currently does the simplest thing possible: just stores the
    /// resulting value so the result can be reused  when that calculation
    /// is done multiple times.
    fn add_calculation(&mut self, calculation: Calculation) -> ValueSource {
        let existing_calculation = self
            .calculations
            .iter()
            .find(|c| c.calculation == calculation);
        match existing_calculation {
            Some(existing_calculation) => ValueSource::Intermediate(existing_calculation.target),
            None => {
                let target = self.num_intermediates;
                self.calculations.push(CalculationInfo {
                    calculation,
                    target,
                });
                self.num_intermediates += 1;
                ValueSource::Intermediate(target)
            }
        }
    }

    /// Generates an optimized evaluation for the expression
    fn add_expression(&mut self, expr: &Expression<C::ScalarExt>) -> ValueSource {
        match expr {
            Expression::Constant(scalar) => self.add_constant(scalar),
            Expression::Selector(_selector) => unreachable!(),
            Expression::Fixed(query) => {
                let rot_idx = self.add_rotation(&query.rotation);
                self.add_calculation(Calculation::Store(ValueSource::Fixed(
                    query.column_index,
                    rot_idx,
                )))
            }
            Expression::Advice(query) => {
                let rot_idx = self.add_rotation(&query.rotation);
                self.add_calculation(Calculation::Store(ValueSource::Advice(
                    query.column_index,
                    rot_idx,
                )))
            }
            Expression::Instance(query) => {
                let rot_idx = self.add_rotation(&query.rotation);
                self.add_calculation(Calculation::Store(ValueSource::Instance(
                    query.column_index,
                    rot_idx,
                )))
            }
            Expression::Challenge(challenge) => self.add_calculation(Calculation::Store(
                ValueSource::Challenge(challenge.index()),
            )),
            Expression::Negated(a) => match **a {
                Expression::Constant(scalar) => self.add_constant(&-scalar),
                _ => {
                    let result_a = self.add_expression(a);
                    match result_a {
                        ValueSource::Constant(0) => result_a,
                        _ => self.add_calculation(Calculation::Negate(result_a)),
                    }
                }
            },
            Expression::Sum(a, b) => {
                // Undo subtraction stored as a + (-b) in expressions
                match &**b {
                    Expression::Negated(b_int) => {
                        let result_a = self.add_expression(a);
                        let result_b = self.add_expression(b_int);
                        if result_a == ValueSource::Constant(0) {
                            self.add_calculation(Calculation::Negate(result_b))
                        } else if result_b == ValueSource::Constant(0) {
                            result_a
                        } else {
                            self.add_calculation(Calculation::Sub(result_a, result_b))
                        }
                    }
                    _ => {
                        let result_a = self.add_expression(a);
                        let result_b = self.add_expression(b);
                        if result_a == ValueSource::Constant(0) {
                            result_b
                        } else if result_b == ValueSource::Constant(0) {
                            result_a
                        } else if result_a <= result_b {
                            self.add_calculation(Calculation::Add(result_a, result_b))
                        } else {
                            self.add_calculation(Calculation::Add(result_b, result_a))
                        }
                    }
                }
            }
            Expression::Product(a, b) => {
                let result_a = self.add_expression(a);
                let result_b = self.add_expression(b);
                if result_a == ValueSource::Constant(0) || result_b == ValueSource::Constant(0) {
                    ValueSource::Constant(0)
                } else if result_a == ValueSource::Constant(1) {
                    result_b
                } else if result_b == ValueSource::Constant(1) {
                    result_a
                } else if result_a == ValueSource::Constant(2) {
                    self.add_calculation(Calculation::Double(result_b))
                } else if result_b == ValueSource::Constant(2) {
                    self.add_calculation(Calculation::Double(result_a))
                } else if result_a == result_b {
                    self.add_calculation(Calculation::Square(result_a))
                } else if result_a <= result_b {
                    self.add_calculation(Calculation::Mul(result_a, result_b))
                } else {
                    self.add_calculation(Calculation::Mul(result_b, result_a))
                }
            }
            Expression::Scaled(a, f) => {
                if *f == C::ScalarExt::zero() {
                    ValueSource::Constant(0)
                } else if *f == C::ScalarExt::one() {
                    self.add_expression(a)
                } else {
                    let cst = self.add_constant(f);
                    let result_a = self.add_expression(a);
                    self.add_calculation(Calculation::Mul(result_a, cst))
                }
            }
        }
    }

    /// Creates a new evaluation structure
    pub fn instance(&self) -> EvaluationData<C> {
        EvaluationData {
            intermediates: vec![C::ScalarExt::zero(); self.num_intermediates],
            rotations: vec![0usize; self.rotations.len()],
        }
    }

    pub fn evaluate<B: Basis>(
        &self,
        data: &mut EvaluationData<C>,
        fixed: &[Polynomial<C::ScalarExt, B>],
        advice: &[Polynomial<C::ScalarExt, B>],
        instance: &[Polynomial<C::ScalarExt, B>],
        challenges: &[C::ScalarExt],
        beta: &C::ScalarExt,
        gamma: &C::ScalarExt,
        theta: &C::ScalarExt,
        y: &C::ScalarExt,
        previous_value: &C::ScalarExt,
        idx: usize,
        rot_scale: i32,
        isize: i32,
    ) -> C::ScalarExt {
        // All rotation index values
        for (rot_idx, rot) in self.rotations.iter().enumerate() {
            data.rotations[rot_idx] = get_rotation_idx(idx, *rot, rot_scale, isize);
        }

        // All calculations, with cached intermediate results
        for calc in self.calculations.iter() {
            data.intermediates[calc.target] = calc.calculation.evaluate(
                &data.rotations,
                &self.constants,
                &data.intermediates,
                fixed,
                advice,
                instance,
                challenges,
                beta,
                gamma,
                theta,
                y,
                previous_value,
            );
        }

        // Return the result of the last calculation (if any)
        if let Some(calc) = self.calculations.last() {
            data.intermediates[calc.target]
        } else {
            C::ScalarExt::zero()
        }
    }
}

/// Simple evaluation of an expression
pub fn evaluate<F: FieldExt, B: Basis>(
    expression: &Expression<F>,
    size: usize,
    rot_scale: i32,
    fixed: &[Polynomial<F, B>],
    advice: &[Polynomial<F, B>],
    instance: &[Polynomial<F, B>],
    challenges: &[F],
) -> Vec<F> {
    let mut values = vec![F::zero(); size];
    let isize = size as i32;
    parallelize(&mut values, |values, start| {
        for (i, value) in values.iter_mut().enumerate() {
            let idx = start + i;
            *value = expression.evaluate(
                &|scalar| scalar,
                &|_| panic!("virtual selectors are removed during optimization"),
                &|query| {
                    fixed[query.column_index]
                        [get_rotation_idx(idx, query.rotation.0, rot_scale, isize)]
                },
                &|query| {
                    advice[query.column_index]
                        [get_rotation_idx(idx, query.rotation.0, rot_scale, isize)]
                },
                &|query| {
                    instance[query.column_index]
                        [get_rotation_idx(idx, query.rotation.0, rot_scale, isize)]
                },
                &|challenge| challenges[challenge.index()],
                &|a| -a,
                &|a, b| a + &b,
                &|a, b| a * b,
                &|a, scalar| a * scalar,
            );
        }
    });
    values
}
