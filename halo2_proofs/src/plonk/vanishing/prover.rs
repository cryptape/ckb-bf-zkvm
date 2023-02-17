use core::iter;

use ff::Field;
use group::Curve;
use rand_core::RngCore;

use super::Argument;
use crate::{
    arithmetic::{eval_polynomial, CurveAffine, FieldExt},
    plonk::{ChallengeX, ChallengeY, Error},
    poly::{
        self,
        commitment::{Blind, ParamsProver},
        Coeff, EvaluationDomain, ExtendedLagrangeCoeff, Polynomial, ProverQuery,
    },
    transcript::{EncodedChallenge, TranscriptWrite},
    vec, Vec,
};

pub(in crate::plonk) struct Committed<C: CurveAffine> {
    random_poly: Polynomial<C::Scalar, Coeff>,
    random_blind: Blind<C::Scalar>,
}

pub(in crate::plonk) struct Constructed<C: CurveAffine> {
    h_pieces: Vec<Polynomial<C::Scalar, Coeff>>,
    h_blinds: Vec<Blind<C::Scalar>>,
    committed: Committed<C>,
}

pub(in crate::plonk) struct Evaluated<C: CurveAffine> {
    h_poly: Polynomial<C::Scalar, Coeff>,
    h_blind: Blind<C::Scalar>,
    committed: Committed<C>,
}

impl<C: CurveAffine> Argument<C> {
    /// This commitment scheme commits to a _zero polynomial_,
    /// that means our commitment scheme is binding but not hidding.
    /// This is fine for schemes that does not require zero-knowledge.
    pub(in crate::plonk) fn commit<
        'params,
        P: ParamsProver<'params, C>,
        E: EncodedChallenge<C>,
        R: RngCore,
        T: TranscriptWrite<C, E>,
    >(
        params: &P,
        domain: &EvaluationDomain<C::Scalar>,
        mut _rng: R,
        transcript: &mut T,
    ) -> Result<Committed<C>, Error> {
        // Sample a random polynomial of degree n - 1
        let random_poly = domain.constant_lagrange(C::Scalar::one());
        let random_poly = domain.lagrange_to_coeff(random_poly);
        // Sample a random blinding factor
        let random_blind = Blind(C::Scalar::zero());
        let c = params.commit(&random_poly, random_blind).to_affine();
        // We write the identity point to the transcript which
        // is the commitment of the zero polynomial.
        transcript.write_point(c)?;

        Ok(Committed {
            random_poly,
            random_blind,
        })
    }
}

impl<C: CurveAffine> Committed<C> {
    pub(in crate::plonk) fn construct<
        'params,
        P: ParamsProver<'params, C>,
        E: EncodedChallenge<C>,
        R: RngCore,
        T: TranscriptWrite<C, E>,
    >(
        self,
        params: &P,
        domain: &EvaluationDomain<C::Scalar>,
        h_poly: Polynomial<C::Scalar, ExtendedLagrangeCoeff>,
        mut rng: R,
        transcript: &mut T,
    ) -> Result<Constructed<C>, Error> {
        // Divide by t(X) = X^{params.n} - 1.
        let h_poly = domain.divide_by_vanishing_poly(h_poly);

        // Obtain final h(X) polynomial
        let h_poly = domain.extended_to_coeff(h_poly);

        // Split h(X) up into pieces
        let h_pieces = h_poly
            .chunks_exact(params.n() as usize)
            .map(|v| domain.coeff_from_vec(v.to_vec()))
            .collect::<Vec<_>>();
        drop(h_poly);
        let h_blinds: Vec<_> = h_pieces
            .iter()
            .map(|_| Blind(C::Scalar::random(&mut rng)))
            .collect();

        // Compute commitments to each h(X) piece
        let h_commitments_projective: Vec<_> = h_pieces
            .iter()
            .zip(h_blinds.iter())
            .map(|(h_piece, blind)| params.commit(h_piece, *blind))
            .collect();
        let mut h_commitments = vec![C::identity(); h_commitments_projective.len()];
        C::Curve::batch_normalize(&h_commitments_projective, &mut h_commitments);
        let h_commitments = h_commitments;

        // Hash each h(X) piece
        for c in h_commitments.iter() {
            transcript.write_point(*c)?;
        }

        Ok(Constructed {
            h_pieces,
            h_blinds,
            committed: self,
        })
    }
}

impl<C: CurveAffine> Constructed<C> {
    pub(in crate::plonk) fn evaluate<E: EncodedChallenge<C>, T: TranscriptWrite<C, E>>(
        self,
        x: ChallengeX<C>,
        xn: C::Scalar,
        domain: &EvaluationDomain<C::Scalar>,
        transcript: &mut T,
    ) -> Result<Evaluated<C>, Error> {
        let h_poly = self
            .h_pieces
            .iter()
            .rev()
            .fold(domain.empty_coeff(), |acc, eval| acc * xn + eval);

        let h_blind = self
            .h_blinds
            .iter()
            .rev()
            .fold(Blind(C::Scalar::zero()), |acc, eval| {
                acc * Blind(xn) + *eval
            });

        let random_eval = eval_polynomial(&self.committed.random_poly, *x);
        transcript.write_scalar(random_eval)?;

        Ok(Evaluated {
            h_poly,
            h_blind,
            committed: self.committed,
        })
    }
}

impl<C: CurveAffine> Evaluated<C> {
    pub(in crate::plonk) fn open(
        &self,
        x: ChallengeX<C>,
    ) -> impl Iterator<Item = ProverQuery<'_, C>> + Clone {
        iter::empty()
            .chain(Some(ProverQuery {
                point: *x,
                poly: &self.h_poly,
                blind: self.h_blind,
            }))
            .chain(Some(ProverQuery {
                point: *x,
                poly: &self.committed.random_poly,
                blind: self.committed.random_blind,
            }))
    }
}
