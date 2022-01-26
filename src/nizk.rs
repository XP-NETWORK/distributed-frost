// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Zero-knowledge proofs.


use k256::AffinePoint;
use k256::ProjectivePoint;
use k256::Scalar;

use k256::elliptic_curve::Field;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::GroupEncoding;
use rand::CryptoRng;
use rand::Rng;
use sha3::Digest;
use sha3::Keccak256;

/// A proof of knowledge of a secret key, created by making a Schnorr signature
/// with the secret key.
///
/// This proof is created by making a pseudo-Schnorr signature,
/// \\( \sigma\_i = (s\_i, r\_i) \\) using \\( a\_{i0} \\) (from
/// `frost_secp256k1::keygen::DistributedKeyGeneration::<RoundOne>::compute_share`)
/// as the secret key, such that \\( k \stackrel{\\$}{\leftarrow} \mathbb{Z}\_q \\),
/// \\( M\_i = g^k \\), \\( s\_i = \mathcal{H}(i, \phi, g^{a\_{i0}}, M\_i) \\),
/// \\( r\_i = k + a\_{i0} \cdot s\_i \\).
///
/// Verification is done by calculating \\(M'\_i = g^r + A\_i^{-s}\\),
/// where \\(A\_i = g^{a_i}\\), and using it to compute
/// \\(s'\_i = \mathcal{H}(i, \phi, A\_i, M'\_i)\\), then finally
/// \\(s\_i \stackrel{?}{=} s'\_i\\).
#[derive(Clone, Debug)]
pub struct NizkOfSecretKey {
    /// The scalar portion of the Schnorr signature encoding the context.
    pub s: Scalar,
    /// The scalar portion of the Schnorr signature which is the actual signature.
    pub r: Scalar,
}

impl NizkOfSecretKey {
    /// Prove knowledge of a secret key.
    pub fn prove(
        index: &u32,
        secret_key: &Scalar,
        public_key: &AffinePoint,
        mut csprng: impl Rng + CryptoRng,
    ) -> Self
    {
        let k: Scalar = Scalar::random(&mut csprng);
        let M: ProjectivePoint = AffinePoint::GENERATOR * &k;

        let mut hram = Keccak256::default();

        hram.update(&index.to_be_bytes());
        hram.update(b"\xCE\xA6");
        hram.update(&public_key.to_bytes());
        hram.update(&M.to_affine().to_bytes());

        let s = Scalar::from_repr(hram.finalize()).unwrap();
        let r = k + (secret_key * &s);

        NizkOfSecretKey { s, r }
    }

    /// Verify that the prover does indeed know the secret key.
    pub fn verify(&self, index: &u32, public_key: &AffinePoint) -> Result<(), ()> {
        let M_prime: ProjectivePoint = (AffinePoint::GENERATOR * &self.r) + (*public_key * &-self.s);

        let mut hram = Keccak256::default();

        hram.update(&index.to_be_bytes());
        hram.update(b"\xCE\xA6");
        hram.update(&public_key.to_bytes());
        hram.update(&M_prime.to_affine().to_bytes());

        let s_prime = Scalar::from_repr(hram.finalize()).unwrap();

        if self.s == s_prime {
            return Ok(());
        }

        Err(())
    }
}
