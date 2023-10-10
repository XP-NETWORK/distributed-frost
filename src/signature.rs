// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! FROST signatures and their creation.

#[cfg(feature = "std")]
use std::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use k256::FieldBytes;
use k256::ProjectivePoint;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::LinearCombination;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha3::Digest;
use sha3::Keccak256;

use core::cmp::Ordering;

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::collections::hash_map::Values;
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use k256::CompressedPoint;
use k256::AffinePoint;
use k256::Scalar;

use crate::FrostInfo;
use crate::keygen::GroupKey;
use crate::keygen::IndividualPublicKey;
use crate::precomputation::SecretCommitmentShareList;

pub use crate::keygen::SecretKey;

// XXX Nonce reuse is catastrophic and results in obtaining an individual
//     signer's long-term secret key; it must be prevented at all costs.

/// An individual signer in the threshold signature scheme.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Signer {
    /// The participant index of this signer.
    pub participant_index: u32,
    /// One of the commitments that were published by each signing participant
    /// in the pre-computation phase.
    pub published_commitment_share: (AffinePoint, AffinePoint),
}

impl Ord for Signer {
    fn cmp(&self, other: &Signer) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialOrd for Signer {
    fn partial_cmp(&self, other: &Signer) -> Option<Ordering> {
        match self.participant_index.cmp(&other.participant_index) {
            Ordering::Less => Some(Ordering::Less),
            // WARNING: Participants cannot have identical indices, so dedup() MUST be called.
            Ordering::Equal => Some(Ordering::Equal),
            Ordering::Greater => Some(Ordering::Greater),
        }
    }
}

impl PartialEq for Signer {
    fn eq(&self, other: &Signer) -> bool {
        self.participant_index == other.participant_index
    }
}

/// A partially-constructed threshold signature, made by each participant in the
/// signing protocol during the first phase of a signature creation.
#[derive(Debug)]
pub struct PartialThresholdSignature {
    /// Index of the signature
    pub index: u32,
    /// Z component of sig
    pub z: Scalar,
}

/// A complete, aggregated threshold signature.
#[derive(Debug)]
pub struct ThresholdSignature {
    pub(crate) R: AffinePoint,
    pub(crate) z: Scalar,
}

impl ThresholdSignature {
    /// Serialize this threshold signature to an array of 64 bytes.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];

        bytes[..33].copy_from_slice(&self.R.to_bytes()[..]);
        bytes[33..].copy_from_slice(&self.z.to_bytes()[..]);
        bytes
    }

    /// Attempt to deserialize a threshold signature from an array of 64 bytes.
    pub fn from_bytes(bytes: [u8; 65]) -> Option<ThresholdSignature> {
        let Rc = CompressedPoint::from_slice(&bytes[..33]);
        let R = Option::from(AffinePoint::from_bytes(&Rc))?;

        let z = Option::from(Scalar::from_repr(FieldBytes::clone_from_slice(&bytes[33..])))?;

        Some(ThresholdSignature { R, z })
    }
}

#[cfg(feature = "std")]
macro_rules! impl_indexed_hashmap {
    (Type = $type:ident, Item = $item:ident) => {

impl $type {
    pub(crate) fn new() -> $type {
        $type(HashMap::new())
    }

    // [CFRG] Since the sorting order matters for the public API, both it
    // and the canonicalisation of the participant indices needs to be
    // specified.
    pub(crate) fn insert(&mut self, index: &u32, point: $item) {
        self.0.insert(index.to_be_bytes(), point);
    }

    pub(crate) fn get(&self, index: &u32) -> Option<&$item> {
        self.0.get(&index.to_be_bytes())
    }

    #[allow(unused)]
    pub(crate) fn sorted(&self) -> Vec<(u32, $item)> {
        let mut sorted: Vec<(u32, $item)> = Vec::with_capacity(self.0.len());

        for (i, point) in self.0.iter() {
            let index = u32::from_be_bytes(*i);
            sorted.insert(index as usize, (index, *point));
        }
        sorted
    }

    #[allow(unused)]
    pub(crate) fn values(&self) -> Values<'_, [u8; 4], $item> {
        self.0.values()
    }
}
    };
} // END macro_rules! impl_indexed_hashmap

/// A struct for storing signers' R values with the signer's participant index.
//
// I hate this so much.
//
// XXX TODO there might be a more efficient way to optimise this data structure
//     and its algorithms?
#[cfg(feature = "std")]
#[derive(Debug)]
struct SignerRs(pub(crate) HashMap<[u8; 4], AffinePoint>);

#[cfg(feature = "std")]
impl_indexed_hashmap!(Type = SignerRs, Item = AffinePoint);

/// A type for storing signers' partial threshold signatures along with the
/// respective signer participant index.
#[cfg(feature = "std")]
#[derive(Debug)]
pub(crate) struct PartialThresholdSignatures(pub(crate) HashMap<[u8; 4], Scalar>);

#[cfg(feature = "std")]
impl_indexed_hashmap!(Type = PartialThresholdSignatures, Item = Scalar);

/// A type for storing signers' individual public keys along with the respective
/// signer participant index.
#[cfg(feature = "std")]
#[derive(Debug)]
pub(crate) struct IndividualPublicKeys(pub(crate) HashMap<[u8; 4], AffinePoint>);

#[cfg(feature = "std")]
impl_indexed_hashmap!(Type = IndividualPublicKeys, Item = AffinePoint);

/// Compute a Keccak256 hash of am abi-encoded `context_string` and a `message`.
pub fn compute_message_hash(context_string: &[u8], message: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::default();

    h.update(context_string);
    h.update(message);

    h.finalize().into()
}

#[cfg(feature = "std")]
fn compute_binding_factors_and_group_commitment(
    message_hash: &[u8; 32],
    signers: &[Signer]
) -> (HashMap<u32, Scalar>, SignerRs) {
    let mut binding_factors: HashMap<u32, Scalar> = HashMap::with_capacity(signers.len());
    let mut Rs: SignerRs = SignerRs::new();

    // [CFRG] Should the hash function be hardcoded in the RFC or should
    // we instead specify the output/block size?
    let mut h = Keccak256::new();

    // [DIFFERENT_TO_PAPER] I added a context string and reordered to hash
    // constants like the message first.
    //h.update(b"FROST-KECCAK256");
    h.update(&message_hash[..]);

    // [DIFFERENT_TO_PAPER] I added the set of participants (in the paper
    // B = <(i, D_{ij}, E_(ij))> i \E S) here to avoid rehashing them over and
    // over again.
    for signer in signers.iter() {
        let mut hiding = signer.published_commitment_share.0.to_bytes();
        hiding[0] &= 1;
        let mut binding = signer.published_commitment_share.1.to_bytes();
        binding[0] &= 1;

        h.update(&signer.participant_index.to_be_bytes());
        h.update(&hiding[1..]);
        h.update(&hiding[0..1]);
        h.update(&binding[1..]);
        h.update(&binding[0..1]);
    }

    for signer in signers.iter() {
        let hiding = signer.published_commitment_share.0;
        let mut hiding_bytes = hiding.to_bytes();
        hiding_bytes[0] &= 1;
        let binding = signer.published_commitment_share.1;
        let mut binding_bytes = binding.to_bytes();
        binding_bytes[0] &= 1;

        let mut h1 = h.clone();

        // [DIFFERENT_TO_PAPER] I put in the participant index last to finish
        // their unique calculation of rho.
        h1.update(&signer.participant_index.to_be_bytes());
        h1.update(&hiding_bytes[1..]);
        h1.update(&hiding_bytes[0..1]);
        h1.update(&binding_bytes[1..]);
        h1.update(&binding_bytes[0..1]);

        let binding_factor = Scalar::from_repr(h1.finalize()).unwrap(); // This is rho in the paper.

        // THIS IS THE MAGIC STUFF ↓↓↓
        Rs.insert(&signer.participant_index, (binding * binding_factor + hiding).to_affine());
        binding_factors.insert(signer.participant_index, binding_factor);
    }
    (binding_factors, Rs)
}

// [DIFFERENT_FROM_PAPER] H(Y | m | Addr(Y))
fn compute_challenge(message_hash: &[u8; 32], group_key: &GroupKey, R: &AffinePoint) -> Scalar {
    let mut h1 = Keccak256::default();
    let enc = R.to_encoded_point(false).to_bytes();
    h1.update(&enc[1..33]);
    h1.update(&enc[33..]);
    let nonceGenPub = h1.finalize();

    let mut h2 = Keccak256::default();

    // XXX [PAPER] Decide if we want a context string for the challenge.  This
    // would break compatibility with standard ed25519 libraries for verification.
    //h2.update(b"FROST-KECCAK256");

    let mut gk_comp = group_key.to_bytes();
    gk_comp[0] &= 1;

    h2.update(&gk_comp[1..]);
    h2.update(&gk_comp[0..1]);
    h2.update(&message_hash[..]);
    h2.update(&nonceGenPub[12..]);

    let res = h2.finalize();

    Scalar::from_repr(res).unwrap()
}

/// Calculate using Lagrange's method the interpolation of a polynomial.
///
/// # Note
///
/// isis stole this from Chelsea and Ian but they stole it from Lagrange, so who
/// can really say.
pub(crate) fn calculate_lagrange_coefficients(
    participant_index: &u32,
    all_participant_indices: &[u32]
) -> Result<Scalar, &'static str> {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;

    let mine = Scalar::from(*participant_index);

    for j in all_participant_indices.iter() {
        if j == participant_index {
            continue;
        }
        let s = Scalar::from(*j);

        num *= s;
        den *= s - mine; // Check to ensure that one person isn't trying to sign twice.
    }

    if den == Scalar::ZERO {
        return Err("Duplicate shares provided");
    }
    Ok(num * den.invert().unwrap())
}

impl SecretKey {
    /// Compute an individual signer's [`PartialThresholdSignature`] contribution to
    /// a [`ThresholdSignature`] on a `message`.
    ///
    /// # Inputs
    ///
    /// * The `message_hash` to be signed by every individual signer, this should be
    ///   the `Keccak256` digest of the message, optionally along with some application-specific
    ///   context string, and can be calculated with the helper function
    ///   [`compute_message_hash`].
    /// * The public [`GroupKey`] for this group of signing participants,
    /// * This signer's [`SecretCommitmentShareList`] being used in this instantiation and
    /// * The index of the particular `CommitmentShare` being used, and
    /// * The list of all the currently participating [`Signer`]s (including ourself).
    ///
    /// # Warning
    ///
    /// The secret share `index` here **must** be the same secret share
    /// corresponding to its public commitment which is passed to
    /// `SignatureAggregrator.include_signer()`.
    ///
    /// # Returns
    ///
    /// A Result whose `Ok` value contains a [`PartialThresholdSignature`], which
    /// should be sent to the [`SignatureAggregator`].  Otherwise, its `Err` value contains
    /// a string describing the error which occurred.
    #[cfg(feature = "std")]
    pub fn sign(
        &self,
        message_hash: &[u8; 32],
        group_key: &GroupKey,
        // XXX [PAPER] I don't know that we can guarantee simultaneous runs of the protocol
        // with these nonces being potentially reused?
        my_secret_commitment_share_list: &mut SecretCommitmentShareList,
        my_commitment_share_index: usize,
        signers: &[Signer]
    ) -> Result<PartialThresholdSignature, &'static str> {
        if my_commitment_share_index + 1 > my_secret_commitment_share_list.commitments.len() {
            return Err("Commitment share index out of bounds");
        }

        let (binding_factors, Rs) = compute_binding_factors_and_group_commitment(
            &message_hash,
            &signers
        );
        let R: ProjectivePoint = Rs.values().fold(ProjectivePoint::IDENTITY, |acc, x| acc + x);
        let challenge = compute_challenge(&message_hash, &group_key, &R.to_affine());
        let my_binding_factor = binding_factors
            .get(&self.index)
            .ok_or("Could not compute our blinding factor")?;
        let all_participant_indices: Vec<u32> = signers
            .iter()
            .map(|x| x.participant_index)
            .collect();
        let lambda: Scalar = calculate_lagrange_coefficients(
            &self.index,
            &all_participant_indices
        )?;
        let my_commitment_share =
            my_secret_commitment_share_list.commitments[my_commitment_share_index].clone();
        let z =
            my_commitment_share.hiding.nonce +
            my_commitment_share.binding.nonce * my_binding_factor -
            lambda * self.key * challenge; // [DIFFERENT_TO_PAPER] this term is positive in the paper.

        // [DIFFERENT_TO_PAPER] We need to instead pass in the commitment
        // share list and zero-out the used commitment share, which means the
        // signature aggregator needs to tell us somehow which one they picked from
        // our published list.
        //
        // I.... don't really love this API?

        // XXX [PAPER] If we do lists like this, then the indices of the public
        // commitment shares go out of sync.

        // Zero out our secrets from memory to prevent nonce reuse.
        my_secret_commitment_share_list.drop_share(my_commitment_share);

        Ok(PartialThresholdSignature { index: self.index, z })
    }
}

/// A signature aggregator, in any of various states.
pub trait Aggregator {}

/// The internal state of a signature aggregator.
#[cfg(feature = "std")]
#[derive(Debug)]
pub(crate) struct AggregatorState {
    /// The protocol instance parameters.
    pub(crate) parameters: FrostInfo,
    /// The set of signing participants for this round.
    pub(crate) signers: Vec<Signer>,
    /// The signer's public keys for verifying their [`PartialThresholdSignature`].
    pub(crate) public_keys: IndividualPublicKeys,
    /// The partial signatures from individual participants which have been
    /// collected thus far.
    pub(crate) partial_signatures: PartialThresholdSignatures,
    /// The group public key for all the participants.
    pub(crate) group_key: GroupKey,
}

/// A signature aggregator is an untrusted party who coalesces all of the
/// participating signers' published commitment shares and their
/// [`PartialThresholdSignature`] and creates the final [`ThresholdSignature`].
/// The signature aggregator may even be one of the \\(t\\) participants in this
/// signing operation.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct SignatureAggregator<A: Aggregator> {
    /// The aggregator's actual state, shared across types.
    pub(crate) state: Box<AggregatorState>,
    /// The aggregator's additional state.
    pub(crate) aggregator: A,
}

/// The initial state for a [`SignatureAggregator`], which may include invalid
/// or non-sensical data.
#[derive(Debug)]
pub struct Initial {
    /// An optional context string for computing the message hash.
    pub(crate) context: Vec<u8>,
    /// The message to be signed.
    pub(crate) message: Vec<u8>,
}

impl Aggregator for Initial {}

/// The finalized state for a [`SignatureAggregator`], which has thoroughly
/// validated its data.
///
/// # Guarantees
///
/// * There are no duplicate signing attempts from the same individual signer.
/// * All expected signers have contributed a partial signature.
/// * All expected signers have a public key.
// XXX Should we check that these public keys are valid?
///
/// This leaves only one remaining failure mode for the actual aggregation of
/// the partial signatures:
///
/// * Any signer could have contributed a malformed partial signature.
#[derive(Debug)]
pub struct Finalized {
    /// The hashed context and message for signing.
    pub(crate) message_hash: [u8; 32],
}

impl Aggregator for Finalized {}

#[cfg(feature = "std")]
impl SignatureAggregator<Initial> {
    /// Construct a new signature aggregator from some protocol instantiation
    /// `parameters` and a `message` to be signed.
    ///
    /// # Inputs
    ///
    /// * The [`Parameters`] for this threshold signing operation,
    /// * The public [`GroupKey`] for the intended sets of signers,
    /// * An optional `context` string for computing the message hash,
    /// * The `message` to be signed.
    ///
    /// # Notes
    ///
    /// The `context` and the `message` string should be given to the aggregator
    /// so that all signers can query them before deciding whether or not to
    /// sign.
    ///
    /// # Returns
    ///
    /// A new [`SignatureAggregator`].
    pub fn new(
        parameters: FrostInfo,
        group_key: GroupKey,
        context: Vec<u8>,
        message: Vec<u8>
    ) -> SignatureAggregator<Initial> {
        let signers: Vec<Signer> = Vec::with_capacity(parameters.thresholdvalue as usize);
        let public_keys = IndividualPublicKeys::new();
        let partial_signatures = PartialThresholdSignatures::new();
        let state = AggregatorState {
            parameters,
            signers,
            public_keys,
            partial_signatures,
            group_key,
        };

        SignatureAggregator { state: Box::new(state), aggregator: Initial { context, message } }
    }

    /// Include a signer in the protocol.
    ///
    /// # Warning
    ///
    /// If this method is called for a specific participant, then that
    /// participant MUST provide a partial signature to give to
    /// [`SignatureAggregator.include_partial_signature`], otherwise the signing
    /// procedure will fail.
    ///
    /// # Panics
    ///
    /// If the `signer.participant_index` doesn't match the `public_key.index`.
    pub fn include_signer(
        &mut self,
        participant_index: u32,
        published_commitment_share: (AffinePoint, AffinePoint),
        public_key: IndividualPublicKey
    ) {
        assert_eq!(
            participant_index,
            public_key.index,
            "Tried to add signer with participant index {}, but public key is for participant with index {}",
            participant_index,
            public_key.index
        );

        self.state.signers.push(Signer { participant_index, published_commitment_share });
        self.state.public_keys.insert(&public_key.index, public_key.share);
    }

    /// Get the list of partipating signers.
    ///
    /// # Returns
    ///
    /// A `&Vec<Signer>` of the participating signers in this round.
    pub fn get_signers<'sa>(&'sa mut self) -> &'sa Vec<Signer> {
        // .sort() must be called before .dedup() because the latter only
        // removes consecutive repeated elements.
        self.state.signers.sort();
        self.state.signers.dedup();

        &self.state.signers
    }

    /// Helper function to get the remaining signers who were expected to sign,
    /// but have not yet contributed their [`PartialThresholdSignature`]s.
    ///
    /// This can be used by an honest aggregator who wishes to ensure that the
    /// aggregation procedure is ready to be run, or who wishes to be able to
    /// remind/poll individual signers for their [`PartialThresholdSignature`]
    /// contribution.
    ///
    /// # Returns
    ///
    /// A sorted `Vec` of unique [`Signer`]s who have yet to contribute their
    /// partial signatures.
    pub fn get_remaining_signers(&self) -> Vec<Signer> {
        let mut remaining_signers: Vec<Signer> = Vec::new();

        for signer in self.state.signers.iter() {
            if self.state.partial_signatures.get(&signer.participant_index).is_none() {
                remaining_signers.push(*signer);
            }
        }
        remaining_signers.sort();
        remaining_signers.dedup();
        remaining_signers
    }

    /// Add a [`PartialThresholdSignature`] to be included in the aggregation.
    pub fn include_partial_signature(&mut self, partial_signature: PartialThresholdSignature) {
        self.state.partial_signatures.insert(&partial_signature.index, partial_signature.z);
    }

    /// Ensure that this signature aggregator is in a proper state to run the aggregation protocol.
    ///
    /// # Returns
    ///
    /// A Result whose Ok() value is a finalized aggregator, otherwise a
    /// `Hashmap<u32, &'static str>` containing the participant indices of the misbehaving
    /// signers and a description of their misbehaviour.
    ///
    /// If the `Hashmap` contains a key for `0`, this indicates that
    /// the aggregator did not have \(( t' \)) partial signers
    /// s.t. \(( t \le t' \le n \)).
    pub fn finalize(
        mut self
    ) -> Result<SignatureAggregator<Finalized>, HashMap<u32, &'static str>> {
        let mut misbehaving_participants: HashMap<u32, &'static str> = HashMap::new();
        let remaining_signers = self.get_remaining_signers();

        // [DIFFERENT_TO_PAPER] We're reporting missing partial signatures which
        // could possibly be the fault of the aggregator, but here we explicitly
        // make it the aggregator's fault and problem.
        if !remaining_signers.is_empty() {
            // We call the aggregator "participant 0" for the sake of error messages.
            misbehaving_participants.insert(0, "Missing remaining signer(s)");

            for signer in remaining_signers.iter() {
                misbehaving_participants.insert(
                    signer.participant_index,
                    "Missing partial signature"
                );
            }
        }

        // Ensure that our new state is ordered and deduplicated.
        self.state.signers = self.get_signers().clone();

        for signer in self.state.signers.iter() {
            if self.state.public_keys.get(&signer.participant_index).is_none() {
                // XXX These should be Vec<&'static str> for full error reporting
                misbehaving_participants.insert(signer.participant_index, "Missing public key");
            }
        }

        if !misbehaving_participants.is_empty() {
            return Err(misbehaving_participants);
        }

        let message_hash = compute_message_hash(&self.aggregator.context, &self.aggregator.message);

        Ok(SignatureAggregator { state: self.state, aggregator: Finalized { message_hash } })
    }
}

#[cfg(feature = "std")]
impl SignatureAggregator<Finalized> {
    /// Aggregate a set of previously-collected partial signatures.
    ///
    /// # Returns
    ///
    /// A Result whose Ok() value is a [`ThresholdSignature`], otherwise a
    /// `Hashmap<u32, &'static str>` containing the participant indices of the misbehaving
    /// signers and a description of their misbehaviour.
    pub fn aggregate(&self) -> Result<ThresholdSignature, HashMap<u32, &'static str>> {
        let mut misbehaving_participants: HashMap<u32, &'static str> = HashMap::new();

        let (_, Rs) = compute_binding_factors_and_group_commitment(
            &self.aggregator.message_hash,
            &self.state.signers
        );
        let R: ProjectivePoint = Rs.values().fold(ProjectivePoint::IDENTITY, |acc, x| acc + x);
        let Raff = R.to_affine();
        let c = compute_challenge(&self.aggregator.message_hash, &self.state.group_key, &Raff);
        let all_participant_indices: Vec<u32> = self.state.signers
            .iter()
            .map(|x| x.participant_index)
            .collect();
        let mut z = Scalar::ZERO;

        for signer in self.state.signers.iter() {
            // [DIFFERENT_TO_PAPER] We're not just pulling lambda out of our
            // ass, instead to get the correct algebraic properties to allow for
            // partial signature aggregation with t <= #participant <= n, we
            // have to do Langrangian polynomial interpolation.
            //
            // This unwrap() cannot fail, since the attempted division by zero in
            // the calculation of the Lagrange interpolation cannot happen,
            // because we use the typestate pattern,
            // i.e. SignatureAggregator<Initial>.finalize(), to ensure that
            // there are no duplicate signers, which is the only thing that
            // would cause a denominator of zero.
            let lambda = calculate_lagrange_coefficients(
                &signer.participant_index,
                &all_participant_indices
            ).unwrap();

            // Similar to above, this unwrap() cannot fail, because
            // SignatureAggregator<Initial>.finalize() checks that we have
            // partial signature for every expected signer.
            let partial_sig = self.state.partial_signatures.get(&signer.participant_index).unwrap();

            // Again, this unwrap() cannot fail, because of the checks in finalize().
            let Y_i = self.state.public_keys.get(&signer.participant_index).unwrap();

            let check = AffinePoint::GENERATOR * partial_sig;

            // Again, this unwrap() cannot fail, because we check the
            // participant indexes against the expected ones in finalize().
            let R_i = Rs.get(&signer.participant_index).unwrap();

            // [DIFFERENT_TO_PAPER] c * lambda is positive in the paper
            if check == *Y_i * (-c * lambda) + R_i {
                z += partial_sig;
            } else {
                // XXX We don't really need the error string anymore, since there's only one failure mode.
                misbehaving_participants.insert(
                    signer.participant_index,
                    "Incorrect partial signature"
                );
            }
        }

        match !misbehaving_participants.is_empty() {
            true => Err(misbehaving_participants),
            false => Ok(ThresholdSignature { z, R: Raff }),
        }
    }
}

impl ThresholdSignature {
    /// Verify this [`ThresholdSignature`].
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is an empty tuple if the threshold signature
    /// was successfully verified, otherwise a vector of the participant indices
    /// of any misbehaving participants.
    pub fn verify(&self, group_key: &GroupKey, message_hash: &[u8; 32]) -> Result<(), ()> {
        let c_prime = compute_challenge(&message_hash, &group_key, &self.R);
        // [DIFFERENT_TO_PAPER] modified schnorr
        let R_prime = ProjectivePoint::lincomb(
            &group_key.0.into(),
            &c_prime,
            &ProjectivePoint::GENERATOR,
            &self.z
        );

        match self.R.to_bytes() == R_prime.to_affine().to_bytes() {
            true => Ok(()),
            false => Err(()),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;

    use crate::keygen::Participant;
    use crate::keygen::{ DistributedKeyGeneration, RoundOne };
    use crate::precomputation::generate_commitment_share_lists;

    use k256::elliptic_curve::Field;
    use rand::rngs::OsRng;

    #[test]
    fn signing_and_verification_single_party() {
        let params = FrostInfo { thresholdvalue: 1, totalvalue: 1 };

        let (p1, p1coeffs) = Participant::new(&params, 1);

        p1.proof_of_secret_key.verify(&p1.index, &p1.commitments[0].to_affine()).unwrap();

        let mut p1_other_participants: Vec<Participant> = Vec::new();
        let p1_state = DistributedKeyGeneration::<RoundOne>
            ::new(&params, &p1.index, &p1coeffs, &mut p1_other_participants)
            .unwrap();
        let p1_my_secret_shares = Vec::new();
        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let result = p1_state.finish(&p1.public_key().unwrap());

        assert!(result.is_ok());

        let (group_key, p1_sk) = result.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(
            &mut OsRng,
            1,
            1
        );

        let mut aggregator = SignatureAggregator::new(
            params,
            group_key,
            context.to_vec(),
            message.to_vec()
        );

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk
            .sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers)
            .unwrap();

        aggregator.include_partial_signature(p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("{:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_1_out_of_1() {
        let params = FrostInfo { thresholdvalue: 1, totalvalue: 1 };

        let (p1, p1coeffs) = Participant::new(&params, 1);

        let mut p1_other_participants: Vec<Participant> = Vec::with_capacity(0);
        let p1_state = DistributedKeyGeneration::<RoundOne>
            ::new(&params, &p1.index, &p1coeffs, &mut p1_other_participants)
            .unwrap();
        let p1_my_secret_shares = Vec::with_capacity(0);
        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish(&p1.public_key().unwrap()).unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(
            &mut OsRng,
            1,
            1
        );

        let mut aggregator = SignatureAggregator::new(
            params,
            group_key,
            context.to_vec(),
            message.to_vec()
        );

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk
            .sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers)
            .unwrap();

        aggregator.include_partial_signature(p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_1_out_of_2() {
        let params = FrostInfo { thresholdvalue: 1, totalvalue: 2 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);

        let mut p1_other_participants: Vec<Participant> = vec![p2.clone()];
        let p1_state = DistributedKeyGeneration::<RoundOne>
            ::new(&params, &p1.index, &p1coeffs, &mut p1_other_participants)
            .unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();

        let mut p2_other_participants: Vec<Participant> = vec![p1.clone()];
        let p2_state = DistributedKeyGeneration::<RoundOne>
            ::new(&params, &p2.index, &p2coeffs, &mut p2_other_participants)
            .unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec![p2_their_secret_shares[0].clone()]; // XXX FIXME indexing
        let p2_my_secret_shares = vec![p1_their_secret_shares[0].clone()];

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish(&p1.public_key().unwrap()).unwrap();
        let (_, _p2_sk) = p2_state.finish(&p2.public_key().unwrap()).unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(
            &mut OsRng,
            1,
            1
        );

        let mut aggregator = SignatureAggregator::new(
            params,
            group_key,
            context.to_vec(),
            message.to_vec()
        );

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk
            .sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers)
            .unwrap();

        aggregator.include_partial_signature(p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_3_out_of_5() {
        let params = FrostInfo { thresholdvalue: 3, totalvalue: 5 };

        let (p1, p1coeffs) = Participant::new(&params, 1);
        let (p2, p2coeffs) = Participant::new(&params, 2);
        let (p3, p3coeffs) = Participant::new(&params, 3);
        let (p4, p4coeffs) = Participant::new(&params, 4);
        let (p5, p5coeffs) = Participant::new(&params, 5);

        let mut p1_other_participants: Vec<Participant> = vec![
            p2.clone(),
            p3.clone(),
            p4.clone(),
            p5.clone()
        ];
        let p1_state = DistributedKeyGeneration::<RoundOne>
            ::new(&params, &p1.index, &p1coeffs, &mut p1_other_participants)
            .unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();

        let mut p2_other_participants: Vec<Participant> = vec![
            p1.clone(),
            p3.clone(),
            p4.clone(),
            p5.clone()
        ];
        let p2_state = DistributedKeyGeneration::<RoundOne>
            ::new(&params, &p2.index, &p2coeffs, &mut p2_other_participants)
            .unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec![
            p1.clone(),
            p2.clone(),
            p4.clone(),
            p5.clone()
        ];
        let p3_state = DistributedKeyGeneration::<RoundOne>
            ::new(&params, &p3.index, &p3coeffs, &mut p3_other_participants)
            .unwrap();
        let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec![
            p1.clone(),
            p2.clone(),
            p3.clone(),
            p5.clone()
        ];
        let p4_state = DistributedKeyGeneration::<RoundOne>
            ::new(&params, &p4.index, &p4coeffs, &mut p4_other_participants)
            .unwrap();
        let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec![
            p1.clone(),
            p2.clone(),
            p3.clone(),
            p4.clone()
        ];
        let p5_state = DistributedKeyGeneration::<RoundOne>
            ::new(&params, &p5.index, &p5coeffs, &mut p5_other_participants)
            .unwrap();
        let p5_their_secret_shares = p5_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec![
            p2_their_secret_shares[0].clone(), // XXX FIXME indexing
            p3_their_secret_shares[0].clone(),
            p4_their_secret_shares[0].clone(),
            p5_their_secret_shares[0].clone()
        ];

        let p2_my_secret_shares = vec![
            p1_their_secret_shares[0].clone(),
            p3_their_secret_shares[1].clone(),
            p4_their_secret_shares[1].clone(),
            p5_their_secret_shares[1].clone()
        ];

        let p3_my_secret_shares = vec![
            p1_their_secret_shares[1].clone(),
            p2_their_secret_shares[1].clone(),
            p4_their_secret_shares[2].clone(),
            p5_their_secret_shares[2].clone()
        ];

        let p4_my_secret_shares = vec![
            p1_their_secret_shares[2].clone(),
            p2_their_secret_shares[2].clone(),
            p3_their_secret_shares[2].clone(),
            p5_their_secret_shares[3].clone()
        ];

        let p5_my_secret_shares = vec![
            p1_their_secret_shares[3].clone(),
            p2_their_secret_shares[3].clone(),
            p3_their_secret_shares[3].clone(),
            p4_their_secret_shares[3].clone()
        ];

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_secret_shares).unwrap();
        let p3_state = p3_state.to_round_two(p3_my_secret_shares).unwrap();
        let p4_state = p4_state.to_round_two(p4_my_secret_shares).unwrap();
        let p5_state = p5_state.to_round_two(p5_my_secret_shares).unwrap();
    }

    #[test]
    fn signing_and_verification_2_out_of_3() {
        fn do_keygen() -> Result<(FrostInfo, SecretKey, SecretKey, SecretKey, GroupKey), ()> {
            let params = FrostInfo { thresholdvalue: 2, totalvalue: 3 };

            let (p1, p1coeffs) = Participant::new(&params, 1);
            let (p2, p2coeffs) = Participant::new(&params, 2);
            let (p3, p3coeffs) = Participant::new(&params, 3);

            p2.proof_of_secret_key.verify(&p2.index, &p2.commitments[0].to_affine())?;
            p3.proof_of_secret_key.verify(&p3.index, &p3.commitments[0].to_affine())?;

            let mut p1_other_participants: Vec<Participant> = vec![p2.clone(), p3.clone()];
            let p1_state = DistributedKeyGeneration::<RoundOne>
                ::new(&params, &p1.index, &p1coeffs, &mut p1_other_participants)
                .or(Err(()))?;
            let p1_their_secret_shares = p1_state.their_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec![p1.clone(), p3.clone()];
            let p2_state = DistributedKeyGeneration::<RoundOne>
                ::new(&params, &p2.index, &p2coeffs, &mut p2_other_participants)
                .or(Err(()))?;
            let p2_their_secret_shares = p2_state.their_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec![p1.clone(), p2.clone()];
            let p3_state = DistributedKeyGeneration::<RoundOne>
                ::new(&params, &p3.index, &p3coeffs, &mut p3_other_participants)
                .or(Err(()))?;
            let p3_their_secret_shares = p3_state.their_secret_shares()?;

            let p1_my_secret_shares = vec![
                p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                p3_their_secret_shares[0].clone()
            ];
            let p2_my_secret_shares = vec![
                p1_their_secret_shares[0].clone(),
                p3_their_secret_shares[1].clone()
            ];
            let p3_my_secret_shares = vec![
                p1_their_secret_shares[1].clone(),
                p2_their_secret_shares[1].clone()
            ];

            let p1_state = p1_state.to_round_two(p1_my_secret_shares)?;
            let p2_state = p2_state.to_round_two(p2_my_secret_shares)?;
            let p3_state = p3_state.to_round_two(p3_my_secret_shares)?;

            let (p1_group_key, p1_secret_key) = p1_state.finish(&p1.public_key().unwrap())?;
            let (p2_group_key, p2_secret_key) = p2_state.finish(&p2.public_key().unwrap())?;
            let (p3_group_key, p3_secret_key) = p3_state.finish(&p3.public_key().unwrap())?;

            assert!(p1_group_key.0.to_bytes() == p2_group_key.0.to_bytes());
            assert!(p2_group_key.0.to_bytes() == p3_group_key.0.to_bytes());

            Ok((params, p1_secret_key, p2_secret_key, p3_secret_key, p1_group_key))
        }
        let keygen_protocol = do_keygen();

        assert!(keygen_protocol.is_ok());

        let (params, p1_sk, p2_sk, _p3_sk, group_key) = keygen_protocol.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(
            &mut OsRng,
            1,
            1
        );
        let (p2_public_comshares, mut p2_secret_comshares) = generate_commitment_share_lists(
            &mut OsRng,
            2,
            1
        );

        let mut aggregator = SignatureAggregator::new(
            params,
            group_key.clone(),
            context.to_vec(),
            message.to_vec()
        );

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk
            .sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers)
            .unwrap();
        let p2_partial = p2_sk
            .sign(&message_hash, &group_key, &mut p2_secret_comshares, 0, signers)
            .unwrap();

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("{:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn aggregator_get_signers() {
        let params = FrostInfo { thresholdvalue: 2, totalvalue: 3 };
        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let (p1_public_comshares, _) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p2_public_comshares, _) = generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator = SignatureAggregator::new(
            params,
            GroupKey(AffinePoint::IDENTITY),
            context.to_vec(),
            message.to_vec()
        );

        let p1_sk = SecretKey { index: 1, key: Scalar::random(&mut OsRng) };
        let p2_sk = SecretKey { index: 2, key: Scalar::random(&mut OsRng) };

        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());
        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());

        let signers = aggregator.get_signers();

        // The signers should be deduplicated.
        assert!(signers.len() == 2);

        // The indices should match and be in sorted order.
        assert!(signers[0].participant_index == 1);
        assert!(signers[1].participant_index == 2);

        // Participant 1 should have the correct precomputed shares.
        assert!(signers[0].published_commitment_share.0 == p1_public_comshares.commitments[0].0);
        assert!(signers[0].published_commitment_share.1 == p1_public_comshares.commitments[0].1);

        // Same for participant 2.
        assert!(signers[1].published_commitment_share.0 == p2_public_comshares.commitments[0].0);
        assert!(signers[1].published_commitment_share.1 == p2_public_comshares.commitments[0].1);
    }
}
