// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2017-2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! A Rust implementation of **[FROST]**: **F**lexible **R**ound-**O**ptimised **S**chnorr **T**hreshold signatures.
//!
//! Threshold signatures are a cryptographic construction wherein a subset, \\( t \\),
//! of a group of \\( n \\) signers can produce a valid signature.  For example, if
//! Alice, Bob, and Carol set up key materials for a 2-out-of-3 threshold signature
//! scheme, then the same public group key can be used to verify a message signed
//! by Alice and Carol as a different message signed by Bob and Carol.
//!
//! FROST signatures are unique in that they manage to optimise threshold signing into
//! a single round, while still safeguarding against [various] [cryptographic] [attacks]
//! that effect other threshold signing schemes, by utilising [commitments] to
//! pre-computed secret shares.
//!
//! For a more in-depth explanation of the mathematics involved, please see
//! [here](keygen/index.html), [here](precomputation/index.html), and
//! [here](signature/index.html).
//!
//! [FROST]: https://eprint.iacr.org/2020/852
//! [various]: https://eprint.iacr.org/2018/417
//! [cryptographic]: https://eprint.iacr.org/2020/945
//! [attacks]: https://www.researchgate.net/profile/Claus_Schnorr/publication/2900710_Security_of_Blind_Discrete_Log_Signatures_against_Interactive_Attacks/links/54231e540cf26120b7a6bb47.pdf
//! [commitments]: https://en.wikipedia.org/wiki/Commitment_scheme
//!
//! # Usage
//!
//! Alice, Bob, and Carol would like to set up a threshold signing scheme where
//! at least two of them need to sign on a given message to produce a valid
//! signature.
//!
//! ```rust
//! use frost_secp256k1::Parameters;
//!
//! let params = Parameters { t: 2, n: 3 };
//! ```
//!
//! ## Distributed Key Generation
//!
//! Alice, Bob, and Carol each generate their secret polynomial coefficients
//! (which make up each individual's personal secret key) and commitments to
//! them, as well as a zero-knowledge proof of their personal secret key.  Out
//! of scope, they each need to agree upon their *participant index* which is
//! some non-zero integer unique to each of them (these are the `1`, `2`, and
//! `3` in the following examples).
//!
//! ```rust
//! # use frost_secp256k1::Parameters;
//! use frost_secp256k1::Participant;
//! #
//! # let params = Parameters { t: 2, n: 3 };
//!
//! let (alice, alice_coefficients) = Participant::new(&params, 1);
//! let (bob, bob_coefficients) = Participant::new(&params, 2);
//! let (carol, carol_coefficients) = Participant::new(&params, 3);
//! ```
//!
//! They send these values to each of the other participants (also out of scope
//! for this library), or otherwise publish them publicly somewhere.
//!
//! ```rust
//! # // This comment is here just to silence the "this code block is empty" warning.
//! // send_to_bob(alice);
//! // send_to_carol(alice);
//! // send_to_alice(bob);
//! // send_to_carol(bob);
//! // send_to_alice(carol);
//! // send_to_bob(carol);
//! ```
//!
//! Note that they should only send the `alice`, `bob`, and `carol` structs, *not*
//! the `alice_coefficients`, etc., as the latter are their personal secret keys.
//!
//! Bob and Carol verify Alice's zero-knowledge proof by doing:
//!
//! ```rust
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! alice.proof_of_secret_key.verify(&alice.index, &alice.public_key().unwrap())?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Similarly, Alice and Carol verify Bob's proof:
//!
//! ```rust
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! bob.proof_of_secret_key.verify(&bob.index, &bob.public_key().unwrap())?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! And, again, Alice and Bob verify Carol's proof:
//!
//! ```rust
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! carol.proof_of_secret_key.verify(&carol.index, &carol.public_key().unwrap())?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alice enters round one of the distributed key generation protocol:
//!
//! ```rust
//! use frost_secp256k1::DistributedKeyGeneration;
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! #
//! # fn do_test() -> Result<(), Vec<u32>> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//!
//! let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//!                                                      &mut alice_other_participants)?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alice then collects the secret shares which they send to the other participants:
//!
//! ```rust
//! # use frost_secp256k1::DistributedKeyGeneration;
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! let alice_their_secret_shares = alice_state.their_secret_shares()?;
//!
//! // send_to_bob(alice_their_secret_shares[0]);
//! // send_to_carol(alice_their_secret_shares[1]);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Bob and Carol each do the same:
//!
//! ```rust
//! # use frost_secp256k1::DistributedKeyGeneration;
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! #
//! # fn do_test() -> Result<(), Vec<u32>> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//!                                                    &mut bob_other_participants)?;
//! # Ok(()) }
//! # fn do_test2() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//!
//! let bob_their_secret_shares = bob_state.their_secret_shares()?;
//!
//! // send_to_alice(bob_their_secret_shares[0]);
//! // send_to_carol(bob_their_secret_shares[1]);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); assert!(do_test2().is_ok()); }
//! ```
//!
//! and
//!
//! ```rust
//! # use frost_secp256k1::DistributedKeyGeneration;
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! #
//! # fn do_test() -> Result<(), Vec<u32>> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//!                                                      &mut carol_other_participants)?;
//! # Ok(()) }
//! # fn do_test2() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//!
//! let carol_their_secret_shares = carol_state.their_secret_shares()?;
//!
//! // send_to_alice(carol_their_secret_shares[0]);
//! // send_to_bob(carol_their_secret_shares[1]);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); assert!(do_test2().is_ok()); }
//! ```
//!
//! Each participant now has a vector of secret shares given to them by the other participants:
//!
//! ```rust
//! # use frost_secp256k1::DistributedKeyGeneration;
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//!                                   carol_their_secret_shares[0].clone());
//! let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//!                                 carol_their_secret_shares[1].clone());
//! let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//!                                   bob_their_secret_shares[1].clone());
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! The participants then use these secret shares from the other participants to advance to
//! round two of the distributed key generation protocol.
//!
//! ```rust
//! # use frost_secp256k1::DistributedKeyGeneration;
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! # let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//! #                                   carol_their_secret_shares[0].clone());
//! # let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//! #                                 carol_their_secret_shares[1].clone());
//! # let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//! #                                   bob_their_secret_shares[1].clone());
//! #
//! let alice_state = alice_state.to_round_two(alice_my_secret_shares)?;
//! let bob_state = bob_state.to_round_two(bob_my_secret_shares)?;
//! let carol_state = carol_state.to_round_two(carol_my_secret_shares)?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Each participant can now derive their long-lived, personal secret keys and the group's
//! public key.  They should all derive the same group public key.  They
//! also derive their [`IndividualPublicKey`]s from their [`IndividualSecretKey`]s.
//!
//! ```rust
//! # use frost_secp256k1::DistributedKeyGeneration;
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! # let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//! #                                   carol_their_secret_shares[0].clone());
//! # let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//! #                                 carol_their_secret_shares[1].clone());
//! # let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//! #                                   bob_their_secret_shares[1].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_secret_shares)?;
//! # let bob_state = bob_state.to_round_two(bob_my_secret_shares)?;
//! # let carol_state = carol_state.to_round_two(carol_my_secret_shares)?;
//! #
//! let (alice_group_key, alice_secret_key) = alice_state.finish(&alice.public_key().unwrap())?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish(&bob.public_key().unwrap())?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish(&carol.public_key().unwrap())?;
//!
//! assert!(alice_group_key == bob_group_key);
//! assert!(carol_group_key == bob_group_key);
//!
//! let alice_public_key = alice_secret_key.to_public();
//! let bob_public_key = bob_secret_key.to_public();
//! let carol_public_key = carol_secret_key.to_public();
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! ## Precomputation and Partial Signatures
//!
//! Alice, Bob, and Carol can now create partial threshold signatures over an agreed upon
//! message with their respective secret keys, which they can then give to an untrusted
//! [`SignatureAggregator`] (which can be one of the participants) to create a
//! 2-out-of-3 threshold signature.  To do this, they each pre-compute (using
//! [`generate_commitment_share_lists`]) and publish a list of commitment shares.
//!
//! ```rust
//! # #[cfg(feature = "std")]
//! use frost_secp256k1::compute_message_hash;
//! # #[cfg(feature = "std")]
//! use frost_secp256k1::generate_commitment_share_lists;
//! # use frost_secp256k1::DistributedKeyGeneration;
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! # #[cfg(feature = "std")]
//! use frost_secp256k1::SignatureAggregator;
//!
//! use rand::rngs::OsRng;
//! # #[cfg(feature = "std")]
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! # let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//! #                                   carol_their_secret_shares[0].clone());
//! # let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//! #                                 carol_their_secret_shares[1].clone());
//! # let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//! #                                   bob_their_secret_shares[1].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_secret_shares)?;
//! # let bob_state = bob_state.to_round_two(bob_my_secret_shares)?;
//! # let carol_state = carol_state.to_round_two(carol_my_secret_shares)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish(&alice.public_key().unwrap())?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish(&bob.public_key().unwrap())?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish(&carol.public_key().unwrap())?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//!
//! let (alice_public_comshares, mut alice_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
//! let (bob_public_comshares, mut bob_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
//! let (carol_public_comshares, mut carol_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
//!
//! // Each application developer should choose a context string as unique to their usage as possible,
//! // in order to provide domain separation from other applications which use FROST signatures.
//! let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! let message = b"This is a test of the tsunami alert system. This is only a test.";
//!
//! // Every signer should compute a hash of the message to be signed, along with, optionally,
//! // some additional context, such as public information about the run of the protocol.
//! let message_hash = compute_message_hash(&context[..], &message[..]);
//!
//! let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), context.to_vec(), message.to_vec());
//! # Ok(()) }
//! # #[cfg(feature = "std")]
//! # fn main() { assert!(do_test().is_ok()); }
//! # #[cfg(not(feature = "std"))]
//! # fn main() { }
//! ```
//!
//! The aggregator takes note of each expected signer for this run of the protocol.  For this run,
//! we'll have Alice and Carol sign.
//!
//! ```rust
//! # #[cfg(feature = "std")]
//! # use frost_secp256k1::compute_message_hash;
//! # #[cfg(feature = "std")]
//! # use frost_secp256k1::generate_commitment_share_lists;
//! # use frost_secp256k1::DistributedKeyGeneration;
//! # use frost_secp256k1::IndividualPublicKey;
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! # #[cfg(feature = "std")]
//! # use frost_secp256k1::SignatureAggregator;
//! #
//! # use rand::rngs::OsRng;
//! #
//! # #[cfg(feature = "std")]
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(()))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares()?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(()))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares()?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(()))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares()?;
//! # let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//! #                                   carol_their_secret_shares[0].clone());
//! # let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//! #                                 carol_their_secret_shares[1].clone());
//! # let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//! #                                   bob_their_secret_shares[1].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_secret_shares)?;
//! # let bob_state = bob_state.to_round_two(bob_my_secret_shares)?;
//! # let carol_state = carol_state.to_round_two(carol_my_secret_shares)?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish(&alice.public_key().unwrap())?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish(&bob.public_key().unwrap())?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish(&carol.public_key().unwrap())?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//! #
//! # let (alice_public_comshares, mut alice_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
//! # let (bob_public_comshares, mut bob_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
//! # let (carol_public_comshares, mut carol_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
//! #
//! # let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let message_hash = compute_message_hash(&context[..], &message[..]);
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), context.to_vec(), message.to_vec());
//! #
//! aggregator.include_signer(1, alice_public_comshares.commitments[0], alice_public_key);
//! aggregator.include_signer(3, carol_public_comshares.commitments[0], carol_public_key);
//! # Ok(()) }
//! # #[cfg(feature = "std")]
//! # fn main() { assert!(do_test().is_ok()); }
//! # #[cfg(not(feature = "std"))]
//! # fn main() { }
//! ```
//!
//! The aggregator should then publicly announce which participants are expected to be signers.
//!
//! ```rust,ignore
//! let signers = aggregator.get_signers();
//! ```
//!
//! Alice and Carol each then compute their partial signatures, and send these to the signature aggregator.
//!
//! ```rust
//! # #[cfg(feature = "std")]
//! # use frost_secp256k1::compute_message_hash;
//! # #[cfg(feature = "std")]
//! # use frost_secp256k1::generate_commitment_share_lists;
//! # use frost_secp256k1::DistributedKeyGeneration;
//! # use frost_secp256k1::Parameters;
//! # use frost_secp256k1::Participant;
//! # #[cfg(feature = "std")]
//! # use frost_secp256k1::SignatureAggregator;
//! #
//! # use rand::rngs::OsRng;
//! #
//! # #[cfg(feature = "std")]
//! # fn do_test() -> Result<(), &'static str> {
//! # let params = Parameters { t: 2, n: 3 };
//! #
//! # let (alice, alice_coefficients) = Participant::new(&params, 1);
//! # let (bob, bob_coefficients) = Participant::new(&params, 2);
//! # let (carol, carol_coefficients) = Participant::new(&params, 3);
//! #
//! # let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! # let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
//! #                                                      &mut alice_other_participants).or(Err(""))?;
//! # let alice_their_secret_shares = alice_state.their_secret_shares().or(Err(""))?;
//! #
//! # let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! # let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
//! #                                                    &mut bob_other_participants).or(Err(""))?;
//! # let bob_their_secret_shares = bob_state.their_secret_shares().or(Err(""))?;
//! #
//! # let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! # let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
//! #                                                      &mut carol_other_participants).or(Err(""))?;
//! # let carol_their_secret_shares = carol_state.their_secret_shares().or(Err(""))?;
//! # let alice_my_secret_shares = vec!(bob_their_secret_shares[0].clone(),
//! #                                   carol_their_secret_shares[0].clone());
//! # let bob_my_secret_shares = vec!(alice_their_secret_shares[0].clone(),
//! #                                 carol_their_secret_shares[1].clone());
//! # let carol_my_secret_shares = vec!(alice_their_secret_shares[1].clone(),
//! #                                   bob_their_secret_shares[1].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_secret_shares).or(Err(""))?;
//! # let bob_state = bob_state.to_round_two(bob_my_secret_shares).or(Err(""))?;
//! # let carol_state = carol_state.to_round_two(carol_my_secret_shares).or(Err(""))?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish(&alice.public_key().unwrap()).or(Err(""))?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish(&bob.public_key().unwrap()).or(Err(""))?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish(&carol.public_key().unwrap()).or(Err(""))?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//! #
//! # let (alice_public_comshares, mut alice_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
//! # let (bob_public_comshares, mut bob_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
//! # let (carol_public_comshares, mut carol_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
//! #
//! # let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let message_hash = compute_message_hash(&context[..], &message[..]);
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), context.to_vec(), message.to_vec());
//! #
//! # aggregator.include_signer(1, alice_public_comshares.commitments[0], (&alice_secret_key).into());
//! # aggregator.include_signer(3, carol_public_comshares.commitments[0], (&carol_secret_key).into());
//! #
//! # let signers = aggregator.get_signers();
//!
//! let alice_partial = alice_secret_key.sign(&message_hash, &alice_group_key,
//!                                           &mut alice_secret_comshares, 0, signers)?;
//! let carol_partial = carol_secret_key.sign(&message_hash, &carol_group_key,
//!                                           &mut carol_secret_comshares, 0, signers)?;
//!
//! aggregator.include_partial_signature(alice_partial);
//! aggregator.include_partial_signature(carol_partial);
//! # Ok(()) }
//! # #[cfg(feature = "std")]
//! # fn main() { assert!(do_test().is_ok()); }
//! # #[cfg(not(feature = "std"))]
//! # fn main() { }
//! ```
//!
//! ## Signature Aggregation
//!
//! Once all the expected signers have sent their partial signatures, the
//! aggregator attempts to finalize its state, ensuring that there are no errors
//! thus far in the partial signatures, before finally attempting to complete
//! the aggregation of the partial signatures into a threshold signature.
//!
//! ```rust,ignore
//! let aggregator = aggregator.finalize()?;
//! ```
//!
//! If the aggregator could not finalize the state, then the `.finalize()` method
//! will return a `HashMap<u32, &'static str>` describing participant indices and the issues
//! encountered for them.  These issues are **guaranteed to be the fault of the aggregator**,
//! e.g. not collecting all the expected partial signatures, accepting two partial
//! signatures from the same participant, etc.
//!
//! And the same for the actual aggregation, if there was an error then a
//! `HashMap<u32, &'static str>` will be returned which maps participant indices to issues.
//! Unlike before, however, these issues are guaranteed to be the fault of the
//! corresponding participant, specifically, that their partial signature was invalid.
//!
//! ```rust,ignore
//! let threshold_signature = aggregator.aggregate()?;
//! ```
//!
//! Anyone with the group public key can then verify the threshold signature
//! in the same way they would for a standard Schnorr signature.
//!
//! ```rust,ignore
//! let verified = threshold_signature.verify(&alice_group_key, &message_hash)?;
//! ```
//!
//! # Note on `no_std` usage
//!
//! Most of this crate is `no_std` compliant, however, the current
//! implementation uses `HashMap`s for the signature creation and aggregation
//! protocols, and thus requires the standard library.

// #![no_std]
#![warn(future_incompatible)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

#[cfg(not(any(feature = "std", feature = "alloc")))]
compile_error!("Either feature \"std\" or \"alloc\" must be enabled for this crate.");

// We use the vec! macro in unittests.
#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod keygen;
pub mod parameters;
pub mod precomputation;
pub mod nizk;

// The signing protocol uses Hashmap (currently for both the signature aggregator
// and signers), which requires std.
pub mod signature;

use std::vec::Vec;
use generic_array::GenericArray;
use generic_array::typenum::B0;
use generic_array::typenum::B1;
use generic_array::typenum::UTerm;
use k256::Scalar;
use k256::elliptic_curve::group::GroupEncoding;
use keygen::Coefficients;
pub use keygen::DistributedKeyGeneration;
pub use keygen::GroupKey;
pub use keygen::IndividualPublicKey;
pub use keygen::Participant;
pub use keygen::SecretKey as IndividualSecretKey;
use keygen::SecretShare;
use nizk::NizkOfSecretKey;
pub use parameters::Parameters;
#[cfg(feature = "std")]
pub use precomputation::generate_commitment_share_lists;
pub use signature::ThresholdSignature;

#[cfg(feature = "std")]
pub use crate::signature::compute_message_hash;
#[cfg(feature = "std")]
pub use crate::signature::SignatureAggregator;

///@Irtisam24TODO add proper documentation
#[derive(Clone, Debug, Copy)]
pub struct FrostInfo {
    ///
    pub thresholdvalue: u8,
    ///
    pub totalvalue: u8,
}

/// Type Alias for public_bytes type
pub type PublicBytes = GenericArray<
    u8,
    sha3::digest::typenum::UInt<
        sha3::digest::typenum::UInt<
            sha3::digest::typenum::UInt<
                sha3::digest::typenum::UInt<
                    sha3::digest::typenum::UInt<sha3::digest::typenum::UInt<UTerm, B1>, B0>,
                    B0
                >,
                B0
            >,
            B0
        >,
        B1
    >
>;

/// Function to convert Participant vector from bytes to Particpant object
/// This function is for frost with parameters of 7/11 where 7 is  (Threshold) and 11( total parties)
fn convert_bytes_to_party(party_bytes: &[u8; 315]) -> Participant {
    // Structure of bytes
    // ZKP R scaler 40 bytes
    // ZKP S scaler 40 bytes
    // 7 Commitments shares 33 bytes=231
    // index u32 ->u8 = 4 bytes
    // Total=40+40+33+33+33+33+33+33+33+4=315
    // Create an empty commitment Vector
    let mut commit_vector: Vec<k256::ProjectivePoint> = vec![];

    let mut bytes_sequence: [u8; 4] = [0, 0, 0, 0];
    bytes_sequence.clone_from_slice(&party_bytes[311..315]);

    // Since No direct conversion from u8 to u32 is available,
    // we skim through 8 bytes and converting them during the process
    //  and convert u8 to u32 to form Index
    let index_u32_integer: u32 =
        ((bytes_sequence[0] as u32) << 24) |
        ((bytes_sequence[1] as u32) << 16) |
        ((bytes_sequence[2] as u32) << 8) |
        (bytes_sequence[3] as u32);
    // copy r and s bytes from slice
    // to convert these bytes back i
    let mut bytes_for_r: [u8; 32] = [0; 32];
    bytes_for_r.copy_from_slice(&party_bytes[0..32]);
    let mut bytes_for_s: [u8; 32] = [0; 32];
    bytes_for_s.copy_from_slice(&party_bytes[32..64]);

    // create S and R from De-Serializing bincode and

    let skey: Result<Scalar, Box<bincode::ErrorKind>> = bincode::deserialize(bytes_for_s.as_ref());
    let rkey: Result<Scalar, Box<bincode::ErrorKind>> = bincode::deserialize(bytes_for_r.as_ref());
    // create a new Nizk of Secret Keys  with r and S for formation of participant
    // This Nizk is a ZKP which allows other parties to verify that the particpant is holder of private key / Secret Vector and
    // susequently verfied Participant        let mut zkpfull: frost_secp256k1::nizk::NizkOfSecretKey =
    let zkpfull = NizkOfSecretKey {
        s: skey.unwrap(),
        r: rkey.unwrap(),
    };
    // Counter of Commitment so to loop through all 7 commitments

    let mut commit = 0;
    let mut start_bytes = 80;
    // Counter of Commitment so to loop through all 7 commitments of size 33bytes
    while commit < 7 {
        let endvalue = start_bytes + 33;
        // Each commitment is of 33 bytes which is actually a projective point with two scalers .
        let mut bytescommit: [u8; 33] = [0; 33];
        // 33 bytes for creating a commitment for Commitment vector in Participant
        bytescommit.copy_from_slice(&party_bytes[start_bytes..endvalue]);
        let genarray = GenericArray::from_slice(bytescommit.as_ref());
        // Create a Projective point from bytes with z [1,0,0,0,0]
        let byte_projective = k256::ProjectivePoint::from_bytes(&genarray).unwrap();
        // Push the prepared projective point on commitment vector

        commit_vector.push(byte_projective);

        start_bytes = endvalue;
        commit = commit + 1;
    }

    // Create a new participant with index, commitment vector and proof of secret key  from bytes
    let party_convert: Participant = Participant {
        index: index_u32_integer,
        commitments: commit_vector,
        proof_of_secret_key: zkpfull,
    };

    party_convert
}

/// The secret Vector of  particpant to be converted to bytes
/// These secrets are to be shared with other parties .
/// Before proceeding to the Round one every party must collect Secret shares created by all other parties for self
/// and create a Vector of secret shares with all secret shares from all parties destined for self
/// In configuration of 11 Parties, each party will get 10 SecretShares
/// Size of one SecretShare is 44 bytes . so total size would be 440
pub fn convert_secret_to_bytes(secretvector: &Vec<SecretShare>) -> [u8; 440] {
    //Structure of one Secretbytes is Index and polynomial_evaluation which is a Scaler ( 40+4)
    // Direct Constructor for polynomial_evaluation ( Scaler) is not present so we
    // serialize it with bincode instead of using to bytes function which return the sec bytes
    // and adding index manually
    // every secret share is 44 bytes long
    let total = secretvector.len();
    let mut count = 0;
    let mut secretbytes: [u8; 440] = [0; 440];
    let mut startindex = 0;
    let mut endindex = 0;
    // loop through all bytes and calculating the size of next location
    //  by getting the length and adding it in the start index
    while count < total {
        let writebytes: Vec<u8> = bincode::serialize(&secretvector[count]).unwrap();
        // convert secret vector[count] to bytes using bincode instead of to bytes function
        let size: usize = writebytes.len();
        endindex = endindex + size;
        secretbytes[startindex..endindex].copy_from_slice(writebytes.as_slice());
        count = count + 1;
        startindex = endindex;
    }
    secretbytes
}

/// Inverting Bytes back to secret Vector of  particpant
/// These secrets are to be shared with other parties.
/// Before proceeding to the Round one every party must collect Secret shares created by all other parties for self
/// and create a Vector of secret shares with all secret shares from all parties destined for self
/// In configuration of 11 Parties, each party will get 10 SecretShares
/// Every Secret share is a vector contaning 10 Secrete shares in the configuration of 11 parties
pub fn convert_bytes_to_secret(secretbytes: [u8; 440]) -> Vec<SecretShare> {
    //Structure of one Secretbytes is Index and polynomial_evaluation which is a Scaler ( 40+4)
    // Direct Constructor for polynomial_evaluation ( Scaler) is not present so we
    // DEserialize it with bincode which return the secret SHare
    // and pushing it to the Secret vector
    let mut secret_vector_from_bytes: Vec<SecretShare> = vec![];

    let mut startindex = 0;
    let mut endindex = 36;
    let total = 11;
    let mut count = 1;
    while count < total {
        let mut bytesvalues: [u8; 36] = [0; 36];
        // Initialize 44 bytes to zero and copy from the input from start index to end index
        // which will be looping through starting from [0..44]
        bytesvalues.copy_from_slice(&secretbytes[startindex..endindex]);
        // Create a clone secret share by deserializing it using bincode
        let clone_secret_share: Result<SecretShare, Box<bincode::ErrorKind>> = bincode::deserialize(
            &bytesvalues
        );
        // unwrap the secretshare and push it on the secretvector to be returned.
        //for a party of 11 the vector will have a size of 10.
        secret_vector_from_bytes.push(clone_secret_share.unwrap());
        // swap the end index with start index and increade endindex by 44

        count = count + 1;
        startindex = endindex;
        endindex = endindex + 36;
    }
    secret_vector_from_bytes
}

/// Function to convert Participant vector to bytes which contains ,
/// Scaler R and S along with index of Party and Commitment shares.
/// The value of commitment share count is dependent upon the set threshold,
/// which in this case is 7
/// The function is only applicable for frost with parameters of 7/11 where 7 is  (Threshold) and 11( total parties)
pub fn convert_party_to_bytes(
    index: &u32,
    commitments_party: Participant,
    zkp: NizkOfSecretKey
) -> [u8; 315] {
    // Return bytes of count 315
    // Structure of bytes
    // ZKP R scaler 40 bytes
    // ZKP S scaler 40 bytes
    // 7 Commitments shares 33 bytes=231
    // index u32 ->u8 = 4 bytes
    // Total=40+40+33+33+33+33+33+33+33+4=315
    // Create a fixed size byte array of 315 size to return

    let mut resultbytes: [u8; 315] = [0; 315];
    //No direct method is available to Prepare Scalers back from bytes
    //so an indirect method was derived and the serialization code
    // of bincode was used to serialze Scaler  and vice versa.
    //The only draw back is that the size of original scaler is 32 bytes while converting it
    // using bincode makes it 40 bytes.
    let rbytes = bincode::serialize(&zkp.r).unwrap();
    let split = rbytes.split_at(32);
    resultbytes[0..32].clone_from_slice(&split.0);
    //copy R bytes to resulant bytes at the start of byte array
    let sbytes = bincode::serialize(&zkp.s).unwrap();
    let split = sbytes.split_at(32);
    resultbytes[32..64].clone_from_slice(&split.0);

    //copy S bytes to resulant bytes at the specified location
    // Total commitments are 7 in our case due to theshold

    let mut commit_count = 0;
    let mut startin_byte_index = 80;
    // start loop to copy all commitment vectors to resulant bytes
    while commit_count < 7 {
        // Each commitment is 33 bytes long but to be sure that no ir-regular
        // data is copied only 33 bytes are split from the usized byte array into
        // generic array and then using the split function are split at specified size .
        //Resulting 33 bytes are cloned  from slice.
        let ending_index = startin_byte_index + 33;
        let commitmentbytes = commitments_party.commitments[commit_count].to_bytes();
        let commit_split = commitmentbytes.split_at(33);
        resultbytes[startin_byte_index..ending_index].clone_from_slice(commit_split.0);
        startin_byte_index = ending_index;
        commit_count = commit_count + 1;
    }
    // copy index bytes in the resultant buffer
    resultbytes[startin_byte_index..315].copy_from_slice(index.to_be_bytes().as_slice());
    // return resultbytes
    resultbytes
}

/// Create Participant using parameters with total number of Participants
/// and threshold value
pub fn create_participant(
    frostInfo: FrostInfo,
    id: u8
) -> (Participant, PublicBytes, Coefficients) {
    let (party, partycoeffs) = Participant::new(&frostInfo, id.into());
    //_partycoeffs are never to shared as these act as the private key for participant in
    // forwarding the Distributed keygeneration algorithm
    // Convert Public key to bytes for writting and distrbution.
    let public_bytes = party.public_key().unwrap().to_bytes();
    (party, public_bytes, partycoeffs)
}
