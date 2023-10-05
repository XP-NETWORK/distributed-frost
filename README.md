Before running code 

Create /opt/frostshare/
Chmod 777 for frostshare 
Create a layout like this and compile the code
Start code with party id 1 and go on till party id 11
Follow on screen instructions 
![image](https://github.com/NoorahSmith/Frost-projective/assets/136467640/b9a69bee-8441-44fc-849f-0ef4994f7aec)
If any error comes in groupkey, it will be highlighted
![image](https://github.com/NoorahSmith/Frost-projective/assets/136467640/4d7ecfdc-be93-4652-a326-487156524abb)
if no error , tss signature will be finalized
.
![image](https://github.com/NoorahSmith/Frost-projective/assets/136467640/8d0589d4-cfca-4171-aacf-fe7c3e5f09a0)



# FROST [![](https://img.shields.io/crates/v/frost-dalek.svg)](https://crates.io/crates/frost-dalek) [![](https://docs.rs/frost-dalek/badge.svg)](https://docs.rs/frost-dalek) [![](https://travis-ci.com/github/isislovecruft/frost-dalek.svg?branch=master)](https://travis-ci.org/isislovecruft/frost-dalek)

A Rust implementation of
[FROST: Flexible Round-Optimised Schnorr Threshold signatures](https://eprint.iacr.org/2020/852)
by Chelsea Komlo and Ian Goldberg.

Modified for [EthSchnorr](https://github.com/smartcontractkit/chainlink/blob/v1.0.1/contracts/src/v0.5/dev/SchnorrSECP256K1.sol) with SECP256k1 EC.

## Usage

Please see [the documentation](https://docs.rs/frost-dalek) for usage examples.

## Note on `no_std` usage

Most of this crate is `no_std` compliant, however, the current
implementation uses `HashMap`s for the signature creation and aggregation
protocols, and thus requires the standard library.

## WARNING

This code is likely not stable.  The author is working with the paper authors on
an RFC which, if/when adopted, will allow us to stabilise this codebase.  Until
then, the structure and construction of these signatures, as well as wireformats
for several types which must be sent between signing parties, may change in
incompatible ways.
