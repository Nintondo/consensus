#![cfg_attr(not(feature = "std"), no_std)]
//! Pure-Rust implementation of the `libbitcoinconsensus` API surface.
//!
//! The goal of this crate is to faithfully reproduce the behaviour of
//! Bitcoin Core's consensus verification logic in Rust without relying on
//! the original C++ implementation.

#[cfg(all(feature = "external-secp", not(feature = "std")))]
compile_error!(
    "The `external-secp` feature requires `std` because it relies on the global secp256k1 context."
);

#[cfg(not(feature = "std"))]
extern crate alloc;

mod script;
mod tx;
pub mod types;

pub use script::ScriptError;

use core::fmt;

use crate::{
    script::{Interpreter, ScriptFlags, SpendContext},
    tx::{SpentOutputs, TransactionContext},
    types::{c_int64, c_uchar, c_uint},
};

/// Do not enable any verification.
pub const VERIFY_NONE: c_uint = 0;
/// Evaluate P2SH (BIP16) subscripts.
pub const VERIFY_P2SH: c_uint = 1 << 0;
/// Enforce strict ECDSA encoding (BIP62).
pub const VERIFY_STRICTENC: c_uint = 1 << 1;
/// Enforce strict DER (BIP66) compliance.
pub const VERIFY_DERSIG: c_uint = 1 << 2;
/// Require signatures to use low-S form (BIP62).
pub const VERIFY_LOW_S: c_uint = 1 << 3;
/// Enforce NULLDUMMY (BIP147).
pub const VERIFY_NULLDUMMY: c_uint = 1 << 4;
/// Require scriptSig to be push only.
pub const VERIFY_SIGPUSHONLY: c_uint = 1 << 5;
/// Require minimal data encodings (BIP62).
pub const VERIFY_MINIMALDATA: c_uint = 1 << 6;
/// Discourage use of upgradable NOP opcodes.
pub const VERIFY_DISCOURAGE_UPGRADABLE_NOPS: c_uint = 1 << 7;
/// Discourage unknown witness program versions (policy flag used by Core's script tests).
pub const VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: c_uint = 1 << 12;
/// Discourage unknown Taproot leaf versions (policy flag used by Bitcoin Core's script tests).
pub const VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: c_uint = 1 << 18;
/// Discourage unknown OP_SUCCESS opcodes inside tapscript (policy flag used by Bitcoin Core's script tests).
pub const VERIFY_DISCOURAGE_OP_SUCCESS: c_uint = 1 << 19;
/// Discourage unknown Taproot public key versions (policy flag used by Bitcoin Core's script tests).
pub const VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE: c_uint = 1 << 20;
/// Require a clean stack after evaluation.
pub const VERIFY_CLEANSTACK: c_uint = 1 << 8;
/// Enable CHECKLOCKTIMEVERIFY (BIP65).
pub const VERIFY_CHECKLOCKTIMEVERIFY: c_uint = 1 << 9;
/// Enable CHECKSEQUENCEVERIFY (BIP112).
pub const VERIFY_CHECKSEQUENCEVERIFY: c_uint = 1 << 10;
/// Enable WITNESS (BIP141).
pub const VERIFY_WITNESS: c_uint = 1 << 11;
/// Require minimal encodings for IF/NOTIF.
pub const VERIFY_MINIMALIF: c_uint = 1 << 13;
/// Enforce NULLFAIL behaviour (BIP147).
pub const VERIFY_NULLFAIL: c_uint = 1 << 14;
/// Require compressed pubkeys in segwit v0 contexts.
pub const VERIFY_WITNESS_PUBKEYTYPE: c_uint = 1 << 15;
/// Enable TAPROOT (BIPs 341 & 342)
pub const VERIFY_TAPROOT: c_uint = 1 << 17;

/// Aggregate of all soft-fork flags prior to Taproot activation.
pub const VERIFY_ALL_PRE_TAPROOT: c_uint = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS;

/// Computes flags for soft fork activation heights on the Bitcoin network.
pub fn height_to_flags(height: u32) -> u32 {
    let mut flag = VERIFY_NONE;

    if height >= 173_805 {
        flag |= VERIFY_P2SH;
    }
    if height >= 363_725 {
        flag |= VERIFY_DERSIG;
    }
    if height >= 388_381 {
        flag |= VERIFY_CHECKLOCKTIMEVERIFY;
    }
    if height >= 419_328 {
        flag |= VERIFY_CHECKSEQUENCEVERIFY;
    }
    if height >= 481_824 {
        flag |= VERIFY_NULLDUMMY | VERIFY_WITNESS;
    }
    if height >= 709_632 {
        flag |= VERIFY_TAPROOT;
    }

    flag
}

/// Reported version of the underlying consensus implementation.
///
/// The value is a placeholder until the pure-Rust implementation reaches
/// feature parity with Bitcoin Core.
pub const CONSENSUS_VERSION: u32 = 0;

/// Returns the `libbitcoinconsensus` version that this crate mimics.
pub fn version() -> u32 {
    CONSENSUS_VERSION
}

/// Detailed failure information returned by the diagnostic verification APIs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ScriptFailure {
    /// High-level error code compatible with `libbitcoinconsensus`.
    pub error: Error,
    /// Detailed interpreter error, mirroring Bitcoin Core's `ScriptError`.
    pub script_error: ScriptError,
}

/// Verifies a single spend (input) of a Bitcoin transaction.
///
/// This mirrors the API provided by `rust-bitcoinconsensus`.
pub fn verify(
    spent_output: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
) -> Result<(), Error> {
    let flags = match spent_outputs {
        Some(_) => VERIFY_ALL_PRE_TAPROOT | VERIFY_TAPROOT,
        None => VERIFY_ALL_PRE_TAPROOT,
    };

    verify_with_flags(
        spent_output,
        amount,
        spending_transaction,
        spent_outputs,
        input_index,
        flags,
    )
}

/// Same as [`verify`] but also reports the interpreter's `ScriptError`.
pub fn verify_with_details(
    spent_output: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
) -> Result<(), ScriptFailure> {
    let flags = match spent_outputs {
        Some(_) => VERIFY_ALL_PRE_TAPROOT | VERIFY_TAPROOT,
        None => VERIFY_ALL_PRE_TAPROOT,
    };

    perform_verification(
        spent_output,
        amount,
        spending_transaction,
        spent_outputs,
        input_index,
        flags,
    )
}

/// Same as [`verify`] but with explicit script verification flags.
pub fn verify_with_flags(
    spent_output_script: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
    flags: u32,
) -> Result<(), Error> {
    perform_verification(
        spent_output_script,
        amount,
        spending_transaction,
        spent_outputs,
        input_index,
        flags,
    )
    .map_err(|failure| failure.error)
}

/// Same as [`verify_with_flags`] but also reports the interpreter's `ScriptError`.
pub fn verify_with_flags_detailed(
    spent_output_script: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
    flags: u32,
) -> Result<(), ScriptFailure> {
    perform_verification(
        spent_output_script,
        amount,
        spending_transaction,
        spent_outputs,
        input_index,
        flags,
    )
}

fn perform_verification(
    spent_output_script: &[u8],
    amount: u64,
    spending_transaction: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
    flags: u32,
) -> Result<(), ScriptFailure> {
    let tx_ctx = TransactionContext::parse(spending_transaction).map_err(|err| ScriptFailure {
        error: err,
        script_error: ScriptError::Ok,
    })?;
    tx_ctx
        .ensure_input_index(input_index)
        .map_err(|err| ScriptFailure {
            error: err,
            script_error: ScriptError::Ok,
        })?;

    let flags = ScriptFlags::from_bits(flags).map_err(|err| ScriptFailure {
        error: err,
        script_error: ScriptError::Ok,
    })?;
    let spent_outputs = spent_outputs
        .map(|raw| SpentOutputs::new(tx_ctx.tx().input.len(), raw))
        .transpose()
        .map_err(|err| ScriptFailure {
            error: err,
            script_error: ScriptError::Ok,
        })?;
    let mut derived_amount: Option<u64> = None;
    if let Some(set) = spent_outputs.as_ref() {
        let prevout = &set.txouts()[input_index];
        if prevout.script_pubkey.as_bytes() != spent_output_script {
            return Err(ScriptFailure {
                error: Error::ERR_SPENT_OUTPUTS_MISMATCH,
                script_error: ScriptError::Ok,
            });
        }
        derived_amount = Some(prevout.value.to_sat());
    }
    let explicit_amount_known = true;
    let amount = derived_amount.unwrap_or(amount);
    let has_amount = derived_amount.is_some() || explicit_amount_known;
    let precomputed = tx_ctx.build_precomputed(spent_outputs.as_ref(), false);
    let spend_context = SpendContext::new(spent_output_script, spent_outputs, amount, has_amount);
    let mut interpreter = Interpreter::new(&tx_ctx, precomputed, input_index, spend_context, flags)
        .map_err(|err| ScriptFailure {
            error: err,
            script_error: ScriptError::Ok,
        })?;

    interpreter.verify().map_err(|err| ScriptFailure {
        error: err,
        script_error: interpreter.last_script_error(),
    })
}

/// Mimics the Bitcoin Core UTXO typedef (bitcoinconsenus.h).
#[repr(C)]
pub struct Utxo {
    /// Pointer to the scriptPubkey bytes.
    pub script_pubkey: *const c_uchar,
    /// The length of the scriptPubkey.
    pub script_pubkey_len: c_uint,
    /// The value in sats.
    pub value: c_int64,
}

/// Errors returned by the consensus verifier.
///
/// The variants mirror the identifiers exposed by `libbitcoinconsensus`.
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum Error {
    /// Default value, passed to `libbitcoinconsensus` as a return parameter.
    ERR_SCRIPT = 0, // This is ERR_OK in Bitcoin Core.
    /// An invalid index for `txTo`.
    ERR_TX_INDEX,
    /// `txToLen` did not match with the size of `txTo`.
    ERR_TX_SIZE_MISMATCH,
    /// An error deserializing `txTo`.
    ERR_TX_DESERIALIZE,
    /// Input amount is required if WITNESS is used.
    ERR_AMOUNT_REQUIRED,
    /// Script verification `flags` are invalid.
    ERR_INVALID_FLAGS,
    /// Verifying Taproot input requires previous outputs.
    ERR_SPENT_OUTPUTS_REQUIRED,
    /// Taproot outputs don't match.
    ERR_SPENT_OUTPUTS_MISMATCH,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        let description = match *self {
            ERR_SCRIPT => "error value was not set (value still 0)",
            ERR_TX_INDEX => "an invalid index for txTo",
            ERR_TX_SIZE_MISMATCH => "txToLen did not match with the size of txTo",
            ERR_TX_DESERIALIZE => "an error deserializing txTo",
            ERR_AMOUNT_REQUIRED => "input amount is required if WITNESS is used",
            ERR_INVALID_FLAGS => "script verification flags are invalid",
            ERR_SPENT_OUTPUTS_REQUIRED => "verifying taproot input requires previous outputs",
            ERR_SPENT_OUTPUTS_MISMATCH => "taproot outputs don't match",
        };

        f.write_str(description)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::{Interpreter, ScriptFlags, SpendContext};
    use crate::tx::SpentOutputs;
    use crate::tx::TransactionContext;
    use crate::Utxo;
    use bitcoin::{
        absolute::LockTime,
        blockdata::script::{Builder, PushBytesBuf, ScriptBuf},
        consensus::{self, Encodable},
        hashes::{hash160, sha256, Hash, HashEngine},
        hex::FromHex,
        key::{TapTweak, UntweakedPublicKey},
        opcodes::all,
        secp256k1::{
            self, constants, ecdsa::Signature as EcdsaSignature, Keypair, Message, Parity,
            Secp256k1, SecretKey,
        },
        sighash::{EcdsaSighashType, Prevouts, SegwitV0Sighash, SighashCache, TapSighashType},
        taproot::{TapLeafHash, TapNodeHash, TAPROOT_ANNEX_PREFIX, TAPROOT_LEAF_TAPSCRIPT},
        transaction::Version,
        Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    #[test]
    fn height_flag_schedule_matches_bitcoin_core() {
        assert_eq!(height_to_flags(0), VERIFY_NONE);
        assert!(height_to_flags(173_805) & VERIFY_P2SH != 0);
        assert!(height_to_flags(363_725) & VERIFY_DERSIG != 0);
        assert!(height_to_flags(388_381) & VERIFY_CHECKLOCKTIMEVERIFY != 0);
        assert!(height_to_flags(419_328) & VERIFY_CHECKSEQUENCEVERIFY != 0);
        assert!(height_to_flags(481_824) & VERIFY_WITNESS != 0);
        assert!(height_to_flags(709_632) & VERIFY_TAPROOT != 0);
    }

    #[test]
    fn verify_legacy_p2pkh() {
        let spent = Vec::from_hex("76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac").unwrap();
        let spending = Vec::from_hex("02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700").unwrap();

        verify(&spent, 0, &spending, None, 0).expect("valid spend");
    }

    #[test]
    fn verify_simple_p2sh_redeem_script() {
        let redeem_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let script_sig = push_data_script(redeem_script.as_bytes());
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let spent_script = ScriptBuf::new_p2sh(&redeem_script.script_hash());
        let tx_bytes = consensus::serialize(&tx);
        verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_P2SH)
            .expect("p2sh redeem should validate");
    }

    #[test]
    fn verify_p2sh_p2wsh_trivial_witness() {
        use bitcoin::hashes::{sha256, Hash};

        let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let witness_script_bytes = witness_script.as_bytes().to_vec();
        let redeem_hash = sha256::Hash::hash(&witness_script_bytes);
        let redeem_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(redeem_hash.to_byte_array().to_vec()).unwrap())
            .into_script();
        let script_sig = push_data_script(redeem_script.as_bytes());
        let witness = Witness::from(vec![witness_script_bytes.clone()]);

        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig,
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let spent_script = ScriptBuf::new_p2sh(&redeem_script.script_hash());
        let tx_bytes = consensus::serialize(&tx);
        verify_with_flags(
            spent_script.as_bytes(),
            5_000,
            &tx_bytes,
            None,
            0,
            VERIFY_P2SH | VERIFY_WITNESS,
        )
        .expect("p2sh-p2wsh witness spend should validate");
    }

    #[test]
    fn verify_script_conditions_then_branch() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_IF)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_ELSE)
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_ENDIF)
            .into_script();
        run_simple_script(script_sig, spent_script).expect("then branch executes");
    }

    #[test]
    fn verify_script_conditions_else_branch() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_IF)
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_ELSE)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_ENDIF)
            .into_script();
        run_simple_script(script_sig, spent_script).expect("else branch executes");
    }

    #[test]
    fn verify_script_unbalanced_conditional_fails() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_IF)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        run_simple_script(script_sig, spent_script).expect_err("missing endif should fail");
    }

    #[test]
    fn verify_altstack_roundtrip() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_TOALTSTACK)
            .push_opcode(all::OP_FROMALTSTACK)
            .push_opcode(all::OP_DEPTH)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_EQUAL)
            .into_script();
        run_simple_script(script_sig, spent_script).expect("altstack operations succeed");
    }

    #[test]
    fn verify_rot_and_swap_ops() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_PUSHNUM_3)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_ROT)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_PUSHNUM_3)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_EQUAL)
            .into_script();
        run_simple_script(script_sig, spent_script).expect("rot/swap maintain order");
    }

    #[test]
    fn verify_pick_and_roll_ops() {
        let pick_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_PUSHNUM_3)
            .into_script();
        let pick_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PICK)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        run_simple_script(pick_sig, pick_script).expect("op_pick duplicates value");

        let roll_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_PUSHNUM_3)
            .push_opcode(all::OP_PUSHNUM_4)
            .into_script();
        let roll_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_3)
            .push_opcode(all::OP_ROLL)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        run_simple_script(roll_sig, roll_script).expect("op_roll moves element to top");
    }

    #[test]
    fn verify_arithmetic_and_within() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_PUSHNUM_3)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_ADD)
            .push_opcode(all::OP_DUP)
            .push_opcode(all::OP_PUSHNUM_5)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_6)
            .push_opcode(all::OP_WITHIN)
            .into_script();
        run_simple_script(script_sig, spent_script).expect("arithmetic and within succeed");
    }

    #[test]
    fn verify_sigpushonly_flag() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_DUP)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_ADD)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_EQUAL)
            .into_script();

        run_simple_script(script_sig.clone(), spent_script.clone()).expect("non push-only allowed");

        run_script_with_ctx_flags(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_SIGPUSHONLY,
        )
        .expect_err("sigpushonly flag rejects non push-only scriptSig");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_SIGPUSHONLY,
        )
        .expect_err("sigpushonly failure reason");
        assert_eq!(failure.script_error, ScriptError::SigPushOnly);
    }

    #[test]
    fn verify_discourage_upgradable_nops_flag() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_NOP5)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();

        run_simple_script(script_sig.clone(), spent_script.clone()).expect("nop allowed");

        run_script_with_ctx_flags(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
        )
        .expect_err("discourage upgradable nops flag rejects reserved nop use");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
        )
        .expect_err("discourage nops detail");
        assert_eq!(failure.script_error, ScriptError::DiscourageUpgradableNops);
    }

    #[test]
    fn verify_checksig_opcount_limit() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);

        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(pk.serialize().to_vec()).unwrap())
            .into_script();

        let mut spent_builder = Builder::new()
            .push_opcode(all::OP_TOALTSTACK)
            .push_opcode(all::OP_TOALTSTACK);
        for _ in 0..35 {
            spent_builder = spent_builder
                .push_opcode(all::OP_FROMALTSTACK)
                .push_opcode(all::OP_FROMALTSTACK)
                .push_opcode(all::OP_2DUP)
                .push_opcode(all::OP_TOALTSTACK)
                .push_opcode(all::OP_TOALTSTACK)
                .push_opcode(all::OP_CHECKSIG)
                .push_opcode(all::OP_DROP);
        }
        let spent_script = spent_builder.push_opcode(all::OP_PUSHNUM_1).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("too many checksigs should exceed opcount budget");
        assert_eq!(failure.script_error, ScriptError::OpCount);
    }

    #[test]
    fn verify_minimalif_flag() {
        let condition = vec![2u8];
        let script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(condition.clone()).unwrap())
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_IF)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_ENDIF)
            .into_script();

        run_simple_script(script_sig.clone(), spent_script.clone()).expect("non minimal true ok");

        run_script_with_ctx_flags(
            script_sig,
            spent_script.clone(),
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_MINIMALIF,
        )
        .expect("MINIMALIF does not apply to legacy scripts");

        let witness_script = spent_script;
        let program = sha256::Hash::hash(witness_script.as_bytes());
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let witness = Witness::from(vec![condition, witness_script.as_bytes().to_vec()]);
        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            witness,
            Amount::from_sat(50_000),
            VERIFY_WITNESS | VERIFY_MINIMALIF,
        )
        .expect_err("non-minimal truthy witness branch rejected by MINIMALIF");
        assert_eq!(failure.script_error, ScriptError::MinimalIf);
    }

    #[test]
    fn verify_cleanstack_flag() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();

        run_simple_script(script_sig.clone(), spent_script.clone()).expect("extra stack elem ok");

        run_script_with_ctx_flags(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_CLEANSTACK,
        )
        .expect_err("cleanstack requires exactly one item");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_CLEANSTACK,
        )
        .expect_err("cleanstack detail");
        assert_eq!(failure.script_error, ScriptError::CleanStack);
    }

    #[test]
    fn verify_multisig_passes() {
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk1 = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk1);
        let pk2 = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk2);

        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_2)
            .push_slice(PushBytesBuf::try_from(pk1.serialize().to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(pk2.serialize().to_vec()).unwrap())
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();

        let tx = multisig_test_transaction();
        let sig1 = sign_input(&secp, &tx, &spent_script, &sk1);
        let sig2 = sign_input(&secp, &tx, &spent_script, &sk2);

        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(sig1).unwrap())
            .push_slice(PushBytesBuf::try_from(sig2).unwrap())
            .into_script();

        let mut tx = tx;
        tx.input[0].script_sig = script_sig;
        let tx_bytes = consensus::serialize(&tx);

        verify(spent_script.as_bytes(), 0, &tx_bytes, None, 0)
            .expect("2-of-2 multisig should validate");
    }

    #[test]
    fn verify_multisig_null_dummy_enforced() {
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[4u8; 32]).unwrap();
        let pk1 = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk1);
        let pk2 = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk2);

        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_2)
            .push_slice(PushBytesBuf::try_from(pk1.serialize().to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(pk2.serialize().to_vec()).unwrap())
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();

        let tx = multisig_test_transaction();
        let sig1 = sign_input(&secp, &tx, &spent_script, &sk1);
        let sig2 = sign_input(&secp, &tx, &spent_script, &sk2);

        let mut tx = tx;
        let good_script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(sig1.clone()).unwrap())
            .push_slice(PushBytesBuf::try_from(sig2.clone()).unwrap())
            .into_script();
        tx.input[0].script_sig = good_script_sig;
        let tx_bytes = consensus::serialize(&tx);
        verify(spent_script.as_bytes(), 0, &tx_bytes, None, 0)
            .expect("zero dummy should satisfy NULLDUMMY");

        let mut tx_bad = tx.clone();
        let bad_script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(vec![1]).unwrap())
            .push_slice(PushBytesBuf::try_from(sig1).unwrap())
            .push_slice(PushBytesBuf::try_from(sig2).unwrap())
            .into_script();
        tx_bad.input[0].script_sig = bad_script_sig;
        let tx_bad_bytes = consensus::serialize(&tx_bad);

        verify_with_flags(
            spent_script.as_bytes(),
            0,
            &tx_bad_bytes,
            None,
            0,
            VERIFY_ALL_PRE_TAPROOT,
        )
        .expect_err("non-zero dummy should fail under NULLDUMMY");

        let failure = verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bad_bytes,
            None,
            0,
            VERIFY_ALL_PRE_TAPROOT,
        )
        .expect_err("nulldummy detail");
        assert_eq!(failure.script_error, ScriptError::SigNullDummy);

        let relaxed_flags = VERIFY_ALL_PRE_TAPROOT & !VERIFY_NULLDUMMY;
        verify_with_flags(
            spent_script.as_bytes(),
            0,
            &tx_bad_bytes,
            None,
            0,
            relaxed_flags,
        )
        .expect("non-zero dummy passes when NULLDUMMY disabled");
    }

    #[test]
    fn verify_stack_size_limit_enforced() {
        let mut sig_builder = Builder::new();
        for _ in 0..=1000 {
            sig_builder = sig_builder.push_opcode(all::OP_PUSHNUM_1);
        }
        let script_sig = sig_builder.into_script();
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("stack overflows after too many pushes");
        assert_eq!(failure.script_error, ScriptError::StackSize);
    }

    #[test]
    fn verify_sig_count_error() {
        let mut script_sig = Builder::new().push_opcode(all::OP_PUSHBYTES_0);
        for _ in 0..2 {
            script_sig = script_sig.push_slice(PushBytesBuf::try_from(vec![0x01]).unwrap());
        }
        let script_sig = script_sig.into_script();

        let spent_script = Builder::new()
            .push_int(2)
            .push_slice(PushBytesBuf::try_from(vec![0x02]).unwrap())
            .push_int(1)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("n_sigs larger than n_keys rejected");
        assert_eq!(failure.script_error, ScriptError::SigCount);
    }

    #[test]
    fn verify_pubkey_count_error() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .into_script();
        let mut spent_builder = Builder::new().push_int(0);
        for _ in 0..21 {
            spent_builder = spent_builder.push_slice(PushBytesBuf::try_from(vec![0x03]).unwrap());
        }
        let spent_script = spent_builder
            .push_int(21)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("too many pubkeys cause PubkeyCount failure");
        assert_eq!(failure.script_error, ScriptError::PubkeyCount);
    }

    #[test]
    fn verify_nullfail_flag() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[5u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);

        let spent_script = Builder::new()
            .push_slice(PushBytesBuf::try_from(pk.serialize().to_vec()).unwrap())
            .push_opcode(all::OP_CHECKSIG)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();

        let mut tx = multisig_test_transaction();
        let mut sig = sign_input(&secp, &tx, &spent_script, &sk);
        corrupt_signature(sig.as_mut_slice());
        let script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(sig.clone()).unwrap())
            .into_script();
        tx.input[0].script_sig = script_sig;
        let tx_bytes = consensus::serialize(&tx);

        verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_NONE)
            .expect("script succeeds when invalid signature is dropped");

        verify_with_flags(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_NULLFAIL,
        )
        .expect_err("nullfail forbids ignoring failing signatures");

        let failure = verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_NULLFAIL,
        )
        .expect_err("nullfail detail");
        assert_eq!(failure.script_error, ScriptError::NullFail);
    }

    #[test]
    fn verify_nullfail_multisig_exhaustion() {
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[11u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[12u8; 32]).unwrap();
        let pk1 = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk1);
        let pk2 = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk2);

        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_2)
            .push_slice(PushBytesBuf::try_from(pk1.serialize().to_vec()).unwrap())
            .push_slice(PushBytesBuf::try_from(pk2.serialize().to_vec()).unwrap())
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_CHECKMULTISIG)
            .push_opcode(all::OP_NOT)
            .into_script();

        let tx = multisig_test_transaction();
        let mut bad_sig1 = sign_input(&secp, &tx, &spent_script, &sk1);
        corrupt_signature(bad_sig1.as_mut_slice());
        let mut bad_sig2 = sign_input(&secp, &tx, &spent_script, &sk2);
        corrupt_signature(bad_sig2.as_mut_slice());

        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(bad_sig1).unwrap())
            .push_slice(PushBytesBuf::try_from(bad_sig2).unwrap())
            .into_script();

        let mut tx = tx;
        tx.input[0].script_sig = script_sig;
        let tx_bytes = consensus::serialize(&tx);

        verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_NONE)
            .expect("CHECKMULTISIG failure is masked by NOT when NULLFAIL disabled");

        let failure = verify_with_flags_detailed(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_NULLFAIL,
        )
        .expect_err("NULLFAIL should trigger when failing non-empty multisig signatures remain");
        assert_eq!(failure.script_error, ScriptError::NullFail);
    }

    #[test]
    fn verify_op_return_sets_script_error() {
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spent_script = Builder::new().push_opcode(all::OP_RETURN).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("op_return halts execution");
        assert_eq!(failure.script_error, ScriptError::OpReturn);
    }

    #[test]
    fn verify_op_verify_sets_script_error() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .into_script();
        let spent_script = Builder::new().push_opcode(all::OP_VERIFY).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("op_verify fails");
        assert_eq!(failure.script_error, ScriptError::Verify);
    }

    #[test]
    fn verify_equalverify_sets_script_error() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_2)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_EQUALVERIFY)
            .into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("equalverify fails");
        assert_eq!(failure.script_error, ScriptError::EqualVerify);
    }

    #[test]
    fn verify_numequalverify_sets_script_error() {
        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_2)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_NUMEQUALVERIFY)
            .into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("numequalverify fails");
        assert_eq!(failure.script_error, ScriptError::NumEqualVerify);
    }

    #[test]
    fn verify_checksigverify_sets_script_error() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pk_bytes = pk.serialize().to_vec();

        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(pk_bytes).unwrap())
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_CHECKSIGVERIFY)
            .into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("checksigverify detects invalid signature");
        assert_eq!(failure.script_error, ScriptError::CheckSigVerify);
    }

    #[test]
    fn verify_checkmultisigverify_sets_script_error() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[10u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);

        let script_sig = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_opcode(all::OP_PUSHBYTES_0)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(pk.serialize().to_vec()).unwrap())
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_CHECKMULTISIGVERIFY)
            .into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("checkmultisigverify fails with empty signature");
        assert_eq!(failure.script_error, ScriptError::CheckMultiSigVerify);
    }

    #[test]
    fn verify_disabled_opcode_sets_script_error() {
        let script_sig = Builder::new().into_script();
        let spent_script = Builder::new().push_opcode(all::OP_CAT).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("disabled opcode should fail");
        assert_eq!(failure.script_error, ScriptError::DisabledOpcode);
    }

    #[test]
    fn verify_reserved_opcode_sets_script_error() {
        let script_sig = Builder::new().into_script();
        let spent_script = Builder::new().push_opcode(all::OP_VERIF).into_script();

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("reserved opcode should fail");
        assert_eq!(failure.script_error, ScriptError::BadOpcode);
    }

    #[test]
    fn verify_dersig_flag_enforced() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[6u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let spent_script = Builder::new()
            .push_slice(PushBytesBuf::try_from(pk.serialize().to_vec()).unwrap())
            .push_opcode(all::OP_CHECKSIG)
            .into_script();

        let mut tx = multisig_test_transaction();
        let mut sig = sign_input(&secp, &tx, &spent_script, &sk);
        malleate_signature_with_extra_zero(&mut sig);
        tx.input[0].script_sig = push_data_script(&sig);
        let tx_bytes = consensus::serialize(&tx);

        verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_NONE)
            .expect("non-DER signature accepted without DERSIG");

        verify_with_flags(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_DERSIG,
        )
        .expect_err("DER signatures required once DERSIG flag set");
    }

    #[test]
    fn verify_low_s_flag_enforced() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let spent_script = Builder::new()
            .push_slice(PushBytesBuf::try_from(pk.serialize().to_vec()).unwrap())
            .push_opcode(all::OP_CHECKSIG)
            .into_script();

        let mut tx = multisig_test_transaction();
        let sig = sign_input(&secp, &tx, &spent_script, &sk);
        let high_s = to_high_s_signature(&sig);
        tx.input[0].script_sig = push_data_script(&high_s);
        let tx_bytes = consensus::serialize(&tx);

        verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_NONE)
            .expect("high-S signature allowed when flag disabled");

        verify_with_flags(spent_script.as_bytes(), 0, &tx_bytes, None, 0, VERIFY_LOW_S)
            .expect_err("LOW_S rejects malleated signatures");
    }

    #[test]
    fn witness_pubkeytype_requires_compressed_keys() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[8u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let witness_script = Builder::new().push_opcode(all::OP_CHECKSIG).into_script();
        let witness_script_bytes = witness_script.as_bytes().to_vec();
        let program = sha256::Hash::hash(&witness_script_bytes);
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();

        let amount = Amount::from_sat(50_000);
        let base_tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: amount,
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let sig = sign_witness_input(&secp, &base_tx, &witness_script, amount, &sk);
        let compressed = pk.serialize().to_vec();
        let uncompressed = pk.serialize_uncompressed().to_vec();

        let mut tx_good = base_tx.clone();
        tx_good.input[0].witness =
            Witness::from(vec![sig.clone(), compressed, witness_script_bytes.clone()]);
        let tx_good_bytes = consensus::serialize(&tx_good);
        verify_with_flags(
            spent_script.as_bytes(),
            amount.to_sat(),
            &tx_good_bytes,
            None,
            0,
            VERIFY_WITNESS | VERIFY_WITNESS_PUBKEYTYPE,
        )
        .expect("compressed pubkey passes when WITNESS_PUBKEYTYPE is enforced");

        let mut tx_bad = base_tx;
        tx_bad.input[0].witness =
            Witness::from(vec![sig, uncompressed, witness_script_bytes.clone()]);
        let tx_bad_bytes = consensus::serialize(&tx_bad);
        verify_with_flags(
            spent_script.as_bytes(),
            amount.to_sat(),
            &tx_bad_bytes,
            None,
            0,
            VERIFY_WITNESS | VERIFY_WITNESS_PUBKEYTYPE,
        )
        .expect_err("uncompressed pubkey rejected when WITNESS_PUBKEYTYPE is enforced");
    }

    #[test]
    fn verify_witness_program_wrong_length() {
        let script_sig = Builder::new().into_script();
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(vec![0u8; 5]).unwrap())
            .into_script();

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            Witness::new(),
            Amount::from_sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("invalid witness length fails");
        assert_eq!(failure.script_error, ScriptError::WitnessProgramWrongLength);
    }

    #[test]
    fn verify_witness_program_witness_empty() {
        let script_sig = Builder::new().into_script();
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(vec![0u8; 32]).unwrap())
            .into_script();

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            Witness::new(),
            Amount::from_sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("missing witness stack fails");
        assert_eq!(
            failure.script_error,
            ScriptError::WitnessProgramWitnessEmpty
        );
    }

    #[test]
    fn verify_witness_program_mismatch_p2wsh() {
        let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let program = sha256::Hash::hash(witness_script.as_bytes());
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let wrong_script = Builder::new().push_opcode(all::OP_PUSHNUM_2).into_script();
        let witness = Witness::from(vec![wrong_script.as_bytes().to_vec()]);

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            witness,
            Amount::from_sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("p2wsh hash mismatch fails");
        assert_eq!(failure.script_error, ScriptError::WitnessProgramMismatch);
    }

    #[test]
    fn verify_witness_program_mismatch_p2wpkh() {
        let program = vec![0x11u8; 20];
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program).unwrap())
            .into_script();
        let witness = Witness::from(vec![vec![0x01]]);

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            witness,
            Amount::from_sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("p2wpkh requires two witness items");
        assert_eq!(failure.script_error, ScriptError::WitnessProgramMismatch);
    }

    #[test]
    fn verify_p2wsh_cleanstack_enforced() {
        let witness_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        let program = sha256::Hash::hash(witness_script.as_bytes());
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let witness = Witness::from(vec![witness_script.as_bytes().to_vec()]);

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            witness,
            Amount::from_sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("witness scripts must leave exactly one stack item");
        assert_eq!(failure.script_error, ScriptError::CleanStack);
    }

    #[test]
    fn verify_p2sh_p2wsh_cleanstack_enforced() {
        let witness_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        let program = sha256::Hash::hash(witness_script.as_bytes());
        let redeem_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let redeem_bytes = redeem_script.as_bytes().to_vec();
        let script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(redeem_bytes.clone()).unwrap())
            .into_script();
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_HASH160)
            .push_slice(
                PushBytesBuf::try_from(hash160::Hash::hash(&redeem_bytes).to_byte_array().to_vec())
                    .unwrap(),
            )
            .push_opcode(all::OP_EQUAL)
            .into_script();
        let witness = Witness::from(vec![witness_script.as_bytes().to_vec()]);

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            witness,
            Amount::from_sat(50_000),
            VERIFY_WITNESS | VERIFY_P2SH,
        )
        .expect_err("p2sh-wrapped witnesses must also leave a clean stack");
        assert_eq!(failure.script_error, ScriptError::CleanStack);
    }

    #[test]
    fn verify_witness_malleated_p2sh() {
        let inner_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let program = sha256::Hash::hash(inner_script.as_bytes());
        let redeem_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
        let script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(redeem_script.as_bytes().to_vec()).unwrap())
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        let witness = Witness::from(vec![inner_script.as_bytes().to_vec()]);

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            witness,
            Amount::from_sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("non-canonical redeem push fails");
        assert_eq!(failure.script_error, ScriptError::WitnessMalleatedP2SH);
    }

    #[test]
    fn verify_witness_malleated_bare() {
        let witness_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let program = sha256::Hash::hash(witness_script.as_bytes());
        let script_pubkey = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(PushBytesBuf::try_from(program.to_byte_array().to_vec()).unwrap())
            .into_script();
        let script_sig = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();

        let failure = run_witness_script_with_ctx(
            script_sig,
            script_pubkey,
            Witness::from(vec![witness_script.as_bytes().to_vec()]),
            Amount::from_sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("bare witness with scriptSig fails");
        assert_eq!(failure.script_error, ScriptError::WitnessMalleated);
    }

    #[test]
    fn verify_witness_unexpected_rejected() {
        let script_pubkey = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let witness = Witness::from(vec![vec![0x01]]);

        let failure = run_witness_script_with_ctx(
            Builder::new().into_script(),
            script_pubkey,
            witness,
            Amount::from_sat(50_000),
            VERIFY_WITNESS,
        )
        .expect_err("unexpected witness data fails");
        assert_eq!(failure.script_error, ScriptError::WitnessUnexpected);
    }

    #[test]
    fn spent_output_script_must_match() {
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let wrong_script = Builder::new().push_opcode(all::OP_PUSHNUM_2).into_script();
        let tx = multisig_test_transaction();
        let tx_bytes = consensus::serialize(&tx);

        let (storage, utxo) = make_utxo(&wrong_script, 0);
        let utxos = [utxo];
        let err = verify_with_flags(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            Some(&utxos),
            0,
            VERIFY_NONE,
        )
        .expect_err("mismatched spent output should fail");
        assert_eq!(err, Error::ERR_SPENT_OUTPUTS_MISMATCH);
        drop(storage);
    }

    #[test]
    fn witness_amount_inferred_from_spent_outputs() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pk_hash = hash160::Hash::hash(&pk.serialize());

        let program = PushBytesBuf::try_from(pk_hash.to_byte_array().to_vec()).unwrap();
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHBYTES_0)
            .push_slice(program)
            .into_script();

        let mut tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let script_code = Builder::new()
            .push_opcode(all::OP_DUP)
            .push_opcode(all::OP_HASH160)
            .push_slice(
                PushBytesBuf::try_from(pk_hash.to_byte_array().to_vec()).expect("pk hash push"),
            )
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_CHECKSIG)
            .into_script();
        let value = Amount::from_sat(75_000);
        let sig = sign_witness_input(&secp, &tx, &script_code, value, &sk);
        tx.input[0].witness = Witness::from(vec![sig, pk.serialize().to_vec()]);
        let tx_bytes = consensus::serialize(&tx);

        let (storage, utxo) = make_utxo(&spent_script, value.to_sat());
        let utxos = [utxo];
        verify_with_flags(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            Some(&utxos),
            0,
            VERIFY_WITNESS,
        )
        .expect("prevout amount inferred from spent outputs");
        drop(storage);
    }

    #[test]
    fn taproot_flag_requires_prevouts() {
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let tx = multisig_test_transaction();
        let tx_bytes = consensus::serialize(&tx);
        let err = verify_with_flags(
            spent_script.as_bytes(),
            0,
            &tx_bytes,
            None,
            0,
            VERIFY_TAPROOT,
        )
        .expect_err("taproot without prevouts should fail");
        assert_eq!(err, Error::ERR_SPENT_OUTPUTS_REQUIRED);
    }

    #[test]
    fn taproot_script_path_succeeds() {
        let script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let (spent_script, witness) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script, Vec::new(), false);
        run_taproot_verification(spent_script, witness, VERIFY_TAPROOT | VERIFY_CLEANSTACK)
            .expect("basic tapscript executes");
    }

    #[test]
    fn taproot_annex_is_hashed() {
        let script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let (spent_script, witness) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script, Vec::new(), true);
        run_taproot_verification(spent_script, witness, VERIFY_TAPROOT)
            .expect("annex-bearing witness allowed");
    }

    #[test]
    fn taproot_control_length_checked() {
        let script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let (spent_script, witness) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script, Vec::new(), false);
        let mut items: Vec<Vec<u8>> = witness.iter().map(|elem| elem.to_vec()).collect();
        let control = items.last_mut().expect("control present");
        control.pop();
        let malformed = Witness::from(items);
        let err = run_taproot_verification(spent_script, malformed, VERIFY_TAPROOT)
            .expect_err("invalid control size rejected");
        assert_eq!(err, ScriptError::TaprootWrongControlSize);
    }

    #[test]
    fn taproot_future_leaf_discouraged() {
        let future_version = TAPROOT_LEAF_TAPSCRIPT.wrapping_add(2);
        let script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let (spent_script, witness) =
            taproot_script_fixture(future_version, script, Vec::new(), false);
        run_taproot_verification(spent_script.clone(), witness.clone(), VERIFY_TAPROOT)
            .expect("future tapscript allowed when flag disabled");
        let err = run_taproot_verification(
            spent_script,
            witness,
            VERIFY_TAPROOT | VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
        )
        .expect_err("discourage flag should reject future leaf");
        assert_eq!(err, ScriptError::DiscourageUpgradableTaprootVersion);
    }

    #[test]
    fn taproot_empty_witness_rejected() {
        let script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let (spent_script, _witness) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script, Vec::new(), false);
        let err = run_taproot_verification(spent_script, Witness::new(), VERIFY_TAPROOT)
            .expect_err("empty taproot witness fails");
        assert_eq!(err, ScriptError::WitnessProgramWitnessEmpty);
    }

    #[test]
    fn taproot_checksig_verifies() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[21u8; 32]).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        let script = Builder::new().push_opcode(all::OP_CHECKSIG).into_script();
        let (spent_script, template) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script.clone(), Vec::new(), false);
        let amount = Amount::from_sat(50_000);
        let sig = sign_tapscript_spend(&secp, &keypair, &script, &spent_script, amount);
        let witness =
            taproot_witness_from_template(vec![sig, xonly.serialize().to_vec()], &template);
        run_taproot_verification(spent_script, witness, VERIFY_TAPROOT | VERIFY_CLEANSTACK)
            .expect("valid tapscript signature executes");
    }

    #[test]
    fn taproot_checksig_invalid_signature_fails_without_nullfail() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[22u8; 32]).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        let script = Builder::new().push_opcode(all::OP_CHECKSIG).into_script();
        let (spent_script, template) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script.clone(), Vec::new(), false);
        let amount = Amount::from_sat(50_000);
        let mut sig = sign_tapscript_spend(&secp, &keypair, &script, &spent_script, amount);
        sig[0] ^= 0x01;
        let witness =
            taproot_witness_from_template(vec![sig, xonly.serialize().to_vec()], &template);
        let err = run_taproot_verification(
            spent_script,
            witness,
            VERIFY_TAPROOT | VERIFY_CLEANSTACK | VERIFY_NULLFAIL,
        )
        .expect_err("invalid signature rejected");
        assert_eq!(err, ScriptError::EvalFalse);
    }

    #[test]
    fn taproot_checksigadd_succeeds() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[23u8; 32]).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        let script = Builder::new()
            .push_int(0)
            .push_opcode(all::OP_SWAP)
            .push_opcode(all::OP_CHECKSIGADD)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_EQUAL)
            .into_script();
        let (spent_script, template) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script.clone(), Vec::new(), false);
        let amount = Amount::from_sat(50_000);
        let sig = sign_tapscript_spend(&secp, &keypair, &script, &spent_script, amount);
        let witness =
            taproot_witness_from_template(vec![sig, xonly.serialize().to_vec()], &template);
        run_taproot_verification(spent_script, witness, VERIFY_TAPROOT | VERIFY_CLEANSTACK)
            .expect("CHECKSIGADD satisfied");
    }

    #[test]
    fn taproot_checksigadd_with_invalid_signature_fails() {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[24u8; 32]).unwrap();
        let (xonly, _) = keypair.x_only_public_key();
        let script = Builder::new()
            .push_int(0)
            .push_opcode(all::OP_SWAP)
            .push_opcode(all::OP_CHECKSIGADD)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_EQUAL)
            .into_script();
        let (spent_script, template) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script, Vec::new(), false);
        let witness =
            taproot_witness_from_template(vec![Vec::new(), xonly.serialize().to_vec()], &template);
        let err = run_taproot_verification(
            spent_script,
            witness,
            VERIFY_TAPROOT | VERIFY_CLEANSTACK | VERIFY_NULLFAIL,
        )
        .expect_err("empty signature rejected");
        assert_eq!(err, ScriptError::EvalFalse);
    }

    #[test]
    fn taproot_multi_a_checksigadd_pattern() {
        let secp = Secp256k1::new();
        let secrets = [[25u8; 32], [26u8; 32], [27u8; 32]];
        let mut builder = Builder::new();
        // Mirror Bitcoin Core's multi_a descriptor script:
        // key0 CHECKSIG, subsequent keys CHECKSIGADD, final threshold via NUMEQUAL.
        for (index, secret) in secrets.iter().enumerate() {
            let keypair = Keypair::from_seckey_slice(&secp, secret).unwrap();
            let (xonly, _) = keypair.x_only_public_key();
            let push = PushBytesBuf::try_from(xonly.serialize().to_vec()).unwrap();
            builder = builder.push_slice(push);
            if index == 0 {
                builder = builder.push_opcode(all::OP_CHECKSIG);
            } else {
                builder = builder.push_opcode(all::OP_CHECKSIGADD);
            }
        }
        builder = builder.push_int(2).push_opcode(all::OP_NUMEQUAL);
        let script = builder.into_script();
        let (spent_script, template) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script.clone(), Vec::new(), false);
        let amount = Amount::from_sat(50_000);
        let signatures: Vec<Vec<u8>> = secrets
            .iter()
            .map(|secret| {
                let keypair = Keypair::from_seckey_slice(&secp, secret).unwrap();
                sign_tapscript_spend(&secp, &keypair, &script, &spent_script, amount)
            })
            .collect();

        let satisfied_stack = vec![signatures[2].clone(), Vec::new(), signatures[0].clone()];
        let witness = taproot_witness_from_template(satisfied_stack, &template);
        run_taproot_verification(
            spent_script.clone(),
            witness,
            VERIFY_TAPROOT | VERIFY_CLEANSTACK,
        )
        .expect("2-of-3 CHECKSIGADD pattern matches Core's multi_a flow");

        let unsatisfied_stack = vec![Vec::new(), Vec::new(), signatures[0].clone()];
        let witness = taproot_witness_from_template(unsatisfied_stack, &template);
        let err =
            run_taproot_verification(spent_script, witness, VERIFY_TAPROOT | VERIFY_CLEANSTACK)
                .expect_err("threshold unmet should fail");
        assert_eq!(err, ScriptError::EvalFalse);
    }

    #[test]
    fn taproot_op_success_short_circuits() {
        let script = ScriptBuf::from_bytes(vec![0x50]);
        let (spent_script, template) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script, Vec::new(), false);
        let witness = taproot_witness_from_template(vec![vec![0x01]], &template);
        run_taproot_verification(spent_script, witness, VERIFY_TAPROOT)
            .expect("op_success short-circuits execution");
    }

    #[test]
    fn taproot_op_success_discouraged_errors() {
        let script = ScriptBuf::from_bytes(vec![0x50]);
        let (spent_script, template) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script, Vec::new(), false);
        let witness = taproot_witness_from_template(vec![vec![0x01]], &template);
        let err = run_taproot_verification(
            spent_script,
            witness,
            VERIFY_TAPROOT | VERIFY_DISCOURAGE_OP_SUCCESS,
        )
        .expect_err("discourage op_success flag should fail");
        assert_eq!(err, ScriptError::DiscourageOpSuccess);
    }

    #[test]
    fn taproot_checkmultisig_disallowed() {
        let script = Builder::new()
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();
        let (spent_script, template) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script, Vec::new(), false);
        let witness = taproot_witness_from_template(Vec::new(), &template);
        let err = run_taproot_verification(spent_script, witness, VERIFY_TAPROOT)
            .expect_err("tapscript CHECKMULTISIG is forbidden");
        assert_eq!(err, ScriptError::TapscriptCheckMultiSig);
    }

    #[test]
    fn taproot_minimal_if_enforced_without_flag() {
        let script = Builder::new()
            .push_slice(PushBytesBuf::try_from(vec![0x02]).unwrap())
            .push_opcode(all::OP_IF)
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_ENDIF)
            .into_script();
        let (spent_script, template) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script, Vec::new(), false);
        let witness = taproot_witness_from_template(Vec::new(), &template);
        let err = run_taproot_verification(spent_script, witness, VERIFY_TAPROOT)
            .expect_err("tapscript enforces minimal-if regardless of flags");
        assert_eq!(err, ScriptError::MinimalIf);
    }

    #[test]
    fn taproot_discourage_upgradable_pubkeytype() {
        let script = Builder::new().push_opcode(all::OP_CHECKSIG).into_script();
        let (spent_script, template) =
            taproot_script_fixture(TAPROOT_LEAF_TAPSCRIPT, script, Vec::new(), false);
        let sig = vec![0x01];
        let stack_items = vec![sig.clone(), vec![0x02; 33]];
        let witness = taproot_witness_from_template(stack_items, &template);
        run_taproot_verification(spent_script.clone(), witness.clone(), VERIFY_TAPROOT)
            .expect("unknown pubkey type permitted without flag");
        let err = run_taproot_verification(
            spent_script,
            witness,
            VERIFY_TAPROOT | VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
        )
        .expect_err("discourage flag rejects unknown pubkey version");
        assert_eq!(err, ScriptError::DiscourageUpgradablePubkeyType);
    }

    fn taproot_script_fixture(
        leaf_version: u8,
        script: ScriptBuf,
        mut stack_items: Vec<Vec<u8>>,
        include_annex: bool,
    ) -> (ScriptBuf, Witness) {
        let internal_key_bytes =
            Vec::from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .expect("generator x");
        let internal_key = UntweakedPublicKey::from_slice(&internal_key_bytes).unwrap();
        let secp = Secp256k1::verification_only();

        let mut engine = TapLeafHash::engine();
        engine.input(&[leaf_version]);
        script
            .consensus_encode(&mut engine)
            .expect("script serialize");
        let tapleaf_hash = TapLeafHash::from_engine(engine);
        let merkle_root = TapNodeHash::from(tapleaf_hash);
        let (tweaked, parity) = internal_key.tap_tweak(&secp, Some(merkle_root));
        let parity_bit = match parity {
            Parity::Even => 0,
            Parity::Odd => 1,
        };

        let mut control = Vec::with_capacity(33);
        control.push(leaf_version | parity_bit);
        control.extend_from_slice(&internal_key.serialize());

        stack_items.push(script.as_bytes().to_vec());
        stack_items.push(control);
        if include_annex {
            stack_items.push(vec![TAPROOT_ANNEX_PREFIX, 0x01]);
        }
        let witness = Witness::from(stack_items);

        let program = tweaked.to_x_only_public_key().serialize();
        let program_push = PushBytesBuf::try_from(program.to_vec()).unwrap();
        let spent_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(program_push)
            .into_script();

        (spent_script, witness)
    }

    fn tapscript_leaf_hash(script: &ScriptBuf, leaf_version: u8) -> TapLeafHash {
        let mut engine = TapLeafHash::engine();
        engine.input(&[leaf_version]);
        script
            .consensus_encode(&mut engine)
            .expect("script serialization");
        TapLeafHash::from_engine(engine)
    }

    fn taproot_witness_from_template(mut stack_items: Vec<Vec<u8>>, template: &Witness) -> Witness {
        let mut items: Vec<Vec<u8>> = template.iter().map(|elem| elem.to_vec()).collect();
        let annex = if let Some(last) = items.last() {
            if !last.is_empty() && last[0] == TAPROOT_ANNEX_PREFIX {
                Some(items.pop().expect("annex present"))
            } else {
                None
            }
        } else {
            None
        };
        let control = items.pop().expect("control block");
        let script_bytes = items.pop().expect("witness script");
        assert!(items.is_empty(), "template should not contain stack items");
        stack_items.push(script_bytes);
        stack_items.push(control);
        if let Some(annex_bytes) = annex {
            stack_items.push(annex_bytes);
        }
        Witness::from(stack_items)
    }

    fn taproot_test_transaction(amount: Amount) -> Transaction {
        Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: amount,
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn sign_tapscript_spend(
        secp: &Secp256k1<secp256k1::All>,
        keypair: &Keypair,
        script: &ScriptBuf,
        spent_script: &ScriptBuf,
        amount: Amount,
    ) -> Vec<u8> {
        let tapleaf_hash = tapscript_leaf_hash(script, TAPROOT_LEAF_TAPSCRIPT);
        let tx = taproot_test_transaction(amount);
        let mut cache = SighashCache::new(&tx);
        let prevout = TxOut {
            value: amount,
            script_pubkey: spent_script.clone(),
        };
        let prevouts = vec![prevout];
        let sighash = cache
            .taproot_signature_hash(
                0,
                &Prevouts::All(prevouts.as_slice()),
                None,
                Some((tapleaf_hash, u32::MAX)),
                TapSighashType::Default,
            )
            .expect("taproot sighash");
        let message = Message::from(sighash);
        let signature = secp.sign_schnorr_no_aux_rand(&message, keypair);
        signature.as_ref().to_vec()
    }

    fn run_taproot_verification(
        spent_script: ScriptBuf,
        witness: Witness,
        flags: u32,
    ) -> Result<(), ScriptError> {
        let amount = Amount::from_sat(50_000);
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: amount,
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let tx_bytes = consensus::serialize(&tx);
        let tx_ctx = TransactionContext::parse(&tx_bytes).unwrap();
        let script_storage = spent_script.as_bytes().to_vec();
        let utxo = Utxo {
            script_pubkey: script_storage.as_ptr(),
            script_pubkey_len: script_storage.len() as u32,
            value: amount.to_sat() as i64,
        };
        let utxos = [utxo];
        let spent_outputs = SpentOutputs::new(1, &utxos).unwrap();
        let script_flags = ScriptFlags::from_bits(flags).unwrap();
        let precomputed = tx_ctx.build_precomputed(Some(&spent_outputs), false);
        let spend_context = SpendContext::new(
            spent_script.as_bytes(),
            Some(spent_outputs),
            amount.to_sat(),
            true,
        );
        let mut interpreter =
            Interpreter::new(&tx_ctx, precomputed, 0, spend_context, script_flags).unwrap();

        match interpreter.verify() {
            Ok(()) => Ok(()),
            Err(Error::ERR_SCRIPT) => Err(interpreter.last_script_error()),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_codesep_affects_sighash() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pk_bytes = pk.serialize();

        let script_code = Builder::new()
            .push_slice(PushBytesBuf::try_from(pk_bytes.to_vec()).unwrap())
            .push_opcode(all::OP_CHECKSIG)
            .into_script();
        let spent_script = Builder::new()
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_CODESEPARATOR)
            .push_slice(PushBytesBuf::try_from(pk_bytes.to_vec()).unwrap())
            .push_opcode(all::OP_CHECKSIG)
            .into_script();

        let mut tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let sighash = SighashCache::new(&tx)
            .legacy_signature_hash(0, &script_code, EcdsaSighashType::All.to_u32())
            .expect("legacy sighash");
        let message = Message::from_digest_slice(&sighash[..]).expect("hash to message");
        let sig = secp.sign_ecdsa(&message, &sk);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);
        let script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(sig_bytes).unwrap())
            .push_slice(PushBytesBuf::try_from(vec![0x01]).unwrap())
            .into_script();
        tx.input[0].script_sig = script_sig;

        let tx_bytes = consensus::serialize(&tx);
        verify(spent_script.as_bytes(), 0, &tx_bytes, None, 0)
            .expect("codesep-adjusted signature verifies");
    }

    #[test]
    fn verify_checklocktimeverify_passes_and_fails() {
        let lock_height = 1000i64;
        let script_sig = Builder::new().into_script();
        let spent_script = Builder::new()
            .push_int(lock_height)
            .push_opcode(all::OP_CLTV)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();

        run_script_with_ctx(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::from_height((lock_height as u32) + 1).unwrap(),
            Sequence::ZERO,
        )
        .expect("locktime met");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::from_height((lock_height as u32) - 1).unwrap(),
            Sequence::ZERO,
            VERIFY_ALL_PRE_TAPROOT,
        )
        .expect_err("locktime unmet");
        assert_eq!(failure.script_error, ScriptError::UnsatisfiedLockTime);

        let negative_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_NEG1)
            .push_opcode(all::OP_CLTV)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        let negative = run_script_with_ctx_flags_detailed(
            Builder::new().into_script(),
            negative_script,
            LockTime::from_height(lock_height as u32).unwrap(),
            Sequence::ZERO,
            VERIFY_ALL_PRE_TAPROOT,
        )
        .expect_err("negative locktime rejected");
        assert_eq!(negative.script_error, ScriptError::NegativeLockTime);
    }

    #[test]
    fn verify_checksequenceverify_passes_and_fails() {
        let relative = 5i64;
        let script_sig = Builder::new().into_script();
        let spent_script = Builder::new()
            .push_int(relative)
            .push_opcode(all::OP_CSV)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();

        run_script_with_ctx(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence(relative as u32),
        )
        .expect("csv satisfied");

        let failure = run_script_with_ctx_flags_detailed(
            script_sig.clone(),
            spent_script.clone(),
            LockTime::ZERO,
            Sequence((relative - 1) as u32),
            VERIFY_ALL_PRE_TAPROOT,
        )
        .expect_err("csv unmet");
        assert_eq!(failure.script_error, ScriptError::UnsatisfiedLockTime);

        let negative_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_NEG1)
            .push_opcode(all::OP_CSV)
            .push_opcode(all::OP_DROP)
            .push_opcode(all::OP_PUSHNUM_1)
            .into_script();
        let negative = run_script_with_ctx_flags_detailed(
            Builder::new().into_script(),
            negative_script,
            LockTime::ZERO,
            Sequence::ZERO,
            VERIFY_ALL_PRE_TAPROOT,
        )
        .expect_err("negative relative locktime rejected");
        assert_eq!(negative.script_error, ScriptError::NegativeLockTime);
    }

    #[test]
    fn verify_script_size_limit_enforced() {
        let script_sig = Builder::new().into_script();
        let oversized = vec![all::OP_NOP.to_u8(); 10_001];
        let spent_script = ScriptBuf::from_bytes(oversized);
        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("scripts larger than 10k bytes rejected");
        assert_eq!(failure.script_error, ScriptError::ScriptSize);
    }

    #[test]
    fn verify_push_size_limit_enforced() {
        let script_sig = Builder::new().into_script();
        let mut script_bytes = Vec::new();
        script_bytes.push(all::OP_PUSHDATA2.to_u8());
        let push_len: u16 = 521;
        script_bytes.push((push_len & 0xff) as u8);
        script_bytes.push((push_len >> 8) as u8);
        script_bytes.extend(vec![0u8; push_len as usize]);
        let spent_script = ScriptBuf::from_bytes(script_bytes);

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("pushes over 520 bytes rejected");
        assert_eq!(failure.script_error, ScriptError::PushSize);
    }

    #[test]
    fn verify_opcode_count_limit_enforced() {
        let script_sig = Builder::new().into_script();
        let mut script_bytes = Vec::new();
        script_bytes.extend(vec![all::OP_NOP.to_u8(); 202]);
        let spent_script = ScriptBuf::from_bytes(script_bytes);

        let failure = run_script_with_ctx_flags_detailed(
            script_sig,
            spent_script,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
        .expect_err("scripts exceeding opcount limit rejected");
        assert_eq!(failure.script_error, ScriptError::OpCount);
    }

    fn push_data_script(data: &[u8]) -> ScriptBuf {
        let push = PushBytesBuf::try_from(data.to_vec()).unwrap();
        Builder::new().push_slice(push).into_script()
    }

    fn malleate_signature_with_extra_zero(sig: &mut Vec<u8>) {
        assert!(!sig.is_empty() && sig[0] == 0x30);
        let total_len = sig[1];
        let r_len = sig[3];
        sig.insert(4, 0x00);
        sig[3] = r_len + 1;
        sig[1] = total_len + 1;
    }

    fn to_high_s_signature(sig: &[u8]) -> Vec<u8> {
        let sighash = *sig.last().expect("signature has hashtype");
        let der = &sig[..sig.len() - 1];
        let signature = EcdsaSignature::from_der(der).expect("valid DER signature");
        let mut compact = signature.serialize_compact();
        let mut s = [0u8; 32];
        s.copy_from_slice(&compact[32..]);
        let high_s = sub_scalar(&constants::CURVE_ORDER, &s);
        compact[32..].copy_from_slice(&high_s);
        let high_sig = EcdsaSignature::from_compact(&compact).expect("compact signature");
        let mut out = high_sig.serialize_der().to_vec();
        out.push(sighash);
        out
    }

    fn sub_scalar(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut value = a[i] as i16 - b[i] as i16 - borrow;
            if value < 0 {
                value += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i] = value as u8;
        }
        result
    }

    fn run_simple_script(script_sig: ScriptBuf, script_pubkey: ScriptBuf) -> Result<(), Error> {
        run_script_with_ctx_flags(
            script_sig,
            script_pubkey,
            LockTime::ZERO,
            Sequence::MAX,
            VERIFY_NONE,
        )
    }

    fn run_script_with_ctx(
        script_sig: ScriptBuf,
        script_pubkey: ScriptBuf,
        lock_time: LockTime,
        sequence: Sequence,
    ) -> Result<(), Error> {
        run_script_with_ctx_flags(
            script_sig,
            script_pubkey,
            lock_time,
            sequence,
            VERIFY_ALL_PRE_TAPROOT,
        )
    }

    fn run_script_with_ctx_flags(
        script_sig: ScriptBuf,
        script_pubkey: ScriptBuf,
        lock_time: LockTime,
        sequence: Sequence,
        flags: u32,
    ) -> Result<(), Error> {
        run_script_with_ctx_flags_detailed(script_sig, script_pubkey, lock_time, sequence, flags)
            .map_err(|failure| failure.error)
    }

    fn run_script_with_ctx_flags_detailed(
        script_sig: ScriptBuf,
        script_pubkey: ScriptBuf,
        lock_time: LockTime,
        sequence: Sequence,
        flags: u32,
    ) -> Result<(), ScriptFailure> {
        let tx = Transaction {
            version: Version(2),
            lock_time,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig,
                sequence,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let tx_bytes = consensus::serialize(&tx);
        verify_with_flags_detailed(script_pubkey.as_bytes(), 0, &tx_bytes, None, 0, flags)
    }

    fn run_witness_script_with_ctx(
        script_sig: ScriptBuf,
        script_pubkey: ScriptBuf,
        witness: Witness,
        amount: Amount,
        flags: u32,
    ) -> Result<(), ScriptFailure> {
        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig,
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: amount,
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let tx_bytes = consensus::serialize(&tx);
        verify_with_flags_detailed(
            script_pubkey.as_bytes(),
            amount.to_sat(),
            &tx_bytes,
            None,
            0,
            flags,
        )
    }

    fn multisig_test_transaction() -> Transaction {
        Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn sign_input(
        secp: &Secp256k1<secp256k1::All>,
        tx: &Transaction,
        script: &ScriptBuf,
        sk: &SecretKey,
    ) -> Vec<u8> {
        let cache = SighashCache::new(tx);
        let sighash = cache
            .legacy_signature_hash(0, script, EcdsaSighashType::All.to_u32())
            .expect("sighash");
        let message = Message::from_digest_slice(&sighash[..]).expect("hash to message");
        let sig = secp.sign_ecdsa(&message, sk);
        let mut bytes = sig.serialize_der().to_vec();
        bytes.push(EcdsaSighashType::All.to_u32() as u8);
        bytes
    }

    fn sign_witness_input(
        secp: &Secp256k1<secp256k1::All>,
        tx: &Transaction,
        script: &ScriptBuf,
        amount: Amount,
        sk: &SecretKey,
    ) -> Vec<u8> {
        let mut cache = SighashCache::new(tx);
        let mut engine = SegwitV0Sighash::engine();
        cache
            .segwit_v0_encode_signing_data_to(&mut engine, 0, script, amount, EcdsaSighashType::All)
            .expect("segwit sighash");
        let sighash = SegwitV0Sighash::from_engine(engine);
        let message = Message::from_digest_slice(&sighash[..]).expect("hash to message");
        let sig = secp.sign_ecdsa(&message, sk);
        let mut bytes = sig.serialize_der().to_vec();
        bytes.push(EcdsaSighashType::All.to_u32() as u8);
        bytes
    }

    fn corrupt_signature(sig: &mut [u8]) {
        if sig.len() > 3 {
            let idx = sig.len() - 3;
            sig[idx] ^= 0x01;
        }
    }

    fn make_utxo(script: &ScriptBuf, value: u64) -> (Vec<u8>, Utxo) {
        let bytes = script.as_bytes().to_vec();
        let utxo = Utxo {
            script_pubkey: bytes.as_ptr(),
            script_pubkey_len: bytes.len() as u32,
            value: value as i64,
        };
        (bytes, utxo)
    }
}
