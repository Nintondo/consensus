//! Transaction parsing and data preparation utilities.
//!
//! The Bitcoin Core implementation relies on `PrecomputedTransactionData` together with the full
//! set of spent outputs to evaluate signatures.  This module mirrors the same structures so that we
//! can incrementally port the interpreter logic without deviating from upstream semantics.

use core::slice;

use bitcoin::{
    consensus,
    hashes::{sha256, sha256d, Hash, HashEngine},
    opcodes::all::OP_PUSHNUM_1,
    script::ScriptBuf,
    Amount, Script, Transaction, TxOut,
};

use crate::{Error, Utxo};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Holds the parsed transaction along with auxiliary data needed during script verification.
#[derive(Debug, Clone)]
pub struct TransactionContext {
    tx: Transaction,
}

impl TransactionContext {
    /// Parses a transaction from wire bytes and reserializes it to guarantee canonical encoding.
    pub fn parse(tx_bytes: &[u8]) -> Result<Self, Error> {
        let tx: Transaction =
            consensus::deserialize(tx_bytes).map_err(|_| Error::ERR_TX_DESERIALIZE)?;

        let canonical = consensus::serialize(&tx);
        if canonical.len() != tx_bytes.len() {
            return Err(Error::ERR_TX_SIZE_MISMATCH);
        }

        Ok(Self { tx })
    }

    /// Returns the fully parsed transaction.
    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    /// Ensures `input_index` points to an existing transaction input.
    pub fn ensure_input_index(&self, input_index: usize) -> Result<(), Error> {
        if input_index >= self.tx.input.len() {
            Err(Error::ERR_TX_INDEX)
        } else {
            Ok(())
        }
    }

    /// Builds the precomputed data cache required for signature hashing.
    pub fn build_precomputed(
        &self,
        spent_outputs: Option<&SpentOutputs>,
        force: bool,
    ) -> PrecomputedTransactionData {
        PrecomputedTransactionData::new(&self.tx, spent_outputs, force)
    }
}

/// Owns the set of UTXOs referenced by a transaction when Taproot verification is required.
#[derive(Debug, Clone)]
pub struct SpentOutputs {
    txouts: Vec<TxOut>,
}

impl SpentOutputs {
    pub fn new(expected: usize, raw: &[Utxo]) -> Result<Self, Error> {
        if raw.len() != expected {
            return Err(Error::ERR_SPENT_OUTPUTS_MISMATCH);
        }

        let mut txouts = Vec::with_capacity(raw.len());
        for utxo in raw {
            if utxo.value < 0 {
                return Err(Error::ERR_AMOUNT_REQUIRED);
            }

            if utxo.script_pubkey_len == 0 && utxo.script_pubkey.is_null() {
                txouts.push(TxOut {
                    value: Amount::from_sat(utxo.value as u64),
                    script_pubkey: ScriptBuf::new(),
                });
                continue;
            }

            if utxo.script_pubkey.is_null() {
                return Err(Error::ERR_TX_DESERIALIZE);
            }

            let script_bytes = unsafe {
                slice::from_raw_parts(utxo.script_pubkey, utxo.script_pubkey_len as usize)
            };
            let script = ScriptBuf::from_bytes(script_bytes.to_vec());

            txouts.push(TxOut {
                value: Amount::from_sat(utxo.value as u64),
                script_pubkey: script,
            });
        }

        Ok(Self { txouts })
    }

    pub fn txouts(&self) -> &[TxOut] {
        &self.txouts
    }
}

/// Mirrors Bitcoin Core's `PrecomputedTransactionData`.
#[derive(Debug, Clone, Default)]
pub struct PrecomputedTransactionData {
    pub prevouts_single_hash: Option<sha256::Hash>,
    pub sequences_single_hash: Option<sha256::Hash>,
    pub outputs_single_hash: Option<sha256::Hash>,
    pub spent_amounts_single_hash: Option<sha256::Hash>,
    pub spent_scripts_single_hash: Option<sha256::Hash>,
    pub hash_prevouts: Option<sha256d::Hash>,
    pub hash_sequence: Option<sha256d::Hash>,
    pub hash_outputs: Option<sha256d::Hash>,
    pub bip143_segwit_ready: bool,
    pub bip341_taproot_ready: bool,
}

impl PrecomputedTransactionData {
    pub fn new(
        tx: &Transaction,
        spent_outputs: Option<&SpentOutputs>,
        force: bool,
    ) -> PrecomputedTransactionData {
        let mut data = PrecomputedTransactionData::default();

        let (mut uses_bip143, mut uses_bip341) = (force, force);

        for (idx, input) in tx.input.iter().enumerate() {
            if input.witness.is_empty() {
                continue;
            }

            if let Some(spent) = spent_outputs {
                if is_native_taproot(&spent.txouts[idx].script_pubkey) {
                    uses_bip341 = true;
                } else {
                    uses_bip143 = true;
                }
            } else {
                uses_bip143 = true;
            }

            if uses_bip143 && uses_bip341 {
                break;
            }
        }

        if uses_bip143 || uses_bip341 {
            let prevouts = hash_prevouts_single(tx);
            let sequences = hash_sequences_single(tx);
            let outputs = hash_outputs_single(tx);
            data.prevouts_single_hash = Some(prevouts);
            data.sequences_single_hash = Some(sequences);
            data.outputs_single_hash = Some(outputs);
        }

        if uses_bip143 {
            data.hash_prevouts = data.prevouts_single_hash.map(double_sha);
            data.hash_sequence = data.sequences_single_hash.map(double_sha);
            data.hash_outputs = data.outputs_single_hash.map(double_sha);
            data.bip143_segwit_ready = true;
        }

        if uses_bip341 {
            if let Some(spent) = spent_outputs {
                data.spent_amounts_single_hash = Some(hash_spent_amounts_single(spent));
                data.spent_scripts_single_hash = Some(hash_spent_scripts_single(spent));
                data.bip341_taproot_ready = true;
            }
        }

        data
    }
}

fn double_sha(hash: sha256::Hash) -> sha256d::Hash {
    sha256d::Hash::hash(&hash.to_byte_array())
}

fn hash_prevouts_single(tx: &Transaction) -> sha256::Hash {
    hash_serialized(tx.input.iter().map(|input| &input.previous_output))
}

fn hash_sequences_single(tx: &Transaction) -> sha256::Hash {
    hash_serialized(tx.input.iter().map(|input| &input.sequence))
}

fn hash_outputs_single(tx: &Transaction) -> sha256::Hash {
    hash_serialized(tx.output.iter())
}

fn hash_spent_amounts_single(spent: &SpentOutputs) -> sha256::Hash {
    let mut engine = sha256::Hash::engine();
    for txout in spent.txouts() {
        let value = txout.value.to_sat() as i64;
        engine.input(&consensus::serialize(&value));
    }
    sha256::Hash::from_engine(engine)
}

fn hash_spent_scripts_single(spent: &SpentOutputs) -> sha256::Hash {
    hash_serialized(spent.txouts().iter().map(|txout| &txout.script_pubkey))
}

fn hash_serialized<'a, I, T>(items: I) -> sha256::Hash
where
    I: IntoIterator<Item = &'a T>,
    T: consensus::Encodable + 'a,
{
    let mut engine = sha256::Hash::engine();
    for item in items {
        engine.input(&consensus::serialize(item));
    }
    sha256::Hash::from_engine(engine)
}

fn is_native_taproot(script: &Script) -> bool {
    script.as_bytes().len() == 34 && script.as_bytes()[0] == OP_PUSHNUM_1.to_u8()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Utxo;
    use bitcoin::{
        blockdata::script::{Builder, PushBytesBuf},
        opcodes::all,
        transaction::Version,
        Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness,
    };

    #[test]
    fn parses_transaction_and_detects_hashes() {
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(42),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let encoded = consensus::serialize(&tx);
        let ctx = TransactionContext::parse(&encoded).expect("valid tx");

        assert_eq!(ctx.tx().compute_txid(), tx.compute_txid());

        let pre = ctx.build_precomputed(None, true);
        assert!(pre.hash_prevouts.is_some());
        assert!(pre.hash_sequence.is_some());
        assert!(pre.hash_outputs.is_some());
    }

    #[test]
    fn spent_outputs_conversion() {
        let script = [0x51u8; 34];
        let utxo = Utxo {
            script_pubkey: script.as_ptr(),
            script_pubkey_len: script.len() as u32,
            value: 10,
        };

        let spent = SpentOutputs::new(1, &[utxo]).expect("valid spent outputs");
        assert_eq!(spent.txouts().len(), 1);
        assert_eq!(spent.txouts()[0].value.to_sat(), 10);
    }

    #[test]
    fn precomputed_marks_taproot_ready_when_prevouts_known() {
        let taproot_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_slice(PushBytesBuf::try_from(vec![0u8; 32]).unwrap())
            .into_script();

        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: Witness::from(vec![vec![0x01]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let storage = taproot_script.as_bytes().to_vec();
        let utxo = Utxo {
            script_pubkey: storage.as_ptr(),
            script_pubkey_len: storage.len() as u32,
            value: 50,
        };
        let spent = SpentOutputs::new(1, &[utxo]).expect("spent outputs");
        drop(storage);

        let encoded = consensus::serialize(&tx);
        let ctx = TransactionContext::parse(&encoded).expect("ctx");
        let pre = ctx.build_precomputed(Some(&spent), false);
        assert!(pre.bip341_taproot_ready);
        assert!(pre.spent_amounts_single_hash.is_some());
        assert!(pre.spent_scripts_single_hash.is_some());
        assert!(!pre.bip143_segwit_ready);
    }
}
