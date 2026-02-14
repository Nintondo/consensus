//! Script interpreter.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(all(feature = "std", not(feature = "external-secp")))]
use std::sync::OnceLock;
#[cfg(feature = "std")]
use std::vec::Vec;

use core::{cell::RefCell, mem};

use bitcoin::{
    absolute::LOCK_TIME_THRESHOLD,
    blockdata::script::{Instruction, PushBytesBuf, Script, ScriptBuf},
    blockdata::transaction::Sequence,
    consensus::Encodable,
    hashes::{hash160, ripemd160, sha1, sha256, sha256d, Hash, HashEngine},
    key::UntweakedPublicKey,
    opcodes::{all, Opcode},
    script::Builder,
    secp256k1::{
        self, ecdsa::Signature as EcdsaSignature, schnorr::Signature as SchnorrSignature, Message,
        Parity, PublicKey, Secp256k1, XOnlyPublicKey,
    },
    sighash::{Annex, Prevouts, SegwitV0Sighash, SighashCache, TapSighashType},
    taproot::{
        TapLeafHash, TapNodeHash, TapTweakHash, TAPROOT_ANNEX_PREFIX, TAPROOT_CONTROL_BASE_SIZE,
        TAPROOT_CONTROL_MAX_SIZE, TAPROOT_CONTROL_NODE_SIZE, TAPROOT_LEAF_MASK,
        TAPROOT_LEAF_TAPSCRIPT,
    },
    Amount, Transaction, Witness,
};

use crate::{
    tx::{PrecomputedTransactionData, SpentOutputs, TransactionContext},
    Error, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_CLEANSTACK,
    VERIFY_CONST_SCRIPTCODE, VERIFY_DERSIG, VERIFY_DISCOURAGE_OP_SUCCESS,
    VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    VERIFY_LOW_S, VERIFY_MINIMALDATA, VERIFY_MINIMALIF, VERIFY_NULLDUMMY, VERIFY_NULLFAIL,
    VERIFY_P2SH, VERIFY_SIGPUSHONLY, VERIFY_STRICTENC, VERIFY_TAPROOT, VERIFY_WITNESS,
    VERIFY_WITNESS_PUBKEYTYPE,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ScriptError {
    Ok,
    Unknown,
    EvalFalse,
    OpReturn,
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    Verify,
    EqualVerify,
    CheckSigVerify,
    CheckMultiSigVerify,
    NumEqualVerify,
    BadOpcode,
    OpCodeSeparator,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    NegativeLockTime,
    UnsatisfiedLockTime,
    SigHashType,
    SigDer,
    MinimalData,
    SigPushOnly,
    SigHighS,
    SigNullDummy,
    PubkeyType,
    CleanStack,
    MinimalIf,
    NullFail,
    DiscourageUpgradableNops,
    DiscourageUpgradableWitnessProgram,
    DiscourageUpgradableTaprootVersion,
    DiscourageOpSuccess,
    DiscourageUpgradablePubkeyType,
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2SH,
    WitnessUnexpected,
    WitnessPubkeyType,
    SchnorrSigSize,
    SchnorrSigHashType,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckMultiSig,
    TapscriptMinimalIf,
    SigFindAndDelete,
}

const SUPPORTED_FLAGS: u32 = VERIFY_P2SH
    | VERIFY_STRICTENC
    | VERIFY_DERSIG
    | VERIFY_LOW_S
    | VERIFY_NULLDUMMY
    | VERIFY_SIGPUSHONLY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_TAPROOT
    | VERIFY_MINIMALDATA
    | VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    | VERIFY_DISCOURAGE_OP_SUCCESS
    | VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
    | VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
    | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | VERIFY_CLEANSTACK
    | VERIFY_MINIMALIF
    | VERIFY_NULLFAIL
    | VERIFY_WITNESS_PUBKEYTYPE
    | VERIFY_CONST_SCRIPTCODE;

const MAX_STACK_SIZE: usize = 1000;
const MAX_SCRIPT_SIZE: usize = 10_000;
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
const MAX_OPS_PER_SCRIPT: usize = 201;
const SCRIPTNUM_MAX_LEN: usize = 4;
const SCRIPTNUM_MAX_LEN_EXTENDED: usize = 5;
const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;
const VALIDATION_WEIGHT_OFFSET: i64 = 50;

#[cfg(all(feature = "external-secp", feature = "std"))]
type VerificationContext = Secp256k1<secp256k1::All>;
#[cfg(not(all(feature = "external-secp", feature = "std")))]
type VerificationContext = Secp256k1<secp256k1::VerifyOnly>;

#[cfg(all(feature = "std", not(feature = "external-secp")))]
static SECP256K1: OnceLock<VerificationContext> = OnceLock::new();

fn with_secp256k1_verification_ctx<R>(f: impl FnOnce(&VerificationContext) -> R) -> R {
    #[cfg(all(feature = "std", feature = "external-secp"))]
    {
        // `bitcoin::secp256k1` re-exports the `global` module when the upstream
        // `secp256k1` crate is built with the `global-context` feature, so we can
        // piggyback on that singleton instead of creating ad-hoc contexts.
        f(&*bitcoin::secp256k1::global::SECP256K1)
    }
    #[cfg(all(feature = "std", not(feature = "external-secp")))]
    {
        f(SECP256K1.get_or_init(Secp256k1::verification_only))
    }
    #[cfg(not(feature = "std"))]
    {
        let ctx = Secp256k1::verification_only();
        f(&ctx)
    }
}

/// Wrapper for script verification flags.
#[derive(Debug, Clone, Copy)]
pub struct ScriptFlags(u32);

impl ScriptFlags {
    pub fn from_bits(bits: u32) -> Result<Self, Error> {
        if bits & !SUPPORTED_FLAGS != 0 {
            return Err(Error::ERR_INVALID_FLAGS);
        }
        Ok(Self(bits))
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    pub fn requires_spent_outputs(self) -> bool {
        self.0 & VERIFY_TAPROOT != 0
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SigVersion {
    Base,
    WitnessV0,
    Taproot,
}

#[derive(Clone, Copy)]
struct SignatureParts {
    signature: EcdsaSignature,
    sighash_type: u32,
}

#[derive(Clone, Copy)]
struct TaprootSignatureParts {
    signature: SchnorrSignature,
    sighash_type: TapSighashType,
}

#[derive(Default)]
struct ExecutionData<'tx> {
    annex: Option<Annex<'tx>>,
    tapleaf_hash: Option<TapLeafHash>,
    leaf_version: Option<u8>,
    code_separator_pos: Option<u32>,
    validation_weight_left: Option<i64>,
}

struct ControlBlock<'a> {
    bytes: &'a [u8],
}

impl<'a> ControlBlock<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, ScriptError> {
        #[allow(clippy::manual_is_multiple_of)]
        if bytes.len() < TAPROOT_CONTROL_BASE_SIZE
            || bytes.len() > TAPROOT_CONTROL_MAX_SIZE
            || (bytes.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0
        {
            return Err(ScriptError::TaprootWrongControlSize);
        }
        Ok(Self { bytes })
    }

    fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    fn leaf_version(&self) -> u8 {
        self.bytes[0] & TAPROOT_LEAF_MASK
    }
}

#[derive(Default)]
struct ScriptCodeCache {
    identity: ScriptIdentity,
    code_separator: usize,
    strip_codeseparators: bool,
    script: ScriptBuf,
}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
struct ScriptIdentity {
    digest: [u8; 32],
    len: usize,
}

impl ScriptIdentity {
    fn new(script: &Script) -> Self {
        let digest = sha256::Hash::hash(script.as_bytes()).to_byte_array();
        Self {
            digest,
            len: script.as_bytes().len(),
        }
    }
}

impl ScriptCodeCache {
    fn matches(
        &self,
        identity: ScriptIdentity,
        code_separator: usize,
        strip_codeseparators: bool,
    ) -> bool {
        self.identity == identity
            && self.code_separator == code_separator
            && self.strip_codeseparators == strip_codeseparators
    }
}

/// Minimal stack abstraction used by the interpreter.
#[derive(Debug, Default, Clone)]
pub struct ScriptStack {
    items: Vec<Vec<u8>>,
}

impl ScriptStack {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn from_items(items: Vec<Vec<u8>>) -> Result<Self, ScriptError> {
        if items.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        for item in &items {
            if item.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ScriptError::PushSize);
            }
        }
        Ok(Self { items })
    }

    pub fn from_witness(witness: &Witness) -> Result<Self, ScriptError> {
        if witness.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        let mut items = Vec::with_capacity(witness.len());
        for elem in witness.iter() {
            let bytes = elem.to_vec();
            if bytes.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ScriptError::PushSize);
            }
            items.push(bytes);
        }
        Ok(Self { items })
    }

    pub fn from_witness_prefix(witness: &Witness, end: usize) -> Result<Self, ScriptError> {
        if end > witness.len() || end > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        let mut items = Vec::with_capacity(end);
        for elem in witness.iter().take(end) {
            let bytes = elem.to_vec();
            if bytes.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(ScriptError::PushSize);
            }
            items.push(bytes);
        }
        Ok(Self { items })
    }

    pub fn push(&mut self, data: Vec<u8>) -> Result<(), ScriptError> {
        if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
        self.items.push(data);
        Ok(())
    }

    pub fn push_bool(&mut self, value: bool) -> Result<(), ScriptError> {
        if value {
            self.push(vec![1])
        } else {
            self.push(Vec::new())
        }
    }

    pub fn pop_bytes(&mut self) -> Result<Vec<u8>, Error> {
        self.items.pop().ok_or(Error::ERR_SCRIPT)
    }

    pub fn last(&self) -> Option<&Vec<u8>> {
        self.items.last()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Input-specific data required to run the interpreter.
pub struct SpendContext<'script> {
    pub script_pubkey: &'script [u8],
    pub spent_outputs: Option<SpentOutputs>,
    pub amount: u64,
    pub has_amount: bool,
}

impl<'script> SpendContext<'script> {
    pub fn new(
        script_pubkey: &'script [u8],
        spent_outputs: Option<SpentOutputs>,
        amount: u64,
        has_amount: bool,
    ) -> Self {
        Self {
            script_pubkey,
            spent_outputs,
            amount,
            has_amount,
        }
    }
}

/// High-level script verification context.
pub struct Interpreter<'tx, 'script> {
    flags: ScriptFlags,
    amount: u64,
    has_amount: bool,
    spent_output_script: &'script [u8],
    spent_outputs: Option<SpentOutputs>,
    tx_ctx: &'tx TransactionContext,
    precomputed: Option<PrecomputedTransactionData>,
    input_index: usize,
    script_code_cache: Option<ScriptCodeCache>,
    sighash_cache: RefCell<SighashCache<&'tx Transaction>>,
    stack: ScriptStack,
    exec_stack: Vec<bool>,
    exec_data: ExecutionData<'tx>,
    last_error: ScriptError,
    op_count: usize,
    sigops: u32,
    had_witness: bool,
}

impl<'tx, 'script> Interpreter<'tx, 'script> {
    pub fn new(
        tx_ctx: &'tx TransactionContext,
        input_index: usize,
        spend: SpendContext<'script>,
        flags: ScriptFlags,
    ) -> Result<Self, Error> {
        if flags.requires_spent_outputs() && spend.spent_outputs.is_none() {
            return Err(Error::ERR_SPENT_OUTPUTS_REQUIRED);
        }

        let SpendContext {
            script_pubkey,
            spent_outputs,
            amount,
            has_amount,
        } = spend;

        Ok(Self {
            flags,
            amount,
            has_amount,
            spent_output_script: script_pubkey,
            spent_outputs,
            tx_ctx,
            precomputed: None,
            input_index,
            script_code_cache: None,
            sighash_cache: RefCell::new(SighashCache::new(tx_ctx.tx())),
            stack: ScriptStack::new(),
            exec_stack: Vec::new(),
            exec_data: ExecutionData::default(),
            last_error: ScriptError::Ok,
            op_count: 0,
            sigops: 0,
            had_witness: false,
        })
    }

    pub fn verify(&mut self) -> Result<(), Error> {
        if self.flags.requires_spent_outputs() && self.spent_outputs.is_none() {
            return Err(Error::ERR_SPENT_OUTPUTS_REQUIRED);
        }

        self.last_error = ScriptError::Ok;
        self.had_witness = false;
        self.exec_data = ExecutionData::default();
        self.script_code_cache = None;
        let txin = &self.tx_ctx.tx().input[self.input_index];
        self.initialize_sigops(txin.script_sig.as_bytes())?;
        let witness_enabled = self.flags.bits() & VERIFY_WITNESS != 0;
        let p2sh_enabled = self.flags.bits() & VERIFY_P2SH != 0;
        let spent_is_p2sh = is_p2sh(self.spent_output_script);
        if witness_enabled
            && spent_is_p2sh
            && !txin.witness.is_empty()
            && !is_canonical_single_push(txin.script_sig.as_bytes())
        {
            return Err(self.fail(ScriptError::WitnessMalleatedP2SH));
        }
        if self.flags.bits() & VERIFY_SIGPUSHONLY != 0 && !is_push_only(txin.script_sig.as_bytes())
        {
            return Err(self.fail(ScriptError::SigPushOnly));
        }
        if witness_enabled && !txin.witness.is_empty() && !self.has_amount {
            return Err(Error::ERR_AMOUNT_REQUIRED);
        }

        let sig_script_res = self.run_on_main_stack(txin.script_sig.as_bytes(), SigVersion::Base);
        self.track_script_error(sig_script_res)?;
        let mut p2sh_stack = if p2sh_enabled && spent_is_p2sh {
            Some(self.stack.clone())
        } else {
            None
        };
        let spent_script_res = self.run_on_main_stack(self.spent_output_script, SigVersion::Base);
        self.track_script_error(spent_script_res)?;
        if witness_enabled {
            if let Some((version, program)) = witness_program(self.spent_output_script) {
                self.had_witness = true;
                if !txin.script_sig.is_empty() {
                    return Err(self.fail(ScriptError::WitnessMalleated));
                }
                let witness_res =
                    self.execute_witness_program(version, program, &txin.witness, false);
                self.track_script_error(witness_res)?;
                let mut stack = ScriptStack::new();
                self.push_bool_element(&mut stack, true)?;
                self.stack = stack;
            }
        }

        if p2sh_enabled && spent_is_p2sh {
            if !is_push_only(txin.script_sig.as_bytes()) {
                return Err(self.fail(ScriptError::SigPushOnly));
            }

            let mut stack_copy = p2sh_stack
                .take()
                .expect("P2SH spend requires preserved stack state");
            if stack_copy.is_empty() {
                return Err(self.fail(ScriptError::EvalFalse));
            }

            let redeem_script = stack_copy.pop_bytes()?;
            self.run_script(&mut stack_copy, &redeem_script, SigVersion::Base)?;
            if stack_copy.is_empty() || !cast_to_bool(stack_copy.last().unwrap()) {
                return Err(self.fail(ScriptError::EvalFalse));
            }

            if witness_enabled {
                if let Some((version, program)) = witness_program(&redeem_script) {
                    self.had_witness = true;
                    let expected = single_push_script(&redeem_script)
                        .map_err(|_| self.fail(ScriptError::SigPushOnly))?;
                    if txin.script_sig.as_bytes() != expected.as_bytes() {
                        return Err(self.fail(ScriptError::WitnessMalleatedP2SH));
                    }
                    let witness_res =
                        self.execute_witness_program(version, program, &txin.witness, true);
                    self.track_script_error(witness_res)?;
                    stack_copy = ScriptStack::new();
                    self.push_element(&mut stack_copy, vec![1])?;
                }
            }

            self.add_sigops_from_script(&redeem_script, true)?;
            self.stack = stack_copy;
        }

        if self.stack.is_empty() || !cast_to_bool(self.stack.last().unwrap()) {
            return Err(self.fail(ScriptError::EvalFalse));
        }

        if self.flags.bits() & VERIFY_CLEANSTACK != 0 {
            self.require_clean_stack(&self.stack).map_err(|err| self.fail(err))?;
        }

        if witness_enabled && !self.had_witness && !txin.witness.is_empty() {
            return Err(self.fail(ScriptError::WitnessUnexpected));
        }

        Ok(())
    }

    #[inline]
    pub fn last_script_error(&self) -> ScriptError {
        self.last_error
    }

    fn fail(&mut self, error: ScriptError) -> Error {
        self.last_error = error;
        Error::ERR_SCRIPT
    }

    fn map_failure<T>(&mut self, result: Result<T, Error>, error: ScriptError) -> Result<T, Error> {
        result.map_err(|_| self.fail(error))
    }

    fn track_script_error<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        match result {
            Err(err) if err == Error::ERR_SCRIPT => {
                if matches!(self.last_error, ScriptError::Ok) {
                    self.last_error = ScriptError::Unknown;
                }
                Err(err)
            }
            other => other,
        }
    }

    fn initialize_sigops(&mut self, script_sig: &[u8]) -> Result<(), Error> {
        let sigops_sig =
            count_sigops_bytes(script_sig, false).map_err(|_| self.fail(ScriptError::BadOpcode))?;
        let sigops_spent = count_sigops_bytes(self.spent_output_script, true)
            .map_err(|_| self.fail(ScriptError::BadOpcode))?;
        self.sigops = sigops_sig
            .checked_add(sigops_spent)
            .ok_or(Error::ERR_SCRIPT)?;
        Ok(())
    }

    fn add_sigops_from_script(&mut self, script_bytes: &[u8], accurate: bool) -> Result<(), Error> {
        let count = count_sigops_bytes(script_bytes, accurate)?;
        self.add_sigops(count)
    }

    fn add_sigops(&mut self, count: u32) -> Result<(), Error> {
        self.sigops = self.sigops.checked_add(count).ok_or(Error::ERR_SCRIPT)?;
        Ok(())
    }

    fn push_element(&mut self, stack: &mut ScriptStack, data: Vec<u8>) -> Result<(), Error> {
        stack.push(data).map_err(|err| self.fail(err))
    }

    fn push_bool_element(&mut self, stack: &mut ScriptStack, value: bool) -> Result<(), Error> {
        stack.push_bool(value).map_err(|err| self.fail(err))
    }

    fn add_ops(&mut self, count: usize) -> Result<(), Error> {
        self.op_count += count;
        if self.op_count > MAX_OPS_PER_SCRIPT {
            Err(self.fail(ScriptError::OpCount))
        } else {
            Ok(())
        }
    }

    fn run_script(
        &mut self,
        stack: &mut ScriptStack,
        script_bytes: &[u8],
        sigversion: SigVersion,
    ) -> Result<(), Error> {
        if script_bytes.is_empty() {
            return Ok(());
        }
        if sigversion != SigVersion::Taproot && script_bytes.len() > MAX_SCRIPT_SIZE {
            return Err(self.fail(ScriptError::ScriptSize));
        }

        self.exec_stack.clear();
        self.op_count = 0;
        let script = Script::from_bytes(script_bytes);
        let bytes = script.as_bytes();
        let mut altstack: Vec<Vec<u8>> = Vec::new();
        let mut code_separator = 0usize;
        let mut cursor = 0usize;
        let mut opcode_pos: u32 = 0;
        let script_len = bytes.len();

        while cursor < script_len {
            let opcode = bytes[cursor];
            cursor += 1;
            let should_execute = self.exec_stack.iter().all(|&cond| cond);

            if (0x01..=0x4b).contains(&opcode) {
                let push_len = opcode as usize;
                if cursor + push_len > script_len {
                    return Err(self.fail(ScriptError::BadOpcode));
                }
                if push_len > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(self.fail(ScriptError::PushSize));
                }
                if should_execute
                    && self.flags.bits() & VERIFY_MINIMALDATA != 0
                    && !is_minimal_push(opcode, &bytes[cursor..cursor + push_len])
                {
                    return Err(self.fail(ScriptError::MinimalData));
                }
                if should_execute {
                    self.push_element(stack, bytes[cursor..cursor + push_len].to_vec())?;
                }
                cursor += push_len;
            } else if opcode == all::OP_PUSHDATA1.to_u8()
                || opcode == all::OP_PUSHDATA2.to_u8()
                || opcode == all::OP_PUSHDATA4.to_u8()
            {
                let width = match opcode {
                    x if x == all::OP_PUSHDATA1.to_u8() => 1,
                    x if x == all::OP_PUSHDATA2.to_u8() => 2,
                    _ => 4,
                };
                let mut len_cursor = cursor;
                let push_len = read_push_length(bytes, &mut len_cursor, width)
                    .map_err(|err| self.fail(err))?;
                if push_len > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(self.fail(ScriptError::PushSize));
                }
                if len_cursor + push_len > script_len {
                    return Err(self.fail(ScriptError::BadOpcode));
                }
                if should_execute
                    && self.flags.bits() & VERIFY_MINIMALDATA != 0
                    && !is_minimal_push(opcode, &bytes[len_cursor..len_cursor + push_len])
                {
                    return Err(self.fail(ScriptError::MinimalData));
                }
                if should_execute {
                    self.push_element(stack, bytes[len_cursor..len_cursor + push_len].to_vec())?;
                }
                cursor = len_cursor + push_len;
            } else {
                let op = Opcode::from(opcode);

                if matches!(op, all::OP_VERIF | all::OP_VERNOTIF) {
                    return Err(self.fail(ScriptError::BadOpcode));
                }
                if matches!(
                    op,
                    all::OP_CAT
                        | all::OP_SUBSTR
                        | all::OP_LEFT
                        | all::OP_RIGHT
                        | all::OP_INVERT
                        | all::OP_AND
                        | all::OP_OR
                        | all::OP_XOR
                        | all::OP_2MUL
                        | all::OP_2DIV
                        | all::OP_MUL
                        | all::OP_DIV
                        | all::OP_MOD
                        | all::OP_LSHIFT
                        | all::OP_RSHIFT
                ) {
                    return Err(self.fail(ScriptError::DisabledOpcode));
                }
                if sigversion != SigVersion::Taproot && opcode > all::OP_PUSHNUM_16.to_u8() {
                    self.add_ops(1)?;
                }
                if op == all::OP_CODESEPARATOR
                    && sigversion == SigVersion::Base
                    && self.flags.bits() & VERIFY_CONST_SCRIPTCODE != 0
                {
                    return Err(self.fail(ScriptError::OpCodeSeparator));
                }

                if is_control_flow(op) {
                    let control_res =
                        self.handle_control_flow(stack, op, should_execute, sigversion);
                    self.track_script_error(control_res)?;
                } else if should_execute {
                    if op == all::OP_CODESEPARATOR {
                        code_separator = cursor;
                        if sigversion == SigVersion::Taproot {
                            self.exec_data.code_separator_pos = Some(opcode_pos);
                        }
                    } else {
                        let opcode_res = self.execute_opcode(
                            stack,
                            &mut altstack,
                            op,
                            script,
                            code_separator,
                            sigversion,
                        );
                        self.track_script_error(opcode_res)?;
                    }
                }
            }

            let limit_res = self.ensure_stack_limit(stack.len(), altstack.len());
            self.track_script_error(limit_res)?;
            opcode_pos = opcode_pos.wrapping_add(1);
        }

        if !self.exec_stack.is_empty() {
            return Err(self.fail(ScriptError::UnbalancedConditional));
        }

        Ok(())
    }

    fn run_on_main_stack(
        &mut self,
        script_bytes: &[u8],
        sigversion: SigVersion,
    ) -> Result<(), Error> {
        let mut stack = mem::take(&mut self.stack);
        let run_res = self.run_script(&mut stack, script_bytes, sigversion);
        let result = self.track_script_error(run_res);
        self.stack = stack;
        result
    }

    fn execute_opcode(
        &mut self,
        stack: &mut ScriptStack,
        altstack: &mut Vec<Vec<u8>>,
        op: Opcode,
        script: &Script,
        code_separator: usize,
        sigversion: SigVersion,
    ) -> Result<(), Error> {
        use all::*;

        let opcode = op.to_u8();
        let require_minimal = self.flags.bits() & VERIFY_MINIMALDATA != 0;

        if matches!(
            op,
            OP_RESERVED | OP_RESERVED1 | OP_RESERVED2 | OP_VER | OP_INVALIDOPCODE
        ) {
            return Err(self.fail(ScriptError::BadOpcode));
        }

        if matches!(
            op,
            OP_CAT
                | OP_SUBSTR
                | OP_LEFT
                | OP_RIGHT
                | OP_INVERT
                | OP_AND
                | OP_OR
                | OP_XOR
                | OP_2MUL
                | OP_2DIV
                | OP_MUL
                | OP_DIV
                | OP_MOD
                | OP_LSHIFT
                | OP_RSHIFT
        ) {
            return Err(self.fail(ScriptError::DisabledOpcode));
        }

        if opcode == OP_PUSHBYTES_0.to_u8() {
            return self.push_element(stack, Vec::new());
        }
        if opcode >= OP_PUSHNUM_1.to_u8() && opcode <= OP_PUSHNUM_16.to_u8() {
            let value = (opcode - OP_PUSHNUM_1.to_u8() + 1) as i32;
            return self.push_element(stack, encode_num(value as i64));
        }

        match op {
            OP_TOALTSTACK => {
                let value =
                    self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
                altstack.push(value);
            }
            OP_FROMALTSTACK => {
                let value = altstack
                    .pop()
                    .ok_or_else(|| self.fail(ScriptError::InvalidAltstackOperation))?;
                self.push_element(stack, value)?;
            }
            OP_IFDUP => {
                let value = stack
                    .last()
                    .ok_or_else(|| self.fail(ScriptError::InvalidStackOperation))?
                    .clone();
                if cast_to_bool(&value) {
                    self.push_element(stack, value)?;
                }
            }
            OP_DEPTH => {
                let depth = encode_num(stack.len() as i64);
                self.push_element(stack, depth)?;
            }
            OP_PUSHNUM_NEG1 => {
                self.push_element(stack, encode_num(-1))?;
            }
            OP_NOP => {}
            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                if self.flags.bits() & VERIFY_DISCOURAGE_UPGRADABLE_NOPS != 0 {
                    return Err(self.fail(ScriptError::DiscourageUpgradableNops));
                }
            }
            OP_DUP => {
                let value = stack
                    .last()
                    .ok_or_else(|| self.fail(ScriptError::InvalidStackOperation))?
                    .clone();
                self.push_element(stack, value)?;
            }
            OP_DROP => {
                self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
            }
            OP_NIP => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let idx = stack.len() - 2;
                stack.items.remove(idx);
            }
            OP_OVER => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let value = stack.items[stack.len() - 2].clone();
                self.push_element(stack, value)?;
            }
            OP_ROT => {
                if stack.len() < 3 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                stack.items.swap(len - 3, len - 2);
                stack.items.swap(len - 2, len - 1);
            }
            OP_SWAP => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                stack.items.swap(len - 2, len - 1);
            }
            OP_TUCK => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                let value = stack.items[len - 1].clone();
                stack.items.insert(len - 2, value);
            }
            OP_2DROP => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
                self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
            }
            OP_2DUP => {
                if stack.len() < 2 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                let first = stack.items[len - 2].clone();
                let second = stack.items[len - 1].clone();
                self.push_element(stack, first)?;
                self.push_element(stack, second)?;
            }
            OP_PICK => {
                let depth = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                if depth < 0 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let depth = depth as usize;
                if depth >= stack.len() {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let idx = stack.len() - 1 - depth;
                let value = stack.items[idx].clone();
                self.push_element(stack, value)?;
            }
            OP_ROLL => {
                let depth = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                if depth < 0 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let depth = depth as usize;
                if depth >= stack.len() {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let idx = stack.len() - 1 - depth;
                let value = stack.items.remove(idx);
                self.push_element(stack, value)?;
            }
            OP_3DUP => {
                if stack.len() < 3 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                let first = stack.items[len - 3].clone();
                let second = stack.items[len - 2].clone();
                let third = stack.items[len - 1].clone();
                self.push_element(stack, first)?;
                self.push_element(stack, second)?;
                self.push_element(stack, third)?;
            }
            OP_2OVER => {
                if stack.len() < 4 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                let first = stack.items[len - 4].clone();
                let second = stack.items[len - 3].clone();
                self.push_element(stack, first)?;
                self.push_element(stack, second)?;
            }
            OP_2ROT => {
                if stack.len() < 6 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                let first = stack.items[len - 6].clone();
                let second = stack.items[len - 5].clone();
                stack.items.drain(len - 6..len - 4);
                self.push_element(stack, first)?;
                self.push_element(stack, second)?;
            }
            OP_2SWAP => {
                if stack.len() < 4 {
                    return Err(self.fail(ScriptError::InvalidStackOperation));
                }
                let len = stack.len();
                stack.items.swap(len - 4, len - 2);
                stack.items.swap(len - 3, len - 1);
            }
            OP_SIZE => {
                let value = stack
                    .last()
                    .ok_or_else(|| self.fail(ScriptError::InvalidStackOperation))?;
                let size = encode_num(value.len() as i64);
                self.push_element(stack, size)?;
            }
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                let mut num = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                match op {
                    OP_1ADD => num += 1,
                    OP_1SUB => num -= 1,
                    OP_NEGATE => num = -num,
                    OP_ABS => {
                        if num < 0 {
                            num = -num;
                        }
                    }
                    OP_NOT => num = if num == 0 { 1 } else { 0 },
                    OP_0NOTEQUAL => num = if num != 0 { 1 } else { 0 },
                    _ => {}
                }
                let encoded = encode_num(num);
                self.push_element(stack, encoded)?;
            }
            OP_ADD
            | OP_SUB
            | OP_BOOLAND
            | OP_BOOLOR
            | OP_NUMEQUAL
            | OP_NUMEQUALVERIFY
            | OP_NUMNOTEQUAL
            | OP_LESSTHAN
            | OP_GREATERTHAN
            | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL
            | OP_MIN
            | OP_MAX => {
                let b = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                let a = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                let result = match op {
                    OP_ADD => a.checked_add(b).ok_or(Error::ERR_SCRIPT)?,
                    OP_SUB => a.checked_sub(b).ok_or(Error::ERR_SCRIPT)?,
                    OP_BOOLAND => {
                        if a != 0 && b != 0 {
                            1
                        } else {
                            0
                        }
                    }
                    OP_BOOLOR => {
                        if a != 0 || b != 0 {
                            1
                        } else {
                            0
                        }
                    }
                    OP_NUMEQUAL | OP_NUMEQUALVERIFY => {
                        if a == b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_NUMNOTEQUAL => {
                        if a != b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_LESSTHAN => {
                        if a < b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_GREATERTHAN => {
                        if a > b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_LESSTHANOREQUAL => {
                        if a <= b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_GREATERTHANOREQUAL => {
                        if a >= b {
                            1
                        } else {
                            0
                        }
                    }
                    OP_MIN => {
                        if a < b {
                            a
                        } else {
                            b
                        }
                    }
                    OP_MAX => {
                        if a > b {
                            a
                        } else {
                            b
                        }
                    }
                    _ => 0,
                };
                self.push_element(stack, encode_num(result))?;
                if op == OP_NUMEQUALVERIFY {
                    self.op_verify_with_code(stack, ScriptError::NumEqualVerify)?;
                }
            }
            OP_WITHIN => {
                let max = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                let min = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                let value = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
                self.push_bool_element(stack, value >= min && value < max)?;
            }
            OP_CLTV => {
                if self.flags.bits() & VERIFY_CHECKLOCKTIMEVERIFY != 0 {
                    let locktime =
                        self.peek_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN_EXTENDED)?;
                    if locktime < 0 {
                        return Err(self.fail(ScriptError::NegativeLockTime));
                    }
                    let check = self.check_lock_time(locktime as u64);
                    if let Err(err) = check {
                        return Err(self.fail(err));
                    }
                }
            }
            OP_CSV => {
                if self.flags.bits() & VERIFY_CHECKSEQUENCEVERIFY != 0 {
                    let sequence =
                        self.peek_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN_EXTENDED)?;
                    if sequence < 0 {
                        return Err(self.fail(ScriptError::NegativeLockTime));
                    }
                    let check = self.check_sequence(sequence as u64);
                    if let Err(err) = check {
                        return Err(self.fail(err));
                    }
                }
            }
            OP_RIPEMD160 => self.op_ripemd160(stack)?,
            OP_SHA1 => self.op_sha1(stack)?,
            OP_SHA256 => self.op_sha256(stack)?,
            OP_HASH160 => self.op_hash160(stack)?,
            OP_HASH256 => self.op_hash256(stack)?,
            OP_EQUAL => self.op_equal(stack)?,
            OP_EQUALVERIFY => {
                self.op_equal(stack)?;
                self.op_verify_with_code(stack, ScriptError::EqualVerify)?;
            }
            OP_VERIFY => self.op_verify(stack)?,
            OP_RETURN => return Err(self.fail(ScriptError::OpReturn)),
            OP_CHECKSIG => self.op_checksig(stack, script, code_separator, sigversion)?,
            OP_CHECKSIGVERIFY => {
                self.op_checksig(stack, script, code_separator, sigversion)?;
                self.op_verify_with_code(stack, ScriptError::CheckSigVerify)?;
            }
            OP_CHECKSIGADD => {
                self.op_checksigadd(stack, sigversion)?;
            }
            OP_CHECKMULTISIG => {
                self.op_checkmultisig(stack, script, code_separator, sigversion)?;
            }
            OP_CHECKMULTISIGVERIFY => {
                self.op_checkmultisig(stack, script, code_separator, sigversion)?;
                self.op_verify_with_code(stack, ScriptError::CheckMultiSigVerify)?;
            }
            _ => return Err(self.fail(ScriptError::BadOpcode)),
        }

        Ok(())
    }

    fn handle_control_flow(
        &mut self,
        stack: &mut ScriptStack,
        op: Opcode,
        should_execute: bool,
        sigversion: SigVersion,
    ) -> Result<(), Error> {
        use all::*;

        match op {
            OP_IF | OP_NOTIF => {
                let mut value = false;
                if should_execute {
                    let condition =
                        self.map_failure(stack.pop_bytes(), ScriptError::UnbalancedConditional)?;
                    let enforce_minimal_if = match sigversion {
                        SigVersion::WitnessV0 => self.flags.bits() & VERIFY_MINIMALIF != 0,
                        SigVersion::Taproot => true,
                        SigVersion::Base => false,
                    };
                    let minimal_if_error = match sigversion {
                        SigVersion::Taproot => ScriptError::TapscriptMinimalIf,
                        _ => ScriptError::MinimalIf,
                    };
                    if enforce_minimal_if
                        && !condition.is_empty()
                        && !is_minimal_if_condition(&condition)
                    {
                        return Err(self.fail(minimal_if_error));
                    }
                    value = cast_to_bool(&condition);
                    if op == OP_NOTIF {
                        value = !value;
                    }
                }
                self.exec_stack.push(value);
            }
            OP_ELSE => {
                let Some(top) = self.exec_stack.last_mut() else {
                    return Err(self.fail(ScriptError::UnbalancedConditional));
                };
                *top = !*top;
            }
            OP_ENDIF => {
                if self.exec_stack.pop().is_none() {
                    return Err(self.fail(ScriptError::UnbalancedConditional));
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn ensure_stack_limit(&mut self, stack_size: usize, altstack_size: usize) -> Result<(), Error> {
        if stack_size + altstack_size > MAX_STACK_SIZE {
            Err(self.fail(ScriptError::StackSize))
        } else {
            Ok(())
        }
    }

    fn op_hash160(&mut self, stack: &mut ScriptStack) -> Result<(), Error> {
        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = hash160::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_ripemd160(&mut self, stack: &mut ScriptStack) -> Result<(), Error> {
        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = ripemd160::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_sha1(&mut self, stack: &mut ScriptStack) -> Result<(), Error> {
        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = sha1::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_sha256(&mut self, stack: &mut ScriptStack) -> Result<(), Error> {
        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = sha256::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_hash256(&mut self, stack: &mut ScriptStack) -> Result<(), Error> {
        let data = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let hash = sha256d::Hash::hash(&data);
        self.push_element(stack, hash.to_byte_array().to_vec())
    }

    fn op_equal(&mut self, stack: &mut ScriptStack) -> Result<(), Error> {
        let a = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let b = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        self.push_bool_element(stack, a == b)
    }

    fn op_verify(&mut self, stack: &mut ScriptStack) -> Result<(), Error> {
        self.op_verify_with_code(stack, ScriptError::Verify)
    }

    fn op_verify_with_code(
        &mut self,
        stack: &mut ScriptStack,
        error: ScriptError,
    ) -> Result<(), Error> {
        let value = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        if !cast_to_bool(&value) {
            return Err(self.fail(error));
        }
        Ok(())
    }

    fn op_checksig(
        &mut self,
        stack: &mut ScriptStack,
        script: &Script,
        code_separator: usize,
        sigversion: SigVersion,
    ) -> Result<(), Error> {
        let pubkey = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let sig = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let result = match sigversion {
            SigVersion::Taproot => self.verify_tapscript_signature(&sig, &pubkey)?,
            _ => {
                let mut script_code = self.build_script_code(script, code_separator, sigversion)?;
                if sigversion == SigVersion::Base {
                    script_code =
                        self.apply_legacy_find_and_delete(script_code.as_script(), &[&sig])?;
                }
                let sig_parts = self.parse_signature(&sig, sigversion)?;
                self.check_pubkey_encoding(&pubkey, sigversion)?;
                self.verify_ecdsa_signature(
                    sig_parts,
                    &pubkey,
                    script_code.as_script(),
                    sigversion,
                )?
            }
        };
        if sigversion != SigVersion::Taproot
            && !result
            && self.flags.bits() & VERIFY_NULLFAIL != 0
            && !sig.is_empty()
        {
            return Err(self.fail(ScriptError::NullFail));
        }
        self.push_bool_element(stack, result)
    }

    fn op_checkmultisig(
        &mut self,
        stack: &mut ScriptStack,
        script: &Script,
        code_separator: usize,
        sigversion: SigVersion,
    ) -> Result<(), Error> {
        if sigversion == SigVersion::Taproot {
            return Err(self.fail(ScriptError::TapscriptCheckMultiSig));
        }
        let require_minimal = self.flags.bits() & VERIFY_MINIMALDATA != 0;
        let n_keys = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
        if n_keys < 0 || n_keys as usize > MAX_PUBKEYS_PER_MULTISIG {
            return Err(self.fail(ScriptError::PubkeyCount));
        }
        let n_keys = n_keys as usize;
        self.add_ops(n_keys)?;
        if stack.len() < n_keys {
            return Err(self.fail(ScriptError::InvalidStackOperation));
        }

        let mut pubkeys = Vec::with_capacity(n_keys);
        for _ in 0..n_keys {
            let key = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
            pubkeys.push(key);
        }

        let n_sigs = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
        if n_sigs < 0 || n_sigs as usize > n_keys {
            return Err(self.fail(ScriptError::SigCount));
        }
        let n_sigs = n_sigs as usize;
        if stack.len() < n_sigs + 1 {
            return Err(self.fail(ScriptError::InvalidStackOperation));
        }

        let mut sigs = Vec::with_capacity(n_sigs);
        for _ in 0..n_sigs {
            let sig = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
            sigs.push(sig);
        }

        let mut script_code = self.build_script_code(script, code_separator, sigversion)?;
        if sigversion == SigVersion::Base {
            let signatures = sigs.iter().map(Vec::as_slice).collect::<Vec<_>>();
            script_code =
                self.apply_legacy_find_and_delete(script_code.as_script(), &signatures)?;
        }
        let dummy = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        if self.flags.bits() & VERIFY_NULLDUMMY != 0 && !dummy.is_empty() {
            return Err(self.fail(ScriptError::SigNullDummy));
        }

        let mut success = true;
        let mut sig_index = 0usize;
        let mut key_index = 0usize;
        let enforce_nullfail = self.flags.bits() & VERIFY_NULLFAIL != 0;

        while success && sig_index < sigs.len() {
            if pubkeys.len() - key_index < sigs.len() - sig_index {
                success = false;
                break;
            }

            let sig_parts = self.parse_signature(&sigs[sig_index], sigversion)?;
            self.check_pubkey_encoding(&pubkeys[key_index], sigversion)?;
            let sig_valid = self.verify_ecdsa_signature(
                sig_parts,
                &pubkeys[key_index],
                script_code.as_script(),
                sigversion,
            )?;
            if !sig_valid && enforce_nullfail && !sigs[sig_index].is_empty() {
                return Err(self.fail(ScriptError::NullFail));
            }
            if sig_valid {
                sig_index += 1;
            }
            key_index += 1;
        }

        if !success && enforce_nullfail {
            let has_non_empty = sigs[sig_index..].iter().any(|sig| !sig.is_empty());
            if has_non_empty {
                return Err(self.fail(ScriptError::NullFail));
            }
        }

        let remaining_keys = pubkeys.len().saturating_sub(key_index);
        let remaining_sigs = sigs.len().saturating_sub(sig_index);
        if remaining_sigs > remaining_keys {
            success = false;
        }

        self.push_bool_element(stack, success)
    }

    fn op_checksigadd(
        &mut self,
        stack: &mut ScriptStack,
        sigversion: SigVersion,
    ) -> Result<(), Error> {
        if sigversion != SigVersion::Taproot {
            return Err(self.fail(ScriptError::BadOpcode));
        }
        if stack.len() < 3 {
            return Err(self.fail(ScriptError::InvalidStackOperation));
        }

        let pubkey = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let require_minimal = self.flags.bits() & VERIFY_MINIMALDATA != 0;
        let value = self.pop_scriptnum(stack, require_minimal, SCRIPTNUM_MAX_LEN)?;
        let sig = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        let sig_valid = self.verify_tapscript_signature(&sig, &pubkey)?;
        let result = value + if sig_valid { 1 } else { 0 };
        self.push_element(stack, encode_num(result))
    }

    fn pop_scriptnum(
        &mut self,
        stack: &mut ScriptStack,
        minimal: bool,
        max_len: usize,
    ) -> Result<i64, Error> {
        let bytes = self.map_failure(stack.pop_bytes(), ScriptError::InvalidStackOperation)?;
        self.decode_scriptnum(&bytes, minimal, max_len)
    }

    fn peek_scriptnum(
        &mut self,
        stack: &ScriptStack,
        minimal: bool,
        max_len: usize,
    ) -> Result<i64, Error> {
        let bytes = stack
            .last()
            .ok_or_else(|| self.fail(ScriptError::InvalidStackOperation))?;
        self.decode_scriptnum(bytes, minimal, max_len)
    }

    fn decode_scriptnum(
        &mut self,
        bytes: &[u8],
        minimal: bool,
        max_len: usize,
    ) -> Result<i64, Error> {
        parse_scriptnum(bytes, minimal, max_len).map_err(|err| self.fail(err))
    }

    fn check_lock_time(&self, locktime: u64) -> Result<(), ScriptError> {
        if locktime > u32::MAX as u64 {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        let tx = self.tx_ctx.tx();
        let tx_lock = tx.lock_time.to_consensus_u32();
        let locktime_u32 = locktime as u32;
        if tx_lock < locktime_u32 {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        if (tx_lock < LOCK_TIME_THRESHOLD) != (locktime_u32 < LOCK_TIME_THRESHOLD) {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        let sequence = tx.input[self.input_index].sequence.to_consensus_u32();
        if sequence == Sequence::MAX.0 {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        Ok(())
    }

    fn check_sequence(&self, sequence: u64) -> Result<(), ScriptError> {
        if (sequence as u32) & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return Ok(());
        }
        if self.tx_ctx.tx().version.0 < 2 {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        let tx_sequence = self.tx_ctx.tx().input[self.input_index]
            .sequence
            .to_consensus_u32();
        if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        let locktime_mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
        let tx_sequence_masked = tx_sequence & locktime_mask;
        let sequence_masked = (sequence as u32) & locktime_mask;
        let tx_is_time = tx_sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG;
        let sequence_is_time = sequence_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG;
        if tx_is_time != sequence_is_time {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        if sequence_masked > tx_sequence_masked {
            return Err(ScriptError::UnsatisfiedLockTime);
        }

        Ok(())
    }

    fn parse_signature(
        &mut self,
        sig_with_hashtype: &[u8],
        sigversion: SigVersion,
    ) -> Result<Option<SignatureParts>, Error> {
        if sig_with_hashtype.is_empty() {
            return Ok(None);
        }

        self.check_signature_encoding(sig_with_hashtype, sigversion)?;

        if sig_with_hashtype.len() == 1 {
            return Ok(None);
        }

        let sighash_type = *sig_with_hashtype.last().unwrap() as u32;
        let sig_bytes = &sig_with_hashtype[..sig_with_hashtype.len() - 1];
        let strict_encoding =
            self.flags.bits() & (VERIFY_DERSIG | VERIFY_LOW_S | VERIFY_STRICTENC) != 0;
        let signature = if strict_encoding {
            EcdsaSignature::from_der(sig_bytes).map_err(|_| self.fail(ScriptError::SigDer))?
        } else {
            match EcdsaSignature::from_der_lax(sig_bytes) {
                Ok(sig) => sig,
                Err(_) => return Ok(None),
            }
        };

        Ok(Some(SignatureParts {
            signature,
            sighash_type,
        }))
    }

    fn parse_taproot_signature(
        &mut self,
        sig_with_hashtype: &[u8],
    ) -> Result<Option<TaprootSignatureParts>, Error> {
        if sig_with_hashtype.is_empty() {
            return Ok(None);
        }
        if sig_with_hashtype.len() != 64 && sig_with_hashtype.len() != 65 {
            return Err(self.fail(ScriptError::SchnorrSigSize));
        }

        let sighash_type = if sig_with_hashtype.len() == 65 {
            let ty = sig_with_hashtype[64];
            if ty == TapSighashType::Default as u8 {
                return Err(self.fail(ScriptError::SchnorrSigHashType));
            }
            TapSighashType::from_consensus_u8(ty)
                .map_err(|_| self.fail(ScriptError::SchnorrSigHashType))?
        } else {
            TapSighashType::Default
        };

        let signature_bytes = &sig_with_hashtype[..64];
        let signature = SchnorrSignature::from_slice(signature_bytes)
            .map_err(|_| self.fail(ScriptError::SchnorrSig))?;

        Ok(Some(TaprootSignatureParts {
            signature,
            sighash_type,
        }))
    }

    fn consume_tapscript_sigop(&mut self) -> Result<(), Error> {
        let remaining = match self.exec_data.validation_weight_left.as_mut() {
            Some(value) => value,
            None => return Err(self.fail(ScriptError::Unknown)),
        };
        *remaining -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
        if *remaining < 0 {
            Err(self.fail(ScriptError::TapscriptValidationWeight))
        } else {
            Ok(())
        }
    }

    fn check_signature_encoding(
        &mut self,
        sig_with_hashtype: &[u8],
        _sigversion: SigVersion,
    ) -> Result<(), Error> {
        if sig_with_hashtype.is_empty() {
            return Ok(());
        }
        let flags = self.flags.bits();
        let enforce_der = flags & (VERIFY_DERSIG | VERIFY_LOW_S | VERIFY_STRICTENC) != 0;
        if enforce_der && !is_valid_signature_encoding(sig_with_hashtype) {
            return Err(self.fail(ScriptError::SigDer));
        }
        if flags & VERIFY_LOW_S != 0 && !is_low_der_signature(sig_with_hashtype) {
            return Err(self.fail(ScriptError::SigHighS));
        }
        if flags & VERIFY_STRICTENC != 0 && !is_defined_hashtype_signature(sig_with_hashtype) {
            return Err(self.fail(ScriptError::SigHashType));
        }
        Ok(())
    }

    fn check_pubkey_encoding(
        &mut self,
        pubkey: &[u8],
        sigversion: SigVersion,
    ) -> Result<(), Error> {
        if self.flags.bits() & VERIFY_STRICTENC != 0 && !is_valid_pubkey_encoding(pubkey) {
            return Err(self.fail(ScriptError::PubkeyType));
        }
        if sigversion == SigVersion::WitnessV0
            && self.flags.bits() & VERIFY_WITNESS_PUBKEYTYPE != 0
            && !is_compressed_pubkey(pubkey)
        {
            return Err(self.fail(ScriptError::WitnessPubkeyType));
        }
        Ok(())
    }

    fn build_script_code(
        &mut self,
        script: &Script,
        code_separator: usize,
        sigversion: SigVersion,
    ) -> Result<ScriptBuf, Error> {
        let strip_codeseparators = matches!(sigversion, SigVersion::Base);
        let identity = ScriptIdentity::new(script);
        let needs_refresh = self
            .script_code_cache
            .as_ref()
            .map(|cache| !cache.matches(identity, code_separator, strip_codeseparators))
            .unwrap_or(true);
        if needs_refresh {
            let script_buf =
                Self::materialize_script_code(script, code_separator, strip_codeseparators)?;
            self.script_code_cache = Some(ScriptCodeCache {
                identity,
                code_separator,
                strip_codeseparators,
                script: script_buf,
            });
        }
        Ok(self
            .script_code_cache
            .as_ref()
            .expect("script code cache is initialized")
            .script
            .clone())
    }

    fn materialize_script_code(
        script: &Script,
        code_separator: usize,
        strip_codeseparators: bool,
    ) -> Result<ScriptBuf, Error> {
        if code_separator > script.as_bytes().len() {
            return Err(Error::ERR_SCRIPT);
        }
        let tail = &script.as_bytes()[code_separator..];
        if strip_codeseparators {
            let stripped = strip_opcode(tail, all::OP_CODESEPARATOR)?;
            Ok(ScriptBuf::from_bytes(stripped))
        } else {
            Ok(ScriptBuf::from_bytes(tail.to_vec()))
        }
    }

    fn execute_witness_program(
        &mut self,
        version: u8,
        program: &[u8],
        witness: &'tx Witness,
        is_p2sh: bool,
    ) -> Result<(), Error> {
        match version {
            0 => match program.len() {
                20 => self.verify_p2wpkh(program, witness),
                32 => self.verify_p2wsh(program, witness),
                _ => Err(self.fail(ScriptError::WitnessProgramWrongLength)),
            },
            1 => {
                if program.len() == 32 && !is_p2sh {
                    self.execute_taproot_program(program, witness)
                } else if !is_p2sh && is_pay_to_anchor(version, program) {
                    Ok(())
                } else if self.flags.bits() & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM != 0 {
                    Err(self.fail(ScriptError::DiscourageUpgradableWitnessProgram))
                } else {
                    Ok(())
                }
            }
            2..=16 => {
                if self.flags.bits() & VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM != 0 {
                    Err(self.fail(ScriptError::DiscourageUpgradableWitnessProgram))
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    fn execute_taproot_program(
        &mut self,
        program: &[u8],
        witness: &'tx Witness,
    ) -> Result<(), Error> {
        if self.flags.bits() & VERIFY_TAPROOT == 0 {
            return Ok(());
        }

        if witness.is_empty() {
            return Err(self.fail(ScriptError::WitnessProgramWitnessEmpty));
        }

        self.exec_data = ExecutionData::default();

        let mut stack_len = witness.len();
        let mut annex: Option<Annex> = None;
        if stack_len >= 2 {
            let last = witness[stack_len - 1].as_ref();
            if !last.is_empty() && last[0] == TAPROOT_ANNEX_PREFIX {
                annex = Some(
                    Annex::new(last).map_err(|_| self.fail(ScriptError::WitnessProgramMismatch))?,
                );
                stack_len -= 1;
            }
        }

        self.exec_data.annex = annex;
        self.exec_data.code_separator_pos = None;

        if stack_len == 0 {
            return Err(self.fail(ScriptError::WitnessProgramWitnessEmpty));
        }

        if stack_len == 1 {
            return self.verify_taproot_key_path(program, witness[0].as_ref());
        }

        let control_slice = witness[stack_len - 1].as_ref();
        let control = ControlBlock::parse(control_slice).map_err(|err| self.fail(err))?;
        let script_bytes = witness[stack_len - 2].as_ref();
        let script = Script::from_bytes(script_bytes);
        stack_len -= 2;
        let leaf_version = control.leaf_version();
        let tapleaf_hash = self.compute_tapleaf_hash(script, leaf_version)?;
        let merkle_root = self.compute_taproot_merkle_root(control.bytes(), tapleaf_hash)?;
        self.verify_taproot_commitment(program, control.bytes(), merkle_root)?;
        self.exec_data.tapleaf_hash = Some(tapleaf_hash);
        self.exec_data.leaf_version = Some(leaf_version);

        if leaf_version == TAPROOT_LEAF_TAPSCRIPT {
            if contains_op_success(script).map_err(|err| self.fail(err))? {
                if self.flags.bits() & VERIFY_DISCOURAGE_OP_SUCCESS != 0 {
                    return Err(self.fail(ScriptError::DiscourageOpSuccess));
                }
                return Ok(());
            }
            let witness_weight =
                serialized_witness_size(witness).ok_or_else(|| self.fail(ScriptError::Unknown))?;
            self.exec_data.validation_weight_left = Some(witness_weight + VALIDATION_WEIGHT_OFFSET);
            let mut script_stack = ScriptStack::from_witness_prefix(witness, stack_len)
                .map_err(|err| self.fail(err))?;
            self.run_script(&mut script_stack, script.as_bytes(), SigVersion::Taproot)?;
            self.ensure_witness_success(&script_stack)
        } else if self.flags.bits() & VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION != 0 {
            Err(self.fail(ScriptError::DiscourageUpgradableTaprootVersion))
        } else {
            Ok(())
        }
    }

    fn verify_p2wpkh(&mut self, program: &[u8], witness: &Witness) -> Result<(), Error> {
        if witness.len() != 2 {
            return Err(self.fail(ScriptError::WitnessProgramMismatch));
        }

        self.add_sigops(1)?;
        let mut stack = ScriptStack::from_witness(witness).map_err(|err| self.fail(err))?;
        let program_bytes =
            PushBytesBuf::try_from(program.to_vec()).map_err(|_| Error::ERR_SCRIPT)?;
        let script = Builder::new()
            .push_opcode(all::OP_DUP)
            .push_opcode(all::OP_HASH160)
            .push_slice(program_bytes)
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_CHECKSIG)
            .into_script();

        self.run_script(&mut stack, script.as_bytes(), SigVersion::WitnessV0)?;
        self.ensure_witness_success(&stack)
    }

    fn compute_tapleaf_hash(
        &mut self,
        script: &Script,
        leaf_version: u8,
    ) -> Result<TapLeafHash, Error> {
        let mut engine = TapLeafHash::engine();
        engine.input(&[leaf_version]);
        script
            .consensus_encode(&mut engine)
            .map_err(|_| Error::ERR_SCRIPT)?;
        Ok(TapLeafHash::from_engine(engine))
    }

    fn compute_taproot_merkle_root(
        &mut self,
        control: &[u8],
        tapleaf_hash: TapLeafHash,
    ) -> Result<TapNodeHash, Error> {
        let mut current = TapNodeHash::from(tapleaf_hash);
        let mut index = TAPROOT_CONTROL_BASE_SIZE;
        while index < control.len() {
            let end = index + TAPROOT_CONTROL_NODE_SIZE;
            if end > control.len() {
                return Err(self.fail(ScriptError::TaprootWrongControlSize));
            }
            let mut node_bytes = [0u8; TAPROOT_CONTROL_NODE_SIZE];
            node_bytes.copy_from_slice(&control[index..end]);
            let node = TapNodeHash::from_byte_array(node_bytes);
            current = TapNodeHash::from_node_hashes(current, node);
            index = end;
        }
        Ok(current)
    }

    fn verify_taproot_commitment(
        &mut self,
        program: &[u8],
        control: &[u8],
        merkle_root: TapNodeHash,
    ) -> Result<(), Error> {
        let internal_key = UntweakedPublicKey::from_slice(&control[1..TAPROOT_CONTROL_BASE_SIZE])
            .map_err(|_| self.fail(ScriptError::WitnessProgramMismatch))?;
        let output_key = XOnlyPublicKey::from_slice(program)
            .map_err(|_| self.fail(ScriptError::WitnessProgramMismatch))?;
        let expected_parity = if control[0] & 1 == 0 {
            Parity::Even
        } else {
            Parity::Odd
        };
        let tweak = TapTweakHash::from_key_and_tweak(internal_key, Some(merkle_root)).to_scalar();
        with_secp256k1_verification_ctx(|secp| {
            if !internal_key.tweak_add_check(secp, &output_key, expected_parity, tweak) {
                return Err(self.fail(ScriptError::WitnessProgramMismatch));
            }
            Ok(())
        })
    }

    fn verify_taproot_key_path(&mut self, program: &[u8], signature: &[u8]) -> Result<(), Error> {
        if program.len() != 32 {
            return Err(self.fail(ScriptError::WitnessProgramMismatch));
        }
        if signature.is_empty() {
            return Err(self.fail(ScriptError::SchnorrSigSize));
        }

        let pubkey = XOnlyPublicKey::from_slice(program)
            .map_err(|_| self.fail(ScriptError::WitnessProgramMismatch))?;
        let Some(parts) = self.parse_taproot_signature(signature)? else {
            return Err(self.fail(ScriptError::SchnorrSigSize));
        };
        let is_valid = self.verify_taproot_signature_common(
            &parts.signature,
            parts.sighash_type,
            &pubkey,
            None,
        )?;
        if is_valid {
            Ok(())
        } else {
            Err(self.fail(ScriptError::SchnorrSig))
        }
    }

    fn verify_p2wsh(&mut self, program: &[u8], witness: &Witness) -> Result<(), Error> {
        if witness.is_empty() {
            return Err(self.fail(ScriptError::WitnessProgramWitnessEmpty));
        }

        let witness_script_bytes = witness[witness.len() - 1].as_ref();
        let script_hash = sha256::Hash::hash(witness_script_bytes);
        let hash_bytes: &[u8] = script_hash.as_ref();
        if hash_bytes != program {
            return Err(self.fail(ScriptError::WitnessProgramMismatch));
        }

        self.add_sigops_from_script(witness_script_bytes, true)?;
        let items = witness
            .iter()
            .take(witness.len() - 1)
            .map(|elem| elem.to_vec())
            .collect();
        let mut stack = ScriptStack::from_items(items).map_err(|err| self.fail(err))?;

        self.run_script(&mut stack, witness_script_bytes, SigVersion::WitnessV0)?;
        self.ensure_witness_success(&stack)
    }

    fn require_clean_stack(&self, stack: &ScriptStack) -> Result<(), ScriptError> {
        if stack.len() != 1 {
            return Err(ScriptError::CleanStack);
        }
        if !cast_to_bool(stack.last().expect("stack length checked")) {
            return Err(ScriptError::CleanStack);
        }
        Ok(())
    }

    fn ensure_witness_success(&mut self, stack: &ScriptStack) -> Result<(), Error> {
        if stack.len() != 1 {
            return Err(self.fail(ScriptError::CleanStack));
        }
        if !cast_to_bool(stack.last().expect("stack length checked")) {
            return Err(self.fail(ScriptError::EvalFalse));
        }
        Ok(())
    }

    fn verify_tapscript_signature(
        &mut self,
        sig_bytes: &[u8],
        pubkey_bytes: &[u8],
    ) -> Result<bool, Error> {
        let has_signature = !sig_bytes.is_empty();
        if has_signature {
            // Core charges validation weight for every non-empty signature before
            // branching on pubkey type, including upgradable key versions.
            self.consume_tapscript_sigop()?;
        }

        if pubkey_bytes.is_empty() {
            return Err(self.fail(ScriptError::PubkeyType));
        }

        if pubkey_bytes.len() != 32 {
            if self.flags.bits() & VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE != 0 {
                return Err(self.fail(ScriptError::DiscourageUpgradablePubkeyType));
            }
            return Ok(has_signature);
        }

        if !has_signature {
            return Ok(false);
        }

        let Some(parts) = self.parse_taproot_signature(sig_bytes)? else {
            return Ok(false);
        };
        let pubkey = XOnlyPublicKey::from_slice(pubkey_bytes)
            .map_err(|_| self.fail(ScriptError::PubkeyType))?;
        let tapleaf_hash = self
            .exec_data
            .tapleaf_hash
            .ok_or_else(|| self.fail(ScriptError::WitnessProgramMismatch))?;
        let code_separator = self.exec_data.code_separator_pos.unwrap_or(u32::MAX);
        self.verify_taproot_signature_common(
            &parts.signature,
            parts.sighash_type,
            &pubkey,
            Some((tapleaf_hash, code_separator)),
        )
    }

    fn verify_taproot_signature_common(
        &mut self,
        signature: &SchnorrSignature,
        sighash_type: TapSighashType,
        pubkey: &XOnlyPublicKey,
        leaf_hash: Option<(TapLeafHash, u32)>,
    ) -> Result<bool, Error> {
        let taproot_ready = self.ensure_precomputed().bip341_taproot_ready;
        if !taproot_ready {
            return Err(self.fail(ScriptError::SchnorrSigHashType));
        }

        let spent_outputs = self
            .spent_outputs
            .as_ref()
            .ok_or(Error::ERR_SPENT_OUTPUTS_REQUIRED)?;
        let prevouts = Prevouts::All(spent_outputs.txouts());
        let annex = self.exec_data.annex.clone();

        let sighash_res = {
            let mut cache = self.sighash_cache.borrow_mut();
            cache.taproot_signature_hash(
                self.input_index,
                &prevouts,
                annex,
                leaf_hash,
                sighash_type,
            )
        };
        let sighash = sighash_res.map_err(|_| self.fail(ScriptError::SchnorrSigHashType))?;
        let message = <Message as From<_>>::from(sighash);
        let is_valid = with_secp256k1_verification_ctx(|secp| {
            secp.verify_schnorr(signature, &message, pubkey).is_ok()
        });
        Ok(is_valid)
    }

    fn verify_ecdsa_signature(
        &mut self,
        sig_parts: Option<SignatureParts>,
        pubkey_bytes: &[u8],
        script_code: &Script,
        sigversion: SigVersion,
    ) -> Result<bool, Error> {
        let pubkey = match PublicKey::from_slice(pubkey_bytes) {
            Ok(pk) => pk,
            Err(_) => return Ok(false),
        };

        let Some(SignatureParts {
            signature,
            sighash_type,
        }) = sig_parts
        else {
            return Ok(false);
        };
        let mut normalized_sig = signature;
        normalized_sig.normalize_s();

        let raw_sighash_type = sighash_type;
        let message = match sigversion {
            SigVersion::Base => {
                let sighash = self
                    .sighash_cache
                    .borrow()
                    .legacy_signature_hash(self.input_index, script_code, raw_sighash_type)
                    .map_err(|_| Error::ERR_SCRIPT)?;
                <Message as From<_>>::from(sighash)
            }
            SigVersion::WitnessV0 => {
                let sighash = self.segwit_v0_signature_hash(script_code, raw_sighash_type)?;
                <Message as From<_>>::from(sighash)
            }
            SigVersion::Taproot => return Err(Error::ERR_SCRIPT),
        };

        let is_valid = with_secp256k1_verification_ctx(|secp| {
            secp.verify_ecdsa(&message, &normalized_sig, &pubkey)
                .is_ok()
        });
        Ok(is_valid)
    }

    fn apply_legacy_find_and_delete(
        &mut self,
        script_code: &Script,
        signatures: &[&[u8]],
    ) -> Result<ScriptBuf, Error> {
        let mut script_bytes = script_code.as_bytes().to_vec();
        for signature in signatures {
            let sig_push = single_push_script(signature).map_err(|_| Error::ERR_SCRIPT)?;
            let (filtered, removed) = find_and_delete(&script_bytes, sig_push.as_bytes());
            if removed > 0 && self.flags.bits() & VERIFY_CONST_SCRIPTCODE != 0 {
                return Err(self.fail(ScriptError::SigFindAndDelete));
            }
            script_bytes = filtered;
        }
        Ok(ScriptBuf::from_bytes(script_bytes))
    }

    fn segwit_v0_signature_hash(
        &mut self,
        script_code: &Script,
        raw_sighash_type: u32,
    ) -> Result<SegwitV0Sighash, Error> {
        // Match Bitcoin Core's WITNESS_V0 SignatureHash path exactly by committing the raw
        // hashtype byte and branching on the raw low 5 bits.
        const SIGHASH_ANYONECANPAY: u32 = 0x80;
        const SIGHASH_BASE_MASK: u32 = 0x1f;
        const SIGHASH_NONE: u32 = 0x02;
        const SIGHASH_SINGLE: u32 = 0x03;

        let precomputed = self.ensure_precomputed().clone();
        let tx = self.tx_ctx.tx();
        let txin = tx.input.get(self.input_index).ok_or(Error::ERR_SCRIPT)?;
        let base_sighash = raw_sighash_type & SIGHASH_BASE_MASK;

        let zero_hash = sha256d::Hash::all_zeros();
        let hash_prevouts = if raw_sighash_type & SIGHASH_ANYONECANPAY == 0 {
            precomputed
                .hash_prevouts
                .unwrap_or_else(|| Self::hash_prevouts_double_sha(tx))
        } else {
            zero_hash
        };
        let hash_sequence = if raw_sighash_type & SIGHASH_ANYONECANPAY == 0
            && base_sighash != SIGHASH_SINGLE
            && base_sighash != SIGHASH_NONE
        {
            precomputed
                .hash_sequence
                .unwrap_or_else(|| Self::hash_sequences_double_sha(tx))
        } else {
            zero_hash
        };
        let hash_outputs = if base_sighash != SIGHASH_SINGLE && base_sighash != SIGHASH_NONE {
            precomputed
                .hash_outputs
                .unwrap_or_else(|| Self::hash_outputs_double_sha(tx))
        } else if base_sighash == SIGHASH_SINGLE && self.input_index < tx.output.len() {
            Self::hash_single_output_double_sha(&tx.output[self.input_index])
        } else {
            zero_hash
        };

        let mut engine = SegwitV0Sighash::engine();
        tx.version
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        hash_prevouts
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        hash_sequence
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        txin.previous_output
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        script_code
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        Amount::from_sat(self.amount)
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        txin.sequence
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        hash_outputs
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        tx.lock_time
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        raw_sighash_type
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");

        Ok(SegwitV0Sighash::from_engine(engine))
    }

    fn hash_prevouts_double_sha(tx: &Transaction) -> sha256d::Hash {
        let mut engine = sha256d::Hash::engine();
        for txin in &tx.input {
            txin.previous_output
                .consensus_encode(&mut engine)
                .expect("hash engine writes are infallible");
        }
        sha256d::Hash::from_engine(engine)
    }

    fn hash_sequences_double_sha(tx: &Transaction) -> sha256d::Hash {
        let mut engine = sha256d::Hash::engine();
        for txin in &tx.input {
            txin.sequence
                .consensus_encode(&mut engine)
                .expect("hash engine writes are infallible");
        }
        sha256d::Hash::from_engine(engine)
    }

    fn hash_outputs_double_sha(tx: &Transaction) -> sha256d::Hash {
        let mut engine = sha256d::Hash::engine();
        for txout in &tx.output {
            txout
                .consensus_encode(&mut engine)
                .expect("hash engine writes are infallible");
        }
        sha256d::Hash::from_engine(engine)
    }

    fn hash_single_output_double_sha(output: &bitcoin::TxOut) -> sha256d::Hash {
        let mut engine = sha256d::Hash::engine();
        output
            .consensus_encode(&mut engine)
            .expect("hash engine writes are infallible");
        sha256d::Hash::from_engine(engine)
    }

    fn ensure_precomputed(&mut self) -> &PrecomputedTransactionData {
        if self.precomputed.is_none() {
            self.precomputed = Some(
                self.tx_ctx
                    .build_precomputed(self.spent_outputs.as_ref(), false),
            );
        }
        self.precomputed
            .as_ref()
            .expect("precomputed data initialized")
    }
}

fn cast_to_bool(data: &[u8]) -> bool {
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            if i == data.len() - 1 && byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

fn encode_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut abs_value = value.unsigned_abs();

    while abs_value > 0 {
        result.push((abs_value & 0xff) as u8);
        abs_value >>= 8;
    }

    if let Some(last) = result.last_mut() {
        if *last & 0x80 != 0 {
            result.push(if value < 0 { 0x80 } else { 0x00 });
        } else if value < 0 {
            *last |= 0x80;
        }
    } else {
        result.push(if value < 0 { 0x81 } else { 0x01 });
    }

    result
}

fn parse_scriptnum(bytes: &[u8], minimal: bool, max_len: usize) -> Result<i64, ScriptError> {
    if bytes.len() > max_len {
        return Err(ScriptError::Unknown);
    }
    if minimal && !is_minimally_encoded(bytes, max_len) {
        return Err(ScriptError::Unknown);
    }
    Ok(decode_num(bytes))
}

fn decode_num(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }

    let mut result: i64 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }

    let last = bytes[bytes.len() - 1];
    if last & 0x80 != 0 {
        let mask = !(0x80i64 << (8 * (bytes.len() - 1)));
        -(result & mask)
    } else {
        result
    }
}

fn is_minimally_encoded(bytes: &[u8], max_len: usize) -> bool {
    if bytes.len() > max_len {
        return false;
    }
    if bytes.is_empty() {
        return true;
    }

    let last = bytes[bytes.len() - 1];
    if (last & 0x7f) == 0 {
        if bytes.len() == 1 {
            return false;
        }
        if bytes[bytes.len() - 2] & 0x80 == 0 {
            return false;
        }
    }

    true
}

fn is_push_only(script_bytes: &[u8]) -> bool {
    Script::from_bytes(script_bytes).is_push_only()
}

fn is_p2sh(script_bytes: &[u8]) -> bool {
    Script::from_bytes(script_bytes).is_p2sh()
}

fn witness_program(script_bytes: &[u8]) -> Option<(u8, &[u8])> {
    let script = Script::from_bytes(script_bytes);
    let version = match script.witness_version() {
        Some(ver) => ver,
        None => {
            return None;
        }
    };
    if script_bytes.len() < 4 {
        return None;
    }
    Some((version.to_num(), &script_bytes[2..]))
}

fn is_pay_to_anchor(version: u8, program: &[u8]) -> bool {
    version == 1 && program.len() == 2 && program[0] == 0x4e && program[1] == 0x73
}

fn single_push_script(
    data: &[u8],
) -> Result<ScriptBuf, bitcoin::blockdata::script::PushBytesError> {
    let push = PushBytesBuf::try_from(data.to_vec())?;
    Ok(Builder::new().push_slice(push).into_script())
}

fn is_control_flow(op: Opcode) -> bool {
    use all::*;

    matches!(op, OP_IF | OP_NOTIF | OP_ELSE | OP_ENDIF)
}

fn is_minimal_if_condition(data: &[u8]) -> bool {
    data.len() == 1 && data[0] == 1
}

fn is_minimal_push(opcode: u8, data: &[u8]) -> bool {
    use all::*;

    if data.is_empty() {
        return opcode == OP_PUSHBYTES_0.to_u8();
    }

    if data.len() == 1 {
        let value = data[0];
        if value == 0x81 {
            return opcode == OP_PUSHNUM_NEG1.to_u8();
        }
        if (1..=16).contains(&value) {
            return opcode == OP_PUSHNUM_1.to_u8() + value - 1;
        }
    }

    if data.len() <= 75 {
        return opcode as usize == data.len();
    }
    if data.len() <= 0xff {
        return opcode == OP_PUSHDATA1.to_u8();
    }
    if data.len() <= 0xffff {
        return opcode == OP_PUSHDATA2.to_u8();
    }
    opcode == OP_PUSHDATA4.to_u8()
}

fn strip_opcode(script_bytes: &[u8], opcode: Opcode) -> Result<Vec<u8>, Error> {
    let script = Script::from_bytes(script_bytes);
    let instructions = script
        .instruction_indices()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::ERR_SCRIPT)?;
    let mut stripped = Vec::with_capacity(script_bytes.len());

    for (idx, (pos, instruction)) in instructions.iter().enumerate() {
        if matches!(instruction, Instruction::Op(op) if *op == opcode) {
            continue;
        }
        let next_pos = if idx + 1 < instructions.len() {
            instructions[idx + 1].0
        } else {
            script_bytes.len()
        };
        stripped.extend_from_slice(&script_bytes[*pos..next_pos]);
    }

    Ok(stripped)
}

fn find_and_delete(script_bytes: &[u8], pattern: &[u8]) -> (Vec<u8>, usize) {
    if pattern.is_empty() {
        return (script_bytes.to_vec(), 0);
    }
    if script_bytes.len() < pattern.len() {
        return (script_bytes.to_vec(), 0);
    }

    let mut removed = 0usize;
    let mut result = Vec::with_capacity(script_bytes.len());
    let mut pc = 0usize;
    let mut pc2 = 0usize;
    let end = script_bytes.len();

    loop {
        result.extend_from_slice(&script_bytes[pc2..pc]);
        while pc + pattern.len() <= end && &script_bytes[pc..pc + pattern.len()] == pattern {
            pc += pattern.len();
            removed += 1;
        }
        pc2 = pc;
        let Some(next_pc) = next_instruction_offset(script_bytes, pc) else {
            break;
        };
        pc = next_pc;
    }

    if removed > 0 {
        result.extend_from_slice(&script_bytes[pc2..end]);
        (result, removed)
    } else {
        (script_bytes.to_vec(), 0)
    }
}

fn is_canonical_single_push(script_bytes: &[u8]) -> bool {
    if script_bytes.is_empty() {
        return false;
    }
    let script = Script::from_bytes(script_bytes);
    let mut instructions = script.instructions();
    match instructions.next() {
        Some(Ok(Instruction::PushBytes(_))) => {}
        _ => return false,
    }
    instructions.next().is_none()
}

fn serialized_witness_size(witness: &Witness) -> Option<i64> {
    let mut total: u64 = compact_size_len(witness.len() as u64);
    for element in witness.iter() {
        let len = element.len() as u64;
        total = total.checked_add(compact_size_len(len))?;
        total = total.checked_add(len)?;
    }
    i64::try_from(total).ok()
}

fn compact_size_len(value: u64) -> u64 {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn contains_op_success(script: &Script) -> Result<bool, ScriptError> {
    let bytes = script.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        let opcode = bytes[index];
        index += 1;
        match opcode {
            0x01..=0x4b => {
                let push_len = opcode as usize;
                index = index
                    .checked_add(push_len)
                    .filter(|idx| *idx <= bytes.len())
                    .ok_or(ScriptError::BadOpcode)?;
            }
            0x4c => {
                let len = read_push_length(bytes, &mut index, 1)?;
                skip_push_data(bytes, len, &mut index)?;
            }
            0x4d => {
                let len = read_push_length(bytes, &mut index, 2)?;
                skip_push_data(bytes, len, &mut index)?;
            }
            0x4e => {
                let len = read_push_length(bytes, &mut index, 4)?;
                skip_push_data(bytes, len, &mut index)?;
            }
            _ => {
                if is_op_success(Opcode::from(opcode)) {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

fn read_push_length(bytes: &[u8], index: &mut usize, width: usize) -> Result<usize, ScriptError> {
    if bytes.len() < *index + width {
        return Err(ScriptError::BadOpcode);
    }
    let mut len: usize = 0;
    for i in 0..width {
        len |= (bytes[*index + i] as usize) << (8 * i);
    }
    *index += width;
    Ok(len)
}

fn skip_push_data(bytes: &[u8], len: usize, index: &mut usize) -> Result<(), ScriptError> {
    *index = index
        .checked_add(len)
        .filter(|idx| *idx <= bytes.len())
        .ok_or(ScriptError::BadOpcode)?;
    Ok(())
}

fn next_instruction_offset(script_bytes: &[u8], offset: usize) -> Option<usize> {
    if offset >= script_bytes.len() {
        return None;
    }

    let opcode = script_bytes[offset];
    let mut cursor = offset + 1;
    match opcode {
        0x01..=0x4b => {
            let push_len = opcode as usize;
            cursor = cursor.checked_add(push_len)?;
            if cursor <= script_bytes.len() {
                Some(cursor)
            } else {
                None
            }
        }
        0x4c => {
            let len = *script_bytes.get(cursor)? as usize;
            cursor += 1;
            cursor = cursor.checked_add(len)?;
            (cursor <= script_bytes.len()).then_some(cursor)
        }
        0x4d => {
            let bytes = script_bytes.get(cursor..cursor + 2)?;
            let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
            cursor += 2;
            cursor = cursor.checked_add(len)?;
            (cursor <= script_bytes.len()).then_some(cursor)
        }
        0x4e => {
            let bytes = script_bytes.get(cursor..cursor + 4)?;
            let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            cursor += 4;
            cursor = cursor.checked_add(len)?;
            (cursor <= script_bytes.len()).then_some(cursor)
        }
        _ => Some(cursor),
    }
}

/// Mirrors Bitcoin Core's `IsOpSuccess` table (`src/script/script.cpp`).
/// Keep this in sync with upstream whenever new semantics are assigned to
/// the reserved opcodes.
fn is_op_success(opcode: Opcode) -> bool {
    matches!(
        opcode.to_u8(),
        80
            | 98
            | 126..=129
            | 131..=134
            | 137..=138
            | 141..=142
            | 149..=153
            | 187..=254
    )
}

fn count_sigops_bytes(script_bytes: &[u8], accurate: bool) -> Result<u32, Error> {
    let script = Script::from_bytes(script_bytes);
    count_sigops(script, accurate)
}

fn count_sigops(script: &Script, accurate: bool) -> Result<u32, Error> {
    use all::*;

    let mut total: u32 = 0;
    let mut last_op: Option<Opcode> = None;
    for instruction in script.instructions() {
        let instruction = instruction.map_err(|_| Error::ERR_SCRIPT)?;
        match instruction {
            Instruction::Op(opcode) => {
                match opcode {
                    OP_CHECKSIG | OP_CHECKSIGVERIFY | OP_CHECKSIGADD => {
                        total = total.checked_add(1).ok_or(Error::ERR_SCRIPT)?;
                    }
                    OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                        let add = if accurate {
                            decode_op_n(last_op).unwrap_or(MAX_PUBKEYS_PER_MULTISIG as u32)
                        } else {
                            MAX_PUBKEYS_PER_MULTISIG as u32
                        };
                        total = total.checked_add(add).ok_or(Error::ERR_SCRIPT)?;
                    }
                    _ => {}
                }
                last_op = Some(opcode);
            }
            Instruction::PushBytes(_) => {
                last_op = None;
            }
        }
    }

    Ok(total)
}

fn decode_op_n(opcode: Option<Opcode>) -> Option<u32> {
    use all::*;

    let op = opcode?;
    let value = op.to_u8();
    if value >= OP_PUSHNUM_1.to_u8() && value <= OP_PUSHNUM_16.to_u8() {
        Some((value - OP_PUSHNUM_1.to_u8() + 1) as u32)
    } else {
        None
    }
}

fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }
    if sig[0] != 0x30 {
        return false;
    }
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }

    let len_r = sig[3] as usize;
    if 5 + len_r >= sig.len() {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;

    if sig[2] != 0x02 {
        return false;
    }
    if len_r == 0 {
        return false;
    }
    if sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0 {
        return false;
    }

    if sig[len_r + 4] != 0x02 {
        return false;
    }
    if len_s == 0 {
        return false;
    }
    if len_r + len_s + 7 != sig.len() {
        return false;
    }
    if sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && (sig[len_r + 7] & 0x80) == 0 {
        return false;
    }
    true
}

fn is_defined_hashtype_signature(sig: &[u8]) -> bool {
    if sig.is_empty() {
        return false;
    }
    let base = sig[sig.len() - 1] & !0x80;
    matches!(base, 0x01..=0x03)
}

fn is_low_der_signature(sig: &[u8]) -> bool {
    if !is_valid_signature_encoding(sig) || sig.len() < 2 {
        return false;
    }

    let sig_bytes = &sig[..sig.len() - 1];
    let Ok(signature) = EcdsaSignature::from_der(sig_bytes) else {
        return false;
    };
    let mut normalized = signature;
    normalized.normalize_s();
    normalized == signature
}

fn is_valid_pubkey_encoding(pubkey: &[u8]) -> bool {
    if pubkey.len() == 33 {
        matches!(pubkey[0], 0x02 | 0x03)
    } else if pubkey.len() == 65 {
        pubkey[0] == 0x04
    } else {
        false
    }
}

fn is_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && matches!(pubkey[0], 0x02 | 0x03)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VERIFY_DERSIG, VERIFY_P2SH, VERIFY_SIGPUSHONLY, VERIFY_TAPROOT, VERIFY_WITNESS};
    use bitcoin::{
        blockdata::script::{Builder, PushBytesBuf},
        consensus,
        hashes::{sha256, Hash},
        hex::FromHex,
        opcodes::all,
        transaction::Version,
        Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    #[test]
    fn rejects_unknown_flags() {
        let invalid_bit = 1 << 31;
        ScriptFlags::from_bits(invalid_bit).expect_err("invalid flag");
    }

    #[test]
    fn requires_spent_outputs_for_taproot() {
        let flags = ScriptFlags::from_bits(VERIFY_TAPROOT).unwrap();
        assert!(flags.requires_spent_outputs());
    }

    #[test]
    fn flag_roundtrip_without_implied_bits_is_lossless() {
        let bits = VERIFY_P2SH | VERIFY_SIGPUSHONLY | VERIFY_DERSIG;
        let flags = ScriptFlags::from_bits(bits).unwrap();
        assert_eq!(flags.bits(), bits);
    }

    #[test]
    fn witness_flag_does_not_imply_p2sh() {
        let flags = ScriptFlags::from_bits(VERIFY_WITNESS).unwrap();
        assert_eq!(flags.bits(), VERIFY_WITNESS);
    }

    #[test]
    fn taproot_flag_does_not_imply_witness_helpers() {
        let flags = ScriptFlags::from_bits(VERIFY_TAPROOT).unwrap();
        assert_eq!(flags.bits(), VERIFY_TAPROOT);
        assert!(flags.requires_spent_outputs());
    }

    #[test]
    fn truncated_push_is_error() {
        let script = ScriptBuf::from_bytes(vec![0x4c, 0x01]);
        let instructions: Result<Vec<_>, _> = script.instruction_indices().collect();
        assert!(instructions.is_err());
    }

    #[test]
    fn sigop_counter_counts_checksig_ops() {
        let script = Builder::new()
            .push_opcode(all::OP_DUP)
            .push_opcode(all::OP_CHECKSIG)
            .push_opcode(all::OP_CHECKSIGVERIFY)
            .into_script();
        assert_eq!(count_sigops_bytes(script.as_bytes(), true).unwrap(), 2);
        assert_eq!(count_sigops_bytes(script.as_bytes(), false).unwrap(), 2);
    }

    #[test]
    fn sigop_counter_handles_multisig_precision() {
        let key1 = PushBytesBuf::try_from(vec![0x02; 33]).unwrap();
        let key2 = PushBytesBuf::try_from(vec![0x03; 33]).unwrap();
        let script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_2)
            .push_slice(key1)
            .push_slice(key2)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(count_sigops_bytes(script.as_bytes(), true).unwrap(), 2);
        assert_eq!(
            count_sigops_bytes(script.as_bytes(), false).unwrap(),
            MAX_PUBKEYS_PER_MULTISIG as u32
        );
    }

    #[test]
    fn sigop_counter_rejects_malformed_pushdata() {
        let malformed = ScriptBuf::from_bytes(vec![all::OP_PUSHDATA1.to_u8(), 0x01]);
        assert!(count_sigops_bytes(malformed.as_bytes(), true).is_err());
    }

    #[test]
    fn witness_v0_p2wpkh_path_charges_single_sigop() {
        let witness = Witness::from(vec![vec![], vec![0x02; 33]]);
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let tx_bytes = consensus::serialize(&tx);
        let tx_ctx = TransactionContext::parse(&tx_bytes).expect("parse tx");
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spend_context = SpendContext::new(spent_script.as_bytes(), None, 0, true);
        let flags = ScriptFlags::from_bits(VERIFY_WITNESS | VERIFY_P2SH).expect("flags");
        let mut interpreter = Interpreter::new(&tx_ctx, 0, spend_context, flags).expect("interpreter");

        let program = [0u8; 20];
        let _ = interpreter.execute_witness_program(0, &program, &tx_ctx.tx().input[0].witness, false);
        assert_eq!(interpreter.sigops, 1);
    }

    #[test]
    fn witness_v0_p2wsh_path_charges_redeem_sigops() {
        let witness_script = Builder::new()
            .push_opcode(all::OP_CHECKSIG)
            .push_opcode(all::OP_CHECKSIGVERIFY)
            .into_script();
        let witness_script_bytes = witness_script.as_bytes().to_vec();
        let witness_program = sha256::Hash::hash(&witness_script_bytes);
        let witness = Witness::from(vec![vec![], vec![0x02; 33], witness_script_bytes]);
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let tx_bytes = consensus::serialize(&tx);
        let tx_ctx = TransactionContext::parse(&tx_bytes).expect("parse tx");
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spend_context = SpendContext::new(spent_script.as_bytes(), None, 0, true);
        let flags = ScriptFlags::from_bits(VERIFY_WITNESS | VERIFY_P2SH).expect("flags");
        let mut interpreter = Interpreter::new(&tx_ctx, 0, spend_context, flags).expect("interpreter");

        let _ = interpreter.execute_witness_program(
            0,
            &witness_program.to_byte_array(),
            &tx_ctx.tx().input[0].witness,
            false,
        );
        assert_eq!(interpreter.sigops, 2);
    }

    #[test]
    fn p2sh_redeem_script_sigops_use_accurate_multisig_count() {
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
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
        let tx_bytes = consensus::serialize(&tx);
        let tx_ctx = TransactionContext::parse(&tx_bytes).expect("parse tx");
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let spend_context = SpendContext::new(spent_script.as_bytes(), None, 0, true);
        let flags = ScriptFlags::from_bits(VERIFY_P2SH).expect("flags");
        let mut interpreter = Interpreter::new(&tx_ctx, 0, spend_context, flags).expect("interpreter");

        let key1 = PushBytesBuf::try_from(vec![0x02; 33]).unwrap();
        let key2 = PushBytesBuf::try_from(vec![0x03; 33]).unwrap();
        let redeem_script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_2)
            .push_slice(key1)
            .push_slice(key2)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();
        interpreter
            .add_sigops_from_script(redeem_script.as_bytes(), true)
            .expect("sigop counting");
        assert_eq!(interpreter.sigops, 2);
    }

    #[test]
    fn find_and_delete_matches_whole_pushes() {
        let pattern = single_push_script(&[0x02, 0x03]).unwrap();
        let script = Builder::new()
            .push_slice(PushBytesBuf::try_from(vec![0x02, 0x03]).unwrap())
            .push_opcode(all::OP_ADD)
            .push_slice(PushBytesBuf::try_from(vec![0x02, 0x03]).unwrap())
            .into_script();
        let (stripped, removed) = find_and_delete(script.as_bytes(), pattern.as_bytes());
        assert_eq!(removed, 2);
        assert_eq!(stripped, vec![all::OP_ADD.to_u8()]);
    }

    #[test]
    fn find_and_delete_does_not_match_sub_slices() {
        let pattern = single_push_script(&[0xaa]).unwrap();
        let script = Builder::new()
            .push_slice(PushBytesBuf::try_from(vec![0xaa, 0xbb]).unwrap())
            .into_script();
        let (stripped, removed) = find_and_delete(script.as_bytes(), pattern.as_bytes());
        assert_eq!(removed, 0);
        assert_eq!(stripped, script.as_bytes());
    }

    #[test]
    fn find_and_delete_matches_only_instruction_boundaries() {
        let pattern = single_push_script(&[]).unwrap();
        let script = ScriptBuf::from_bytes(vec![0x02, 0x00, 0x11, 0x00]);
        let (stripped, removed) = find_and_delete(script.as_bytes(), pattern.as_bytes());
        assert_eq!(removed, 1);
        assert_eq!(stripped, vec![0x02, 0x00, 0x11]);
    }

    #[test]
    fn find_and_delete_core_edge_cases_matrix() {
        let check =
            |script: Vec<u8>, pattern: Vec<u8>, expected: Vec<u8>, expected_removed: usize| {
                let (stripped, removed) = find_and_delete(&script, &pattern);
                assert_eq!(removed, expected_removed);
                assert_eq!(stripped, expected);
            };

        check(
            vec![all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_2.to_u8()],
            vec![],
            vec![all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_2.to_u8()],
            0,
        );
        check(
            vec![
                all::OP_PUSHNUM_1.to_u8(),
                all::OP_PUSHNUM_2.to_u8(),
                all::OP_PUSHNUM_3.to_u8(),
            ],
            vec![all::OP_PUSHNUM_2.to_u8()],
            vec![all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_3.to_u8()],
            1,
        );
        check(
            vec![
                all::OP_PUSHNUM_3.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
                all::OP_PUSHNUM_3.to_u8(),
                all::OP_PUSHNUM_3.to_u8(),
                all::OP_PUSHNUM_4.to_u8(),
                all::OP_PUSHNUM_3.to_u8(),
            ],
            vec![all::OP_PUSHNUM_3.to_u8()],
            vec![all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_4.to_u8()],
            4,
        );
        check(
            Vec::from_hex("0302ff03").unwrap(),
            Vec::from_hex("0302ff03").unwrap(),
            vec![],
            1,
        );
        check(
            Vec::from_hex("0302ff030302ff03").unwrap(),
            Vec::from_hex("0302ff03").unwrap(),
            vec![],
            2,
        );
        check(
            Vec::from_hex("0302ff030302ff03").unwrap(),
            Vec::from_hex("02").unwrap(),
            Vec::from_hex("0302ff030302ff03").unwrap(),
            0,
        );
        check(
            Vec::from_hex("0302ff030302ff03").unwrap(),
            Vec::from_hex("ff").unwrap(),
            Vec::from_hex("0302ff030302ff03").unwrap(),
            0,
        );
        check(
            Vec::from_hex("0302ff030302ff03").unwrap(),
            Vec::from_hex("03").unwrap(),
            Vec::from_hex("02ff0302ff03").unwrap(),
            2,
        );
        check(
            Vec::from_hex("02feed5169").unwrap(),
            Vec::from_hex("feed51").unwrap(),
            Vec::from_hex("02feed5169").unwrap(),
            0,
        );
        check(
            Vec::from_hex("02feed5169").unwrap(),
            Vec::from_hex("02feed51").unwrap(),
            Vec::from_hex("69").unwrap(),
            1,
        );
        check(
            Vec::from_hex("516902feed5169").unwrap(),
            Vec::from_hex("feed51").unwrap(),
            Vec::from_hex("516902feed5169").unwrap(),
            0,
        );
        check(
            Vec::from_hex("516902feed5169").unwrap(),
            Vec::from_hex("02feed51").unwrap(),
            Vec::from_hex("516969").unwrap(),
            1,
        );
        check(
            vec![
                all::OP_PUSHBYTES_0.to_u8(),
                all::OP_PUSHBYTES_0.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
            ],
            vec![all::OP_PUSHBYTES_0.to_u8(), all::OP_PUSHNUM_1.to_u8()],
            vec![all::OP_PUSHBYTES_0.to_u8(), all::OP_PUSHNUM_1.to_u8()],
            1,
        );
        check(
            vec![
                all::OP_PUSHBYTES_0.to_u8(),
                all::OP_PUSHBYTES_0.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
                all::OP_PUSHBYTES_0.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
                all::OP_PUSHNUM_1.to_u8(),
            ],
            vec![all::OP_PUSHBYTES_0.to_u8(), all::OP_PUSHNUM_1.to_u8()],
            vec![all::OP_PUSHBYTES_0.to_u8(), all::OP_PUSHNUM_1.to_u8()],
            2,
        );
        check(
            Vec::from_hex("0003feed").unwrap(),
            Vec::from_hex("03feed").unwrap(),
            Vec::from_hex("00").unwrap(),
            1,
        );
        check(
            Vec::from_hex("0003feed").unwrap(),
            Vec::from_hex("00").unwrap(),
            Vec::from_hex("03feed").unwrap(),
            1,
        );
    }

    #[test]
    fn script_identity_depends_on_script_content() {
        let a = ScriptBuf::from_bytes(vec![all::OP_PUSHNUM_1.to_u8()]);
        let b = ScriptBuf::from_bytes(vec![all::OP_PUSHNUM_2.to_u8()]);
        assert_eq!(a.as_bytes().len(), b.as_bytes().len());
        assert!(ScriptIdentity::new(a.as_script()) != ScriptIdentity::new(b.as_script()));
    }

    #[test]
    fn precomputed_is_lazy_for_no_signature_paths() {
        let spent_script = Builder::new().push_opcode(all::OP_PUSHNUM_1).into_script();
        let tx = Transaction {
            version: Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
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
        let tx_bytes = consensus::serialize(&tx);
        let tx_ctx = TransactionContext::parse(&tx_bytes).expect("parse tx");
        let spend_context = SpendContext::new(spent_script.as_bytes(), None, 0, true);
        let flags = ScriptFlags::from_bits(0).expect("flags");
        let mut interpreter = Interpreter::new(&tx_ctx, 0, spend_context, flags).expect("new");

        interpreter.verify().expect("op_true spend should validate");
        assert!(
            interpreter.precomputed.is_none(),
            "precomputed data should not be built when no signature opcodes execute"
        );
    }

    #[test]
    fn scriptnum_overflow_maps_to_unknown() {
        let overflow = vec![0x00, 0x00, 0x00, 0x80, 0x00];
        let err = parse_scriptnum(&overflow, false, SCRIPTNUM_MAX_LEN).unwrap_err();
        assert_eq!(err, ScriptError::Unknown);
    }

    #[test]
    fn scriptnum_minimal_violation_maps_to_unknown() {
        let non_minimal = vec![0x01, 0x00];
        let err = parse_scriptnum(&non_minimal, true, SCRIPTNUM_MAX_LEN).unwrap_err();
        assert_eq!(err, ScriptError::Unknown);
        let ok = parse_scriptnum(&non_minimal, false, SCRIPTNUM_MAX_LEN).unwrap();
        assert_eq!(ok, 1);
    }

    #[test]
    fn strictenc_hashtype_mask_matches_core() {
        // Core masks only SIGHASH_ANYONECANPAY in strict hashtype checks.
        assert!(is_defined_hashtype_signature(&[0x01]));
        assert!(is_defined_hashtype_signature(&[0x81]));
        assert!(!is_defined_hashtype_signature(&[0x21]));
        assert!(!is_defined_hashtype_signature(&[0x41]));
    }

    #[test]
    fn script_code_materialization_depends_on_sigversion() {
        let script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_opcode(all::OP_CODESEPARATOR)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_CODESEPARATOR)
            .into_script();

        let base = Interpreter::materialize_script_code(script.as_script(), 0, true)
            .expect("base script code materializes");
        assert_eq!(
            base.as_bytes(),
            &[all::OP_PUSHNUM_1.to_u8(), all::OP_PUSHNUM_2.to_u8()]
        );

        let witness_v0 = Interpreter::materialize_script_code(script.as_script(), 0, false)
            .expect("witness v0 script code materializes");
        assert_eq!(witness_v0.as_bytes(), script.as_bytes());
    }
}
