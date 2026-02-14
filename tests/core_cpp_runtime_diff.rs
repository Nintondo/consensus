#![cfg(feature = "core-diff")]

mod script_asm;

use bitcoin::{
    absolute::LockTime,
    consensus as btc_consensus,
    hashes::Hash,
    hex::FromHex,
    opcodes::all,
    transaction::Version,
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use consensus::{
    verify_with_flags_detailed, Utxo, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_DERSIG, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
};
use libloading::Library;
use script_asm::parse_script;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    env,
    ffi::c_int,
    fs,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    str::FromStr,
};

const SCRIPT_TESTS_JSON: &str = include_str!("data/script_tests.json");
const CORE_TX_VALID: &str = include_str!("data/tx_valid.json");
const CORE_TX_INVALID: &str = include_str!("data/tx_invalid.json");

const CORE_CPP_SUPPORTED_FLAGS: u32 = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_TAPROOT;

const ALL_TX_VECTOR_FLAGS: u32 = consensus::VERIFY_P2SH
    | consensus::VERIFY_STRICTENC
    | consensus::VERIFY_DERSIG
    | consensus::VERIFY_LOW_S
    | consensus::VERIFY_SIGPUSHONLY
    | consensus::VERIFY_MINIMALDATA
    | consensus::VERIFY_NULLDUMMY
    | consensus::VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    | consensus::VERIFY_CLEANSTACK
    | consensus::VERIFY_MINIMALIF
    | consensus::VERIFY_NULLFAIL
    | consensus::VERIFY_CHECKLOCKTIMEVERIFY
    | consensus::VERIFY_CHECKSEQUENCEVERIFY
    | consensus::VERIFY_WITNESS
    | consensus::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | consensus::VERIFY_WITNESS_PUBKEYTYPE
    | consensus::VERIFY_CONST_SCRIPTCODE
    | consensus::VERIFY_TAPROOT
    | consensus::VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
    | consensus::VERIFY_DISCOURAGE_OP_SUCCESS
    | consensus::VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION;

#[repr(C)]
#[derive(Clone, Copy)]
struct CoreUtxo {
    script_pubkey: *const u8,
    script_pubkey_len: u32,
    value: i64,
}

type VerifyWithAmountFn = unsafe extern "C" fn(
    *const u8,
    u32,
    i64,
    *const u8,
    u32,
    u32,
    u32,
    *mut c_int,
) -> c_int;

type VerifyWithSpentOutputsFn = unsafe extern "C" fn(
    *const u8,
    u32,
    i64,
    *const u8,
    u32,
    *const CoreUtxo,
    u32,
    u32,
    u32,
    *mut c_int,
) -> c_int;

type VersionFn = unsafe extern "C" fn() -> u32;

#[derive(Default)]
struct RuntimeDiffStats {
    compared_inputs: usize,
    script_vectors_compared: usize,
    tx_valid_vectors_compared: usize,
    tx_invalid_vectors_compared: usize,
    targeted_cases_compared: usize,
    skipped_noncanonical_flags: usize,
    skipped_unsupported_flags: usize,
    skipped_unknown_tokens: usize,
    skipped_placeholder_vectors: usize,
    skipped_taproot_without_spent_outputs_support: usize,
    skipped_parse_failures: usize,
    skipped_missing_prevouts: usize,
    token_skip_counts: BTreeMap<String, usize>,
}

#[derive(Clone)]
struct PrevoutData {
    script_pubkey: ScriptBuf,
    amount_sat: u64,
}

#[derive(Debug)]
enum FlagParseError {
    UnknownToken(String),
}

#[derive(Debug)]
enum TxVectorFlagParse {
    Parsed(u32),
    SkipBadTx,
    SkipUnknown(String),
}

struct CoreCppHarness {
    backend: CoreCppBackend,
}

enum CoreCppBackend {
    LegacyLib(LegacyConsensusLib),
    Helper(CoreCppHelperProcess),
}

struct LegacyConsensusLib {
    lib: Library,
    library_path: PathBuf,
    version: Option<u32>,
    has_spent_outputs_api: bool,
}

struct CoreCppHelperProcess {
    helper_path: PathBuf,
    _child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl CoreCppHarness {
    fn backend_label(&self) -> String {
        match &self.backend {
            CoreCppBackend::LegacyLib(backend) => format!(
                "legacy-libbitcoinconsensus:{} version={:?}",
                backend.library_path.display(),
                backend.version
            ),
            CoreCppBackend::Helper(backend) => {
                format!("core-helper:{}", backend.helper_path.display())
            }
        }
    }

    fn has_spent_outputs_api(&self) -> bool {
        match &self.backend {
            CoreCppBackend::LegacyLib(backend) => backend.has_spent_outputs_api,
            CoreCppBackend::Helper(_) => true,
        }
    }

    fn discover_helper_binary_path() -> Option<PathBuf> {
        let Ok(path) = env::var("CORE_CPP_DIFF_HELPER_BIN") else {
            return None;
        };
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            Some(candidate)
        } else {
            None
        }
    }

    fn helper_project_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("core_cpp_helper")
    }

    fn helper_binary_candidates(build_dir: &Path) -> [PathBuf; 2] {
        [
            build_dir.join("core_consensus_helper"),
            build_dir.join("bin").join("core_consensus_helper"),
        ]
    }

    fn run_command(mut cmd: Command, context: &str) -> Result<(), String> {
        let output = cmd
            .output()
            .map_err(|err| format!("{context} failed to start: {err}"))?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!(
            "{context} failed (status={}): stdout=`{}` stderr=`{}`",
            output
                .status
                .code()
                .map_or_else(|| "signal".to_string(), |code| code.to_string()),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    fn maybe_build_helper() -> Result<Option<PathBuf>, String> {
        let enabled = env::var("CORE_CPP_DIFF_BUILD_HELPER").ok().as_deref() == Some("1");
        if !enabled {
            return Ok(None);
        }
        let core_repo = env::var("BITCOIN_CORE_REPO")
            .map(PathBuf::from)
            .map_err(|_| {
                "CORE_CPP_DIFF_BUILD_HELPER=1 requires BITCOIN_CORE_REPO to point at a local Core checkout"
                    .to_string()
            })?;
        if !core_repo.exists() {
            return Err(format!(
                "BITCOIN_CORE_REPO does not exist: {}",
                core_repo.display()
            ));
        }

        let helper_project = Self::helper_project_dir();
        if !helper_project.exists() {
            return Err(format!(
                "helper project directory missing: {}",
                helper_project.display()
            ));
        }

        let build_dir = env::var("CORE_CPP_DIFF_HELPER_BUILD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                env::temp_dir()
                    .join("consensus")
                    .join("core_cpp_helper_build")
            });
        fs::create_dir_all(&build_dir).map_err(|err| {
            format!(
                "failed to create helper build directory {}: {err}",
                build_dir.display()
            )
        })?;

        let mut configure = Command::new("cmake");
        configure
            .arg("-S")
            .arg(&helper_project)
            .arg("-B")
            .arg(&build_dir)
            .arg(format!("-DBITCOIN_CORE_REPO={}", core_repo.display()));
        Self::run_command(configure, "cmake configure for core helper")?;

        let mut build = Command::new("cmake");
        build
            .arg("--build")
            .arg(&build_dir)
            .arg("--target")
            .arg("core_consensus_helper")
            .arg("-j4");
        Self::run_command(build, "cmake build for core helper")?;

        for candidate in Self::helper_binary_candidates(&build_dir) {
            if candidate.exists() {
                return Ok(Some(candidate));
            }
        }
        Err(format!(
            "helper build succeeded but no helper binary found in {}",
            build_dir.display()
        ))
    }

    fn discover_library_path() -> Option<PathBuf> {
        if let Ok(path) = env::var("CORE_CPP_CONSENSUS_LIB") {
            let candidate = PathBuf::from(path);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        if let Ok(path) = env::var("BITCOINCONSENSUS_LIB") {
            let candidate = PathBuf::from(path);
            if candidate.exists() {
                return Some(candidate);
            }
        }

        let Ok(repo) = env::var("BITCOIN_CORE_REPO") else {
            return None;
        };
        let repo = PathBuf::from(repo);
        let candidates = [
            repo.join("build/src/libbitcoinconsensus.so"),
            repo.join("build/src/libbitcoinconsensus.dylib"),
            repo.join("build/lib/libbitcoinconsensus.so"),
            repo.join("build/lib/libbitcoinconsensus.dylib"),
            repo.join("src/.libs/libbitcoinconsensus.so"),
            repo.join("src/.libs/libbitcoinconsensus.dylib"),
            repo.join("src/libbitcoinconsensus.so"),
            repo.join("src/libbitcoinconsensus.dylib"),
        ];
        candidates.into_iter().find(|path| path.exists())
    }

    fn from_library(path: PathBuf) -> Result<Self, String> {
        // SAFETY: Loading a dynamic library is inherently unsafe; we validate the required symbols below.
        let lib = unsafe { Library::new(&path) }
            .map_err(|err| format!("failed to load {}: {err}", path.display()))?;

        // SAFETY: Symbol lookup checks existence; function pointer types match the C header ABI.
        let _verify_with_amount = unsafe {
            lib.get::<VerifyWithAmountFn>(b"bitcoinconsensus_verify_script_with_amount\0")
        }
        .map_err(|err| {
            format!(
                "library {} does not expose bitcoinconsensus_verify_script_with_amount: {err}",
                path.display()
            )
        })?;

        // SAFETY: Optional symbol probe, type matches expected ABI.
        let has_spent_outputs_api = unsafe {
            lib.get::<VerifyWithSpentOutputsFn>(b"bitcoinconsensus_verify_script_with_spent_outputs\0")
                .is_ok()
        };

        // SAFETY: Optional symbol probe, type matches expected ABI.
        let version = unsafe {
            lib.get::<VersionFn>(b"bitcoinconsensus_version\0")
                .ok()
                .map(|sym| sym())
        };

        Ok(Self {
            backend: CoreCppBackend::LegacyLib(LegacyConsensusLib {
                lib,
                library_path: path,
                version,
                has_spent_outputs_api,
            }),
        })
    }

    fn from_helper_binary(path: PathBuf) -> Result<Self, String> {
        let mut child = Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|err| format!("failed to launch helper {}: {err}", path.display()))?;
        let child_stdin = child.stdin.take().ok_or_else(|| {
            format!(
                "failed to open stdin for helper process {}",
                path.display()
            )
        })?;
        let child_stdout = child.stdout.take().ok_or_else(|| {
            format!(
                "failed to open stdout for helper process {}",
                path.display()
            )
        })?;
        Ok(Self {
            backend: CoreCppBackend::Helper(CoreCppHelperProcess {
                helper_path: path,
                _child: child,
                stdin: BufWriter::new(child_stdin),
                stdout: BufReader::new(child_stdout),
            }),
        })
    }

    fn from_env() -> Result<Option<Self>, String> {
        let backend_pref = env::var("CORE_CPP_DIFF_BACKEND").ok();

        let helper_candidate = if let Some(path) = Self::discover_helper_binary_path() {
            Some(path)
        } else {
            Self::maybe_build_helper()?
        };
        let lib_candidate = Self::discover_library_path();

        match backend_pref.as_deref() {
            Some("helper") => {
                if let Some(path) = helper_candidate {
                    return Self::from_helper_binary(path).map(Some);
                }
                return Err(
                    "CORE_CPP_DIFF_BACKEND=helper but no helper binary was found \
                     (set CORE_CPP_DIFF_HELPER_BIN or CORE_CPP_DIFF_BUILD_HELPER=1 with BITCOIN_CORE_REPO)"
                        .to_string(),
                );
            }
            Some("lib") => {
                if let Some(path) = lib_candidate {
                    return Self::from_library(path).map(Some);
                }
                return Err(
                    "CORE_CPP_DIFF_BACKEND=lib but no legacy libbitcoinconsensus shared library was found \
                     (set CORE_CPP_CONSENSUS_LIB/BITCOINCONSENSUS_LIB)"
                        .to_string(),
                );
            }
            Some(other) => {
                return Err(format!(
                    "invalid CORE_CPP_DIFF_BACKEND={other}; expected one of: helper, lib"
                ));
            }
            None => {}
        }

        if let Some(path) = helper_candidate {
            return Self::from_helper_binary(path).map(Some);
        }
        if let Some(path) = lib_candidate {
            return Self::from_library(path).map(Some);
        }
        Ok(None)
    }

    fn verify(
        &mut self,
        script_pubkey: &[u8],
        amount_sat: u64,
        tx_bytes: &[u8],
        spent_outputs: Option<&[CoreUtxo]>,
        input_index: usize,
        flags: u32,
    ) -> Result<(bool, i32), String> {
        match &mut self.backend {
            CoreCppBackend::LegacyLib(backend) => backend.verify(
                script_pubkey,
                amount_sat,
                tx_bytes,
                spent_outputs,
                input_index,
                flags,
            ),
            CoreCppBackend::Helper(backend) => backend.verify(
                script_pubkey,
                amount_sat,
                tx_bytes,
                spent_outputs,
                input_index,
                flags,
            ),
        }
    }
}

impl LegacyConsensusLib {
    fn verify(
        &self,
        script_pubkey: &[u8],
        amount_sat: u64,
        tx_bytes: &[u8],
        spent_outputs: Option<&[CoreUtxo]>,
        input_index: usize,
        flags: u32,
    ) -> Result<(bool, i32), String> {
        let mut err_code = 0i32;
        let amount_i64: i64 = amount_sat
            .try_into()
            .map_err(|_| format!("amount does not fit in i64: {amount_sat}"))?;
        let tx_len: u32 = tx_bytes
            .len()
            .try_into()
            .map_err(|_| format!("tx too large for C API length field: {}", tx_bytes.len()))?;
        let spk_len: u32 = script_pubkey.len().try_into().map_err(|_| {
            format!(
                "scriptPubKey too large for C API length field: {}",
                script_pubkey.len()
            )
        })?;
        let n_in: u32 = input_index
            .try_into()
            .map_err(|_| format!("input index does not fit u32: {input_index}"))?;

        if let Some(spent) = spent_outputs {
            if self.has_spent_outputs_api {
                // SAFETY: Symbol exists and pointer/length pairs are valid for the lifetime of this call.
                let verify = unsafe {
                    self.lib
                        .get::<VerifyWithSpentOutputsFn>(
                            b"bitcoinconsensus_verify_script_with_spent_outputs\0",
                        )
                        .map_err(|err| format!("failed to load spent-outputs symbol: {err}"))?
                };
                let spent_len: u32 = spent.len().try_into().map_err(|_| {
                    format!(
                        "spent outputs length does not fit C API field: {}",
                        spent.len()
                    )
                })?;
                // SAFETY: all pointers are valid and lengths are accurate during this call.
                let ret = unsafe {
                    verify(
                        script_pubkey.as_ptr(),
                        spk_len,
                        amount_i64,
                        tx_bytes.as_ptr(),
                        tx_len,
                        spent.as_ptr(),
                        spent_len,
                        n_in,
                        flags,
                        &mut err_code,
                    )
                };
                return Ok((ret == 1, err_code));
            }
            return Err(
                "bitcoinconsensus_verify_script_with_spent_outputs not available in loaded library"
                    .to_string(),
            );
        }

        // SAFETY: Symbol exists and pointer/length pairs are valid for the lifetime of this call.
        let verify = unsafe {
            self.lib
                .get::<VerifyWithAmountFn>(b"bitcoinconsensus_verify_script_with_amount\0")
                .map_err(|err| format!("failed to load with-amount symbol: {err}"))?
        };
        // SAFETY: all pointers are valid and lengths are accurate during this call.
        let ret = unsafe {
            verify(
                script_pubkey.as_ptr(),
                spk_len,
                amount_i64,
                tx_bytes.as_ptr(),
                tx_len,
                n_in,
                flags,
                &mut err_code,
            )
        };
        Ok((ret == 1, err_code))
    }
}

fn bytes_to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

impl CoreCppHelperProcess {
    fn verify(
        &mut self,
        script_pubkey: &[u8],
        amount_sat: u64,
        tx_bytes: &[u8],
        spent_outputs: Option<&[CoreUtxo]>,
        input_index: usize,
        flags: u32,
    ) -> Result<(bool, i32), String> {
        let mut spent_fields = Vec::new();
        if let Some(spent) = spent_outputs {
            for utxo in spent {
                // SAFETY: The caller provides UTXO pointers to script bytes that remain valid during this call.
                let script = unsafe {
                    core::slice::from_raw_parts(utxo.script_pubkey, utxo.script_pubkey_len as usize)
                };
                spent_fields.push(format!("{}:{}", utxo.value, bytes_to_hex(script)));
            }
        }

        let line = format!(
            "{}|{}|{}|{}|{}|{}|{}\n",
            flags,
            input_index,
            amount_sat,
            bytes_to_hex(script_pubkey),
            bytes_to_hex(tx_bytes),
            spent_fields.len(),
            spent_fields.join(",")
        );
        self.stdin.write_all(line.as_bytes()).map_err(|err| {
            format!(
                "failed to write request to helper {}: {err}",
                self.helper_path.display()
            )
        })?;
        self.stdin.flush().map_err(|err| {
            format!(
                "failed to flush request to helper {}: {err}",
                self.helper_path.display()
            )
        })?;

        let mut response = String::new();
        let bytes_read = self.stdout.read_line(&mut response).map_err(|err| {
            format!(
                "failed to read helper response from {}: {err}",
                self.helper_path.display()
            )
        })?;
        if bytes_read == 0 {
            return Err(format!(
                "helper {} closed stdout unexpectedly",
                self.helper_path.display()
            ));
        }
        let fields: Vec<&str> = response.trim_end().split('|').collect();
        match fields.first().copied() {
            Some("OK") => {
                if fields.len() < 3 {
                    return Err(format!(
                        "malformed helper response from {}: `{}`",
                        self.helper_path.display(),
                        response.trim_end()
                    ));
                }
                let ok = match fields[1] {
                    "1" => true,
                    "0" => false,
                    other => {
                        return Err(format!(
                            "malformed helper success field from {}: `{other}`",
                            self.helper_path.display()
                        ))
                    }
                };
                let err_code = fields[2].parse::<i32>().map_err(|err| {
                    format!(
                        "failed parsing helper error code from {}: {} (`{}`)",
                        self.helper_path.display(),
                        err,
                        fields[2]
                    )
                })?;
                Ok((ok, err_code))
            }
            Some("ERR") => Err(if fields.len() > 1 {
                format!(
                    "core helper runtime error ({}): {}",
                    self.helper_path.display(),
                    fields[1]
                )
            } else {
                format!(
                    "core helper runtime error ({}): unspecified",
                    self.helper_path.display()
                )
            }),
            _ => Err(format!(
                "unexpected helper response from {}: `{}`",
                self.helper_path.display(),
                response.trim_end()
            )),
        }
    }
}

fn fill_flags(flags: u32) -> u32 {
    let mut out = flags;
    if out & consensus::VERIFY_CLEANSTACK != 0 {
        out |= VERIFY_WITNESS;
    }
    if out & VERIFY_WITNESS != 0 {
        out |= VERIFY_P2SH;
    }
    out
}

fn parse_flags(raw: &str) -> Result<u32, FlagParseError> {
    if raw.trim().is_empty() || raw == "NONE" {
        return Ok(0);
    }

    let mut bits = 0u32;
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let bit = match token {
            "P2SH" => consensus::VERIFY_P2SH,
            "STRICTENC" => consensus::VERIFY_STRICTENC,
            "DERSIG" => consensus::VERIFY_DERSIG,
            "LOW_S" => consensus::VERIFY_LOW_S,
            "SIGPUSHONLY" => consensus::VERIFY_SIGPUSHONLY,
            "MINIMALDATA" => consensus::VERIFY_MINIMALDATA,
            "NULLDUMMY" => consensus::VERIFY_NULLDUMMY,
            "DISCOURAGE_UPGRADABLE_NOPS" => consensus::VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            "CLEANSTACK" => consensus::VERIFY_CLEANSTACK,
            "MINIMALIF" => consensus::VERIFY_MINIMALIF,
            "NULLFAIL" => consensus::VERIFY_NULLFAIL,
            "CHECKLOCKTIMEVERIFY" => consensus::VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => consensus::VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => consensus::VERIFY_WITNESS,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                consensus::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
            }
            "WITNESS_PUBKEYTYPE" => consensus::VERIFY_WITNESS_PUBKEYTYPE,
            "CONST_SCRIPTCODE" => consensus::VERIFY_CONST_SCRIPTCODE,
            "TAPROOT" => consensus::VERIFY_TAPROOT,
            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => consensus::VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
            "DISCOURAGE_OP_SUCCESS" => consensus::VERIFY_DISCOURAGE_OP_SUCCESS,
            "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => {
                consensus::VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
            }
            other => return Err(FlagParseError::UnknownToken(other.to_string())),
        };
        bits |= bit;
    }

    Ok(bits)
}

fn parse_tx_vector_flags(raw: &str) -> TxVectorFlagParse {
    if raw.trim().is_empty() || raw == "NONE" {
        return TxVectorFlagParse::Parsed(0);
    }

    let mut bits = 0u32;
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let bit = match token {
            "P2SH" => consensus::VERIFY_P2SH,
            "STRICTENC" => consensus::VERIFY_STRICTENC,
            "DERSIG" => consensus::VERIFY_DERSIG,
            "LOW_S" => consensus::VERIFY_LOW_S,
            "SIGPUSHONLY" => consensus::VERIFY_SIGPUSHONLY,
            "MINIMALDATA" => consensus::VERIFY_MINIMALDATA,
            "NULLDUMMY" => consensus::VERIFY_NULLDUMMY,
            "DISCOURAGE_UPGRADABLE_NOPS" => consensus::VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            "CLEANSTACK" => consensus::VERIFY_CLEANSTACK,
            "MINIMALIF" => consensus::VERIFY_MINIMALIF,
            "NULLFAIL" => consensus::VERIFY_NULLFAIL,
            "CHECKLOCKTIMEVERIFY" => consensus::VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => consensus::VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => consensus::VERIFY_WITNESS,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                consensus::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
            }
            "WITNESS_PUBKEYTYPE" => consensus::VERIFY_WITNESS_PUBKEYTYPE,
            "CONST_SCRIPTCODE" => consensus::VERIFY_CONST_SCRIPTCODE,
            "TAPROOT" => consensus::VERIFY_TAPROOT,
            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => consensus::VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
            "DISCOURAGE_OP_SUCCESS" => consensus::VERIFY_DISCOURAGE_OP_SUCCESS,
            "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => {
                consensus::VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
            }
            "BADTX" => return TxVectorFlagParse::SkipBadTx,
            other => return TxVectorFlagParse::SkipUnknown(other.to_string()),
        };
        bits |= bit;
    }

    TxVectorFlagParse::Parsed(bits)
}

fn parse_prevouts(raw_inputs: &[Value]) -> Option<HashMap<OutPoint, PrevoutData>> {
    let mut out = HashMap::with_capacity(raw_inputs.len());
    for input in raw_inputs {
        let arr = input.as_array()?;
        if !(3..=4).contains(&arr.len()) {
            return None;
        }
        let txid = Txid::from_str(arr[0].as_str()?).ok()?;
        let vout = arr[1].as_i64()? as u32;
        let script_pubkey = parse_script(arr[2].as_str()?).ok()?;
        let amount_sat = arr.get(3).and_then(Value::as_i64).unwrap_or(0);
        if amount_sat < 0 {
            return None;
        }
        out.insert(
            OutPoint { txid, vout },
            PrevoutData {
                script_pubkey,
                amount_sat: amount_sat as u64,
            },
        );
    }
    Some(out)
}

fn parse_script_vector_witness(entry: &Value) -> Option<(Witness, u64)> {
    let arr = entry.as_array()?;
    if arr.is_empty() {
        return None;
    }
    let amount = arr.last()?.as_f64()?;
    if amount < 0.0 {
        return None;
    }
    let amount_sat = (amount * 100_000_000.0).round() as u64;
    let mut items = Vec::new();
    for item in &arr[..arr.len() - 1] {
        let raw = item.as_str()?;
        if raw.contains('#') {
            return None;
        }
        let bytes = Vec::from_hex(raw).ok()?;
        items.push(bytes);
    }
    Some((Witness::from(items), amount_sat))
}

fn build_script_vector_tx(
    script_pubkey: &ScriptBuf,
    script_sig: &ScriptBuf,
    witness: Witness,
    amount_sat: u64,
) -> Vec<u8> {
    let credit_tx = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(amount_sat),
            script_pubkey: script_pubkey.clone(),
        }],
    };
    let spending = Transaction {
        version: Version(1),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: credit_tx.compute_txid(),
                vout: 0,
            },
            script_sig: script_sig.clone(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(amount_sat),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    btc_consensus::serialize(&spending)
}

fn compare_single_input_case(
    harness: &mut CoreCppHarness,
    script_pubkey: &[u8],
    amount_sat: u64,
    tx_bytes: &[u8],
    spent_outputs: Option<&[Utxo]>,
    input_index: usize,
    flags: u32,
) -> Result<(), String> {
    let ours = verify_with_flags_detailed(
        script_pubkey,
        amount_sat,
        tx_bytes,
        spent_outputs,
        input_index,
        flags,
    );

    let mut core_script_storage = Vec::new();
    let mut core_utxos = Vec::new();
    if let Some(spent) = spent_outputs {
        for utxo in spent {
            // SAFETY: The test harness produced these Utxo pointers from valid in-memory Vec<u8>.
            let script_slice = unsafe {
                core::slice::from_raw_parts(
                    utxo.script_pubkey,
                    utxo.script_pubkey_len as usize,
                )
            };
            core_script_storage.push(script_slice.to_vec());
            let ptr = core_script_storage
                .last()
                .expect("just pushed script storage")
                .as_ptr();
            core_utxos.push(CoreUtxo {
                script_pubkey: ptr,
                script_pubkey_len: script_slice.len() as u32,
                value: utxo.value,
            });
        }
    }
    let core_spent = if core_utxos.is_empty() {
        None
    } else {
        Some(core_utxos.as_slice())
    };

    let (core_ok, core_err) = harness
        .verify(script_pubkey, amount_sat, tx_bytes, core_spent, input_index, flags)
        .map_err(|err| format!("core runtime call failed: {err}"))?;

    if ours.is_ok() != core_ok {
        return Err(format!(
            "runtime diff mismatch: input={input_index} flags={flags:#x} ours={ours:?} core_ok={core_ok} core_err={core_err}"
        ));
    }
    Ok(())
}

fn should_skip_for_flags(flags: u32) -> bool {
    flags & !CORE_CPP_SUPPORTED_FLAGS != 0
}

fn parse_script_vector_flags(
    flags_str: &str,
    stats: &mut RuntimeDiffStats,
) -> Option<u32> {
    let flags = match parse_flags(flags_str) {
        Ok(flags) => flags,
        Err(FlagParseError::UnknownToken(token)) => {
            stats.skipped_unknown_tokens += 1;
            *stats.token_skip_counts.entry(token).or_insert(0) += 1;
            return None;
        }
    };
    if fill_flags(flags) != flags {
        stats.skipped_noncanonical_flags += 1;
        return None;
    }
    if should_skip_for_flags(flags) {
        stats.skipped_unsupported_flags += 1;
        return None;
    }
    Some(flags)
}

fn run_script_vector_samples(
    harness: &mut CoreCppHarness,
    stats: &mut RuntimeDiffStats,
    limit: usize,
) -> Result<(), String> {
    let tests: Vec<Value> =
        serde_json::from_str(SCRIPT_TESTS_JSON).map_err(|err| format!("script tests parse: {err}"))?;
    for case in tests {
        if stats.script_vectors_compared >= limit {
            break;
        }
        let arr = match case.as_array() {
            Some(arr) => arr,
            None => continue,
        };
        if arr.len() == 1 && arr[0].is_string() {
            continue;
        }

        let mut offset = 0usize;
        let mut witness = Witness::new();
        let mut amount_sat = 0u64;
        if arr.get(0).is_some_and(Value::is_array) {
            let Some((w, sats)) = parse_script_vector_witness(&arr[0]) else {
                stats.skipped_placeholder_vectors += 1;
                continue;
            };
            witness = w;
            amount_sat = sats;
            offset += 1;
        }
        if arr.len() < offset + 4 {
            continue;
        }

        let script_sig_raw = match arr[offset].as_str() {
            Some(raw) => raw,
            None => {
                stats.skipped_parse_failures += 1;
                continue;
            }
        };
        let script_pubkey_raw = match arr[offset + 1].as_str() {
            Some(raw) => raw,
            None => {
                stats.skipped_parse_failures += 1;
                continue;
            }
        };
        if script_sig_raw.contains('#') || script_pubkey_raw.contains('#') {
            stats.skipped_placeholder_vectors += 1;
            continue;
        }
        let script_sig = match parse_script(script_sig_raw) {
            Ok(script) => script,
            Err(_) => {
                stats.skipped_parse_failures += 1;
                continue;
            }
        };
        let script_pubkey = match parse_script(script_pubkey_raw) {
            Ok(script) => script,
            Err(_) => {
                stats.skipped_parse_failures += 1;
                continue;
            }
        };
        let flags_str = match arr[offset + 2].as_str() {
            Some(raw) => raw,
            None => continue,
        };
        let Some(flags) = parse_script_vector_flags(flags_str, stats) else {
            continue;
        };

        if flags & VERIFY_TAPROOT != 0 && !harness.has_spent_outputs_api() {
            stats.skipped_taproot_without_spent_outputs_support += 1;
            continue;
        }

        let tx_bytes = build_script_vector_tx(&script_pubkey, &script_sig, witness, amount_sat);
        let owned_script = script_pubkey.as_bytes().to_vec();
        let mut owned_utxo = Utxo {
            script_pubkey: owned_script.as_ptr(),
            script_pubkey_len: owned_script.len() as u32,
            value: amount_sat as i64,
        };
        let spent = if flags & VERIFY_TAPROOT != 0 {
            Some(core::slice::from_mut(&mut owned_utxo))
        } else {
            None
        };

        compare_single_input_case(
            harness,
            script_pubkey.as_bytes(),
            amount_sat,
            &tx_bytes,
            spent.as_deref(),
            0,
            flags,
        )?;
        stats.script_vectors_compared += 1;
        stats.compared_inputs += 1;
    }
    Ok(())
}

fn run_tx_vector_samples(
    harness: &mut CoreCppHarness,
    vectors: &str,
    expect_success: bool,
    limit: usize,
    stats: &mut RuntimeDiffStats,
) -> Result<(), String> {
    let tests: Vec<Value> =
        serde_json::from_str(vectors).map_err(|err| format!("tx vectors parse: {err}"))?;
    for case in tests {
        let done = if expect_success {
            stats.tx_valid_vectors_compared >= limit
        } else {
            stats.tx_invalid_vectors_compared >= limit
        };
        if done {
            break;
        }

        let arr = match case.as_array() {
            Some(value) => value,
            None => continue,
        };
        if arr.len() == 1 && arr[0].is_string() {
            continue;
        }
        if arr.len() != 3 || !arr[0].is_array() || !arr[1].is_string() || !arr[2].is_string() {
            continue;
        }

        let flags_str = arr[2].as_str().unwrap_or_default();
        let parsed_flags = match parse_tx_vector_flags(flags_str) {
            TxVectorFlagParse::Parsed(flags) => flags,
            TxVectorFlagParse::SkipBadTx => continue,
            TxVectorFlagParse::SkipUnknown(token) => {
                stats.skipped_unknown_tokens += 1;
                *stats.token_skip_counts.entry(token).or_insert(0) += 1;
                continue;
            }
        };
        let direct_flags = if expect_success {
            let included = ALL_TX_VECTOR_FLAGS & !parsed_flags;
            let projected = included & CORE_CPP_SUPPORTED_FLAGS;
            if fill_flags(projected) != projected {
                stats.skipped_noncanonical_flags += 1;
                continue;
            }
            projected
        } else {
            if fill_flags(parsed_flags) != parsed_flags {
                stats.skipped_noncanonical_flags += 1;
                continue;
            }
            parsed_flags
        };
        if should_skip_for_flags(direct_flags) {
            stats.skipped_unsupported_flags += 1;
            continue;
        }

        let prevouts = match parse_prevouts(arr[0].as_array().expect("checked array")) {
            Some(map) => map,
            None => {
                stats.skipped_parse_failures += 1;
                continue;
            }
        };
        let tx_hex = arr[1].as_str().expect("checked string");
        let tx_bytes = match Vec::from_hex(tx_hex) {
            Ok(bytes) => bytes,
            Err(_) => {
                stats.skipped_parse_failures += 1;
                continue;
            }
        };
        let tx: Transaction = match btc_consensus::deserialize(&tx_bytes) {
            Ok(tx) => tx,
            Err(_) => {
                stats.skipped_parse_failures += 1;
                continue;
            }
        };

        let mut ordered_prevouts = Vec::with_capacity(tx.input.len());
        for txin in &tx.input {
            let Some(prevout) = prevouts.get(&txin.previous_output) else {
                stats.skipped_missing_prevouts += 1;
                ordered_prevouts.clear();
                break;
            };
            ordered_prevouts.push(prevout.clone());
        }
        if ordered_prevouts.len() != tx.input.len() {
            continue;
        }

        if direct_flags & VERIFY_TAPROOT != 0 && !harness.has_spent_outputs_api() {
            stats.skipped_taproot_without_spent_outputs_support += 1;
            continue;
        }

        let script_storage: Vec<Vec<u8>> = ordered_prevouts
            .iter()
            .map(|prevout| prevout.script_pubkey.as_bytes().to_vec())
            .collect();
        let mut utxos: Vec<Utxo> = ordered_prevouts
            .iter()
            .zip(script_storage.iter())
            .map(|(prevout, script_bytes)| Utxo {
                script_pubkey: script_bytes.as_ptr(),
                script_pubkey_len: script_bytes.len() as u32,
                value: prevout.amount_sat as i64,
            })
            .collect();
        let spent = if direct_flags & VERIFY_TAPROOT != 0 {
            Some(utxos.as_mut_slice())
        } else {
            None
        };

        let mut vector_had_failure = false;
        for (input_index, prevout) in ordered_prevouts.iter().enumerate() {
            compare_single_input_case(
                harness,
                prevout.script_pubkey.as_bytes(),
                prevout.amount_sat,
                &tx_bytes,
                spent.as_deref(),
                input_index,
                direct_flags,
            )?;
            let ours = verify_with_flags_detailed(
                prevout.script_pubkey.as_bytes(),
                prevout.amount_sat,
                &tx_bytes,
                spent.as_deref(),
                input_index,
                direct_flags,
            );
            if ours.is_err() {
                vector_had_failure = true;
            }
            stats.compared_inputs += 1;
        }

        if expect_success && vector_had_failure {
            return Err(format!(
                "expected tx_valid vector to pass but observed local failure: tx={tx_hex} flags={direct_flags:#x}"
            ));
        }
        if !expect_success && !vector_had_failure {
            return Err(format!(
                "expected tx_invalid vector to fail but all inputs passed: tx={tx_hex} flags={direct_flags:#x}"
            ));
        }

        if expect_success {
            stats.tx_valid_vectors_compared += 1;
        } else {
            stats.tx_invalid_vectors_compared += 1;
        }
    }
    Ok(())
}

fn run_targeted_cases(
    harness: &mut CoreCppHarness,
    stats: &mut RuntimeDiffStats,
) -> Result<(), String> {
    // Witness malleation (bare witness with non-empty scriptSig).
    let witness_script = ScriptBuf::from_bytes(vec![all::OP_PUSHNUM_1.to_u8()]);
    let program = bitcoin::hashes::sha256::Hash::hash(witness_script.as_bytes());
    let spent_script = bitcoin::blockdata::script::Builder::new()
        .push_opcode(all::OP_PUSHBYTES_0)
        .push_slice(
            bitcoin::blockdata::script::PushBytesBuf::try_from(program.to_byte_array().to_vec())
                .expect("program bytes"),
        )
        .into_script();
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: ScriptBuf::from_bytes(vec![all::OP_PUSHNUM_1.to_u8()]),
            sequence: Sequence::MAX,
            witness: Witness::from(vec![witness_script.as_bytes().to_vec()]),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let tx_bytes = btc_consensus::serialize(&tx);
    compare_single_input_case(
        harness,
        spent_script.as_bytes(),
        50_000,
        &tx_bytes,
        None,
        0,
        VERIFY_WITNESS,
    )?;
    stats.targeted_cases_compared += 1;
    stats.compared_inputs += 1;

    // Flag-precedence / non-canonical combo edge (TAPROOT-only should not imply WITNESS).
    let tx_flag_edge = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from(vec![vec![0x01]]),
        }],
        output: vec![TxOut {
            value: bitcoin::Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let tx_flag_edge_bytes = btc_consensus::serialize(&tx_flag_edge);
    let spent_script_flag_edge = ScriptBuf::from_bytes(vec![all::OP_PUSHNUM_1.to_u8()]);
    let owned_script_flag_edge = spent_script_flag_edge.as_bytes().to_vec();
    let mut utxo_flag_edge = Utxo {
        script_pubkey: owned_script_flag_edge.as_ptr(),
        script_pubkey_len: owned_script_flag_edge.len() as u32,
        value: 10_000,
    };
    let spent_flag_edge = Some(core::slice::from_mut(&mut utxo_flag_edge));
    compare_single_input_case(
        harness,
        spent_script_flag_edge.as_bytes(),
        10_000,
        &tx_flag_edge_bytes,
        spent_flag_edge.as_deref(),
        0,
        VERIFY_TAPROOT,
    )?;
    stats.targeted_cases_compared += 1;
    stats.compared_inputs += 1;

    Ok(())
}

fn parse_accepted_skip_reasons() -> BTreeMap<String, ()> {
    let mut accepted = BTreeMap::new();
    let Ok(raw) = env::var("CORE_CPP_DIFF_ACCEPTED_SKIPS") else {
        return accepted;
    };
    for token in raw.split(',').map(str::trim).filter(|token| !token.is_empty()) {
        accepted.insert(token.to_string(), ());
    }
    accepted
}

fn skip_reason_counts(stats: &RuntimeDiffStats) -> BTreeMap<&'static str, usize> {
    let mut out = BTreeMap::new();
    out.insert("noncanonical_flags", stats.skipped_noncanonical_flags);
    out.insert("unsupported_flags", stats.skipped_unsupported_flags);
    out.insert("unknown_tokens", stats.skipped_unknown_tokens);
    out.insert("placeholder_vectors", stats.skipped_placeholder_vectors);
    out.insert(
        "taproot_without_spent_outputs_api",
        stats.skipped_taproot_without_spent_outputs_support,
    );
    out.insert("parse_failures", stats.skipped_parse_failures);
    out.insert("missing_prevouts", stats.skipped_missing_prevouts);
    out
}

#[test]
fn core_cpp_runtime_differential_harness() {
    let required = env::var("CORE_CPP_DIFF_REQUIRED").ok().as_deref() == Some("1");
    let strict_skips = env::var("CORE_CPP_DIFF_STRICT").ok().as_deref() == Some("1");
    let script_limit = env::var("CORE_CPP_DIFF_SCRIPT_LIMIT")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(48);
    let tx_limit = env::var("CORE_CPP_DIFF_TX_LIMIT")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(32);

    let mut harness = match CoreCppHarness::from_env() {
        Ok(Some(h)) => h,
        Ok(None) => {
            if required {
                panic!(
                    "CORE_CPP_DIFF_REQUIRED=1 but no direct Core runtime backend was found. \
                     Preferred (Core v28+): set CORE_CPP_DIFF_HELPER_BIN or set CORE_CPP_DIFF_BUILD_HELPER=1 with BITCOIN_CORE_REPO. \
                     Legacy fallback (Core v27 and older): set CORE_CPP_CONSENSUS_LIB or BITCOINCONSENSUS_LIB."
                );
            }
            eprintln!(
                "skipping core_cpp_runtime_differential_harness: no Core runtime backend found \
                 (Core v28+: set CORE_CPP_DIFF_HELPER_BIN or CORE_CPP_DIFF_BUILD_HELPER=1 with BITCOIN_CORE_REPO; \
                 legacy: set CORE_CPP_CONSENSUS_LIB)"
            );
            return;
        }
        Err(err) => {
            if required {
                panic!("CORE_CPP_DIFF_REQUIRED=1 and harness initialization failed: {err}");
            }
            eprintln!("skipping core_cpp_runtime_differential_harness: {err}");
            return;
        }
    };

    let mut stats = RuntimeDiffStats::default();
    run_script_vector_samples(&mut harness, &mut stats, script_limit)
        .unwrap_or_else(|err| panic!("script vector runtime diff failed: {err}"));
    run_tx_vector_samples(&mut harness, CORE_TX_VALID, true, tx_limit, &mut stats)
        .unwrap_or_else(|err| panic!("tx_valid runtime diff failed: {err}"));
    run_tx_vector_samples(&mut harness, CORE_TX_INVALID, false, tx_limit, &mut stats)
        .unwrap_or_else(|err| panic!("tx_invalid runtime diff failed: {err}"));
    run_targeted_cases(&mut harness, &mut stats)
        .unwrap_or_else(|err| panic!("targeted runtime diff failed: {err}"));

    let total_vectors = stats.script_vectors_compared
        + stats.tx_valid_vectors_compared
        + stats.tx_invalid_vectors_compared
        + stats.targeted_cases_compared;
    assert!(
        total_vectors > 0,
        "core C++ runtime diff ran no comparisons"
    );

    println!(
        "core_cpp_runtime_diff: backend={} has_spent_outputs_api={} compared_inputs={} script_vectors={} tx_valid_vectors={} tx_invalid_vectors={} targeted_cases={} skipped_noncanonical_flags={} skipped_unsupported_flags={} skipped_unknown_tokens={} skipped_placeholder_vectors={} skipped_taproot_no_spent_outputs={} skipped_parse_failures={} skipped_missing_prevouts={}",
        harness.backend_label(),
        harness.has_spent_outputs_api(),
        stats.compared_inputs,
        stats.script_vectors_compared,
        stats.tx_valid_vectors_compared,
        stats.tx_invalid_vectors_compared,
        stats.targeted_cases_compared,
        stats.skipped_noncanonical_flags,
        stats.skipped_unsupported_flags,
        stats.skipped_unknown_tokens,
        stats.skipped_placeholder_vectors,
        stats.skipped_taproot_without_spent_outputs_support,
        stats.skipped_parse_failures,
        stats.skipped_missing_prevouts,
    );
    if !stats.token_skip_counts.is_empty() {
        println!("core_cpp_runtime_diff token skips: {:?}", stats.token_skip_counts);
    }

    if strict_skips {
        let accepted = parse_accepted_skip_reasons();
        let skip_counts = skip_reason_counts(&stats);
        let mut unaccepted = Vec::new();
        for (reason, count) in skip_counts {
            if count == 0 {
                continue;
            }
            if !accepted.contains_key(reason) {
                unaccepted.push((reason, count));
            }
        }
        assert!(
            unaccepted.is_empty(),
            "CORE_CPP_DIFF_STRICT=1 and unaccepted skip reasons were observed: {:?}. \
             Set CORE_CPP_DIFF_ACCEPTED_SKIPS=<comma-separated-reasons> for accepted residual skips.",
            unaccepted
        );
    }
}
