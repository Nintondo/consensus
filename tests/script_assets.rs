mod script_asm;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{consensus as btc_consensus, hex::FromHex, ScriptBuf, Transaction, TxOut, Witness};
use consensus::{
    verify_with_flags_detailed, Utxo, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_CLEANSTACK, VERIFY_CONST_SCRIPTCODE, VERIFY_DERSIG, VERIFY_DISCOURAGE_OP_SUCCESS,
    VERIFY_DISCOURAGE_UPGRADABLE_NOPS, VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
    VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    VERIFY_LOW_S, VERIFY_MINIMALDATA, VERIFY_MINIMALIF, VERIFY_NULLDUMMY, VERIFY_NULLFAIL,
    VERIFY_P2SH, VERIFY_SIGPUSHONLY, VERIFY_STRICTENC, VERIFY_TAPROOT, VERIFY_WITNESS,
    VERIFY_WITNESS_PUBKEYTYPE,
};
use script_asm::parse_script;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::Instant,
};

const CORE_TX_VALID: &str = include_str!("data/tx_valid.json");
const CORE_TX_INVALID: &str = include_str!("data/tx_invalid.json");
const CONSENSUS_FLAGS_MASK: u32 = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_TAPROOT;
const ALL_TX_VECTOR_FLAGS: u32 = VERIFY_P2SH
    | VERIFY_STRICTENC
    | VERIFY_DERSIG
    | VERIFY_LOW_S
    | VERIFY_SIGPUSHONLY
    | VERIFY_MINIMALDATA
    | VERIFY_NULLDUMMY
    | VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    | VERIFY_CLEANSTACK
    | VERIFY_MINIMALIF
    | VERIFY_NULLFAIL
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | VERIFY_WITNESS_PUBKEYTYPE
    | VERIFY_CONST_SCRIPTCODE
    | VERIFY_TAPROOT
    | VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE
    | VERIFY_DISCOURAGE_OP_SUCCESS
    | VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION;
const DEFAULT_PARITY_MIN_LARGE_CASES: usize = 200;
const UPSTREAM_MINIMIZER_DEFAULT_NAME: &str = "script_assets_test.json";
const UPSTREAM_MINIMIZER_METADATA_DEFAULT_NAME: &str = "script_assets_test.metadata.json";
const GENERATED_ARTIFACT_METADATA_DEFAULT_NAME: &str = "script_assets_generated_metadata.json";

fn curated_asset_path() -> PathBuf {
    if let Ok(path) = env::var("SCRIPT_ASSETS_CURATED_JSON") {
        return PathBuf::from(path);
    }
    // Legacy alias kept for compatibility with older local workflows.
    if let Ok(path) = env::var("SCRIPT_ASSETS_TEST_JSON") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/script_assets_test.json")
}

fn upstream_minimizer_asset_path() -> Option<PathBuf> {
    if let Ok(path) = env::var("SCRIPT_ASSETS_UPSTREAM_JSON") {
        return Some(PathBuf::from(path));
    }
    let allow_dir_lookup = env::var("SCRIPT_ASSETS_USE_DIR_UNIT_TEST_DATA")
        .ok()
        .as_deref()
        == Some("1");
    if allow_dir_lookup {
        if let Ok(dir) = env::var("DIR_UNIT_TEST_DATA") {
            let candidate = PathBuf::from(dir).join(UPSTREAM_MINIMIZER_DEFAULT_NAME);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn generated_asset_path() -> Option<PathBuf> {
    if let Ok(path) = env::var("SCRIPT_ASSETS_GENERATED_JSON") {
        return Some(PathBuf::from(path));
    }
    if let Ok(dir) = env::var("DIR_UNIT_TEST_DATA") {
        let candidate = PathBuf::from(dir).join("script_assets_generated.json");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let vendored =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/script_assets_generated.json");
    if vendored.exists() {
        return Some(vendored);
    }
    None
}

fn generated_metadata_path() -> PathBuf {
    if let Ok(path) = env::var("SCRIPT_ASSETS_GENERATED_METADATA_JSON") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(GENERATED_ARTIFACT_METADATA_DEFAULT_NAME)
}

fn upstream_metadata_path(upstream_path: &Path) -> Option<PathBuf> {
    if let Ok(path) = env::var("SCRIPT_ASSETS_UPSTREAM_METADATA_JSON") {
        return Some(PathBuf::from(path));
    }
    let sibling = upstream_path
        .parent()
        .map(|dir| dir.join(UPSTREAM_MINIMIZER_METADATA_DEFAULT_NAME));
    match sibling {
        Some(path) if path.exists() => Some(path),
        _ => None,
    }
}

fn script_assets_parity_profile_enabled() -> bool {
    env::var("SCRIPT_ASSETS_PARITY_PROFILE")
        .ok()
        .as_deref()
        .is_some_and(|value| value == "1")
        || env::var("CORE_CPP_DIFF_STRICT")
            .ok()
            .as_deref()
            .is_some_and(|value| value == "1")
}

fn script_assets_require_upstream_corpus() -> bool {
    env::var("SCRIPT_ASSETS_REQUIRE_UPSTREAM")
        .ok()
        .as_deref()
        .is_some_and(|value| value == "1")
}

fn parity_min_large_cases() -> usize {
    env::var("SCRIPT_ASSETS_MIN_CASES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PARITY_MIN_LARGE_CASES)
}

fn script_assets_progress_every() -> usize {
    env::var("SCRIPT_ASSETS_PROGRESS_EVERY")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(100)
}

fn all_consensus_flags() -> Vec<u32> {
    let mut flags = Vec::new();
    for bits in 0u32..128 {
        let mut value = 0u32;
        if bits & 1 != 0 {
            value |= VERIFY_P2SH;
        }
        if bits & 2 != 0 {
            value |= VERIFY_DERSIG;
        }
        if bits & 4 != 0 {
            value |= VERIFY_NULLDUMMY;
        }
        if bits & 8 != 0 {
            value |= VERIFY_CHECKLOCKTIMEVERIFY;
        }
        if bits & 16 != 0 {
            value |= VERIFY_CHECKSEQUENCEVERIFY;
        }
        if bits & 32 != 0 {
            value |= VERIFY_WITNESS;
        }
        if bits & 64 != 0 {
            value |= VERIFY_TAPROOT;
        }
        if value & VERIFY_WITNESS != 0 && value & VERIFY_P2SH == 0 {
            continue;
        }
        if value & VERIFY_TAPROOT != 0 && value & VERIFY_WITNESS == 0 {
            continue;
        }
        flags.push(value);
    }
    flags
}

fn trim_flags(flags: u32) -> u32 {
    let mut out = flags;
    // WITNESS requires P2SH.
    if out & VERIFY_P2SH == 0 {
        out &= !VERIFY_WITNESS;
    }
    // CLEANSTACK requires WITNESS (and transitively P2SH).
    if out & VERIFY_WITNESS == 0 {
        out &= !VERIFY_CLEANSTACK;
    }
    out
}

fn fill_flags(flags: u32) -> u32 {
    let mut out = flags;
    // CLEANSTACK implies WITNESS.
    if out & VERIFY_CLEANSTACK != 0 {
        out |= VERIFY_WITNESS;
    }
    // WITNESS implies P2SH.
    if out & VERIFY_WITNESS != 0 {
        out |= VERIFY_P2SH;
    }
    out
}

fn parse_flags(raw: &str) -> u32 {
    let mut bits = 0u32;
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        bits |= match token {
            "P2SH" => VERIFY_P2SH,
            "DERSIG" => VERIFY_DERSIG,
            "NULLDUMMY" => VERIFY_NULLDUMMY,
            "CHECKLOCKTIMEVERIFY" => VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => VERIFY_WITNESS,
            "TAPROOT" => VERIFY_TAPROOT,
            other => panic!("unknown consensus flag in script asset test: {other}"),
        };
    }
    bits
}

#[derive(Debug)]
enum TxVectorFlagParse {
    Parsed(u32),
    Skip(TxVectorSkipReason),
}

#[derive(Debug)]
enum TxVectorSkipReason {
    BadTx,
    UnknownToken(String),
}

#[derive(Debug)]
enum LargeCorpusSource {
    UpstreamMinimizer(PathBuf),
    DerivedExternalFile(PathBuf),
    DerivedFromCoreVectors,
}

#[derive(Default)]
struct GeneratedCorpusStats {
    total_vectors: usize,
    parsed_vectors: usize,
    generated_success_cases: usize,
    generated_failure_cases: usize,
    skipped_badtx: usize,
    skipped_unknown: usize,
    skipped_noncanonical: usize,
    skipped_incompatible_inputs: usize,
    unknown_token_counts: BTreeMap<String, usize>,
}

struct GeneratedCorpusMetadata {
    source_core_commit: String,
    source_tx_valid_sha256: String,
    source_tx_invalid_sha256: String,
    generated_case_count: usize,
    generated_sha256: String,
}

struct UpstreamCorpusMetadata {
    source_core_commit: String,
    source_generation: String,
    artifact_case_count: usize,
    artifact_sha256: String,
}

#[derive(Default)]
struct MonotonicityStats {
    total_vectors: usize,
    parsed_vectors: usize,
    checked_vectors: usize,
    skipped_badtx: usize,
    skipped_unknown: usize,
    skipped_noncanonical: usize,
    unknown_token_counts: BTreeMap<String, usize>,
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
            "P2SH" => VERIFY_P2SH,
            "STRICTENC" => VERIFY_STRICTENC,
            "DERSIG" => VERIFY_DERSIG,
            "LOW_S" => VERIFY_LOW_S,
            "SIGPUSHONLY" => VERIFY_SIGPUSHONLY,
            "MINIMALDATA" => VERIFY_MINIMALDATA,
            "NULLDUMMY" => VERIFY_NULLDUMMY,
            "DISCOURAGE_UPGRADABLE_NOPS" => VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            "CLEANSTACK" => VERIFY_CLEANSTACK,
            "MINIMALIF" => VERIFY_MINIMALIF,
            "NULLFAIL" => VERIFY_NULLFAIL,
            "CHECKLOCKTIMEVERIFY" => VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => VERIFY_CHECKSEQUENCEVERIFY,
            "WITNESS" => VERIFY_WITNESS,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
            "WITNESS_PUBKEYTYPE" => VERIFY_WITNESS_PUBKEYTYPE,
            "CONST_SCRIPTCODE" => VERIFY_CONST_SCRIPTCODE,
            "TAPROOT" => VERIFY_TAPROOT,
            "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
            "DISCOURAGE_OP_SUCCESS" => VERIFY_DISCOURAGE_OP_SUCCESS,
            "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
            "BADTX" => return TxVectorFlagParse::Skip(TxVectorSkipReason::BadTx),
            other => {
                return TxVectorFlagParse::Skip(TxVectorSkipReason::UnknownToken(
                    other.to_string(),
                ));
            }
        };
        bits |= bit;
    }

    TxVectorFlagParse::Parsed(bits)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn consensus_flags_to_string(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & VERIFY_P2SH != 0 {
        parts.push("P2SH");
    }
    if flags & VERIFY_DERSIG != 0 {
        parts.push("DERSIG");
    }
    if flags & VERIFY_NULLDUMMY != 0 {
        parts.push("NULLDUMMY");
    }
    if flags & VERIFY_CHECKLOCKTIMEVERIFY != 0 {
        parts.push("CHECKLOCKTIMEVERIFY");
    }
    if flags & VERIFY_CHECKSEQUENCEVERIFY != 0 {
        parts.push("CHECKSEQUENCEVERIFY");
    }
    if flags & VERIFY_WITNESS != 0 {
        parts.push("WITNESS");
    }
    if flags & VERIFY_TAPROOT != 0 {
        parts.push("TAPROOT");
    }
    parts.join(",")
}

fn witness_to_json_array(witness: &Witness) -> Vec<Value> {
    witness
        .iter()
        .map(|item| Value::String(encode_hex(item)))
        .collect()
}

fn prevouts_to_json_array(prevouts: &[TxOut]) -> Vec<Value> {
    prevouts
        .iter()
        .map(|txout| Value::String(encode_hex(&btc_consensus::serialize(txout))))
        .collect()
}

fn hash_json_entries(entries: &[Value]) -> String {
    let bytes = serde_json::to_vec(entries).expect("generated script-assets entries serialize");
    sha256::Hash::hash(&bytes).to_string()
}

fn parse_generated_corpus_metadata(path: &Path) -> GeneratedCorpusMetadata {
    let raw = fs::read_to_string(path).unwrap_or_else(|err| {
        panic!(
            "failed to read generated metadata {}: {err}",
            path.display()
        )
    });
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("invalid generated metadata JSON {}: {err}", path.display()));
    let obj = value
        .as_object()
        .unwrap_or_else(|| panic!("generated metadata {} must be an object", path.display()));
    let source = obj
        .get("source_fixtures")
        .and_then(Value::as_object)
        .unwrap_or_else(|| {
            panic!(
                "generated metadata {} missing source_fixtures object",
                path.display()
            )
        });

    GeneratedCorpusMetadata {
        source_core_commit: obj
            .get("source_core_commit")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "generated metadata {} missing source_core_commit",
                    path.display()
                )
            })
            .to_string(),
        source_tx_valid_sha256: source
            .get("tx_valid_sha256")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "generated metadata {} missing tx_valid_sha256",
                    path.display()
                )
            })
            .to_string(),
        source_tx_invalid_sha256: source
            .get("tx_invalid_sha256")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "generated metadata {} missing tx_invalid_sha256",
                    path.display()
                )
            })
            .to_string(),
        generated_case_count: obj
            .get("generated_case_count")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| {
                panic!(
                    "generated metadata {} missing generated_case_count",
                    path.display()
                )
            }) as usize,
        generated_sha256: obj
            .get("generated_sha256")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "generated metadata {} missing generated_sha256",
                    path.display()
                )
            })
            .to_string(),
    }
}

fn parse_upstream_corpus_metadata(path: &Path) -> UpstreamCorpusMetadata {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read upstream metadata {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("invalid upstream metadata JSON {}: {err}", path.display()));
    let obj = value
        .as_object()
        .unwrap_or_else(|| panic!("upstream metadata {} must be an object", path.display()));

    UpstreamCorpusMetadata {
        source_core_commit: obj
            .get("source_core_commit")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "upstream metadata {} missing source_core_commit",
                    path.display()
                )
            })
            .to_string(),
        source_generation: obj
            .get("source_generation")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "upstream metadata {} missing source_generation",
                    path.display()
                )
            })
            .to_string(),
        artifact_case_count: obj
            .get("artifact_case_count")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| {
                panic!(
                    "upstream metadata {} missing artifact_case_count",
                    path.display()
                )
            }) as usize,
        artifact_sha256: obj
            .get("artifact_sha256")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "upstream metadata {} missing artifact_sha256",
                    path.display()
                )
            })
            .to_string(),
    }
}

fn parse_witness(value: &Value) -> Witness {
    let entries = value
        .as_array()
        .unwrap_or_else(|| panic!("witness field must be an array"));
    let mut stack_items = Vec::with_capacity(entries.len());
    for entry in entries {
        let encoded = entry
            .as_str()
            .unwrap_or_else(|| panic!("witness entries must be hex strings"));
        let bytes = Vec::from_hex(encoded)
            .unwrap_or_else(|_| panic!("invalid witness hex in script asset test"));
        stack_items.push(bytes);
    }
    Witness::from_slice(&stack_items)
}

fn parse_prevouts(value: &Value) -> Vec<TxOut> {
    let entries = value
        .as_array()
        .unwrap_or_else(|| panic!("prevouts field must be an array"));
    let mut prevouts = Vec::with_capacity(entries.len());
    for entry in entries {
        let encoded = entry
            .as_str()
            .unwrap_or_else(|| panic!("prevout entries must be hex strings"));
        let bytes = Vec::from_hex(encoded)
            .unwrap_or_else(|_| panic!("invalid prevout hex in script asset test"));
        let txout = btc_consensus::deserialize::<TxOut>(&bytes)
            .unwrap_or_else(|_| panic!("invalid serialized txout in script asset test"));
        prevouts.push(txout);
    }
    prevouts
}

fn parse_tx_vector_prevouts(value: &Value) -> Vec<TxOut> {
    let entries = value
        .as_array()
        .unwrap_or_else(|| panic!("tx vector prevouts must be an array"));
    let mut prevouts = Vec::with_capacity(entries.len());
    for entry in entries {
        let descriptor = entry
            .as_array()
            .unwrap_or_else(|| panic!("tx vector prevout descriptor must be an array"));
        assert!(
            (3..=4).contains(&descriptor.len()),
            "tx vector prevout descriptor must have 3 or 4 fields"
        );
        let script_pubkey = parse_script(
            descriptor[2]
                .as_str()
                .unwrap_or_else(|| panic!("tx vector prevout script must be string")),
        )
        .unwrap_or_else(|err| panic!("tx vector prevout script asm parse failed: {err}"));
        let amount_sat = descriptor.get(3).and_then(Value::as_i64).unwrap_or(0);
        assert!(
            amount_sat >= 0,
            "tx vector prevout amounts must be non-negative"
        );
        prevouts.push(TxOut {
            value: bitcoin::Amount::from_sat(amount_sat as u64),
            script_pubkey,
        });
    }
    prevouts
}

fn build_generated_entries_from_core_vectors(
    vectors: &str,
    expect_success: bool,
    entries: &mut Vec<Value>,
    stats: &mut GeneratedCorpusStats,
) {
    let cases: Vec<Value> = serde_json::from_str(vectors).expect("core tx vectors parse");
    for case in cases {
        let arr = match case.as_array() {
            Some(arr) => arr,
            None => continue,
        };
        if arr.len() == 1 && arr[0].is_string() {
            continue;
        }
        if arr.len() != 3 || !arr[0].is_array() || !arr[1].is_string() || !arr[2].is_string() {
            continue;
        }
        stats.total_vectors += 1;

        let flags_str = arr[2].as_str().expect("flags string");
        let parsed_flags = match parse_tx_vector_flags(flags_str) {
            TxVectorFlagParse::Parsed(flags) => {
                stats.parsed_vectors += 1;
                flags
            }
            TxVectorFlagParse::Skip(TxVectorSkipReason::BadTx) => {
                stats.skipped_badtx += 1;
                continue;
            }
            TxVectorFlagParse::Skip(TxVectorSkipReason::UnknownToken(token)) => {
                stats.skipped_unknown += 1;
                *stats.unknown_token_counts.entry(token).or_insert(0) += 1;
                continue;
            }
        };

        let consensus_flags = if expect_success {
            let included_flags = ALL_TX_VECTOR_FLAGS & !parsed_flags;
            if fill_flags(included_flags) != included_flags {
                stats.skipped_noncanonical += 1;
                continue;
            }
            included_flags & CONSENSUS_FLAGS_MASK
        } else {
            if fill_flags(parsed_flags) != parsed_flags {
                stats.skipped_noncanonical += 1;
                continue;
            }
            parsed_flags & CONSENSUS_FLAGS_MASK
        };

        let flags_field = consensus_flags_to_string(consensus_flags);
        let prevouts = parse_tx_vector_prevouts(&arr[0]);
        let prevouts_json = prevouts_to_json_array(&prevouts);
        let tx_hex = arr[1].as_str().expect("serialized tx string");
        let tx: Transaction = btc_consensus::deserialize(
            &Vec::from_hex(tx_hex).expect("core tx vector serialized transaction hex"),
        )
        .expect("core tx vector serialized transaction decode");

        if tx.input.len() != prevouts.len() {
            stats.skipped_incompatible_inputs += 1;
            continue;
        }

        for (input_index, txin) in tx.input.iter().enumerate() {
            let case_result = verify_case(&tx, &prevouts, input_index, consensus_flags);
            let include = if expect_success {
                case_result.is_ok()
            } else {
                case_result.is_err()
            };
            if !include {
                stats.skipped_incompatible_inputs += 1;
                continue;
            }

            let case = if expect_success {
                stats.generated_success_cases += 1;
                json!({
                    "tx": tx_hex,
                    "prevouts": prevouts_json.clone(),
                    "index": input_index,
                    "flags": flags_field.clone(),
                    "success": {
                        "scriptSig": encode_hex(txin.script_sig.as_bytes()),
                        "witness": witness_to_json_array(&txin.witness),
                    }
                })
            } else {
                stats.generated_failure_cases += 1;
                json!({
                    "tx": tx_hex,
                    "prevouts": prevouts_json.clone(),
                    "index": input_index,
                    "flags": flags_field.clone(),
                    "failure": {
                        "scriptSig": encode_hex(txin.script_sig.as_bytes()),
                        "witness": witness_to_json_array(&txin.witness),
                    }
                })
            };
            entries.push(case);
        }
    }
}

fn generate_script_assets_entries() -> (Vec<Value>, GeneratedCorpusStats) {
    let mut entries = Vec::new();
    let mut stats = GeneratedCorpusStats::default();
    build_generated_entries_from_core_vectors(CORE_TX_VALID, true, &mut entries, &mut stats);
    build_generated_entries_from_core_vectors(CORE_TX_INVALID, false, &mut entries, &mut stats);
    (entries, stats)
}

fn load_script_asset_entries(path: &Path) -> Vec<Value> {
    let raw = fs::read_to_string(path).unwrap_or_else(|err| {
        panic!(
            "failed to read script assets file {}: {err}",
            path.display()
        )
    });
    let tests: Value = serde_json::from_str(&raw).unwrap_or_else(|err| {
        panic!(
            "failed to parse script assets JSON {}: {err}",
            path.display()
        )
    });
    let entries = tests
        .as_array()
        .unwrap_or_else(|| panic!("script assets top-level JSON must be an array"));
    assert!(
        !entries.is_empty(),
        "script assets JSON is empty: {}",
        path.display()
    );
    entries.clone()
}

fn load_or_generate_large_script_assets_entries(
) -> (Vec<Value>, LargeCorpusSource, GeneratedCorpusStats) {
    if let Some(path) = upstream_minimizer_asset_path() {
        let entries = load_script_asset_entries(&path);
        return (
            entries,
            LargeCorpusSource::UpstreamMinimizer(path),
            GeneratedCorpusStats::default(),
        );
    }
    if let Some(path) = generated_asset_path() {
        let entries = load_script_asset_entries(&path);
        return (
            entries,
            LargeCorpusSource::DerivedExternalFile(path),
            GeneratedCorpusStats::default(),
        );
    }
    let (entries, stats) = generate_script_assets_entries();
    (entries, LargeCorpusSource::DerivedFromCoreVectors, stats)
}

fn verify_case(
    tx: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    flags: u32,
) -> Result<(), consensus::ScriptFailure> {
    let tx_bytes = btc_consensus::serialize(tx);
    let spent_script = prevouts[input_index].script_pubkey.as_bytes();
    let amount = prevouts[input_index].value.to_sat();

    if flags & VERIFY_TAPROOT == 0 {
        return verify_with_flags_detailed(
            spent_script,
            amount,
            &tx_bytes,
            None,
            input_index,
            flags,
        );
    }

    let script_storage: Vec<Vec<u8>> = prevouts
        .iter()
        .map(|txout| txout.script_pubkey.as_bytes().to_vec())
        .collect();
    let utxos: Vec<Utxo> = prevouts
        .iter()
        .zip(script_storage.iter())
        .map(|(txout, script)| Utxo {
            script_pubkey: script.as_ptr(),
            script_pubkey_len: script.len() as u32,
            value: txout.value.to_sat() as i64,
        })
        .collect();

    verify_with_flags_detailed(
        spent_script,
        amount,
        &tx_bytes,
        Some(&utxos),
        input_index,
        flags,
    )
}

fn run_core_tx_monotonicity(vectors: &str, expect_success: bool) {
    let cases: Vec<Value> = serde_json::from_str(vectors).expect("core tx vectors parse");
    let consensus_flags = all_consensus_flags();
    let mut checked = 0usize;
    let mut stats = MonotonicityStats::default();

    for case in cases {
        let arr = match case.as_array() {
            Some(arr) => arr,
            None => continue,
        };
        if arr.len() == 1 && arr[0].is_string() {
            continue;
        }
        if arr.len() != 3 || !arr[0].is_array() || !arr[1].is_string() || !arr[2].is_string() {
            continue;
        }
        stats.total_vectors += 1;

        let flags_str = arr[2].as_str().expect("flags string");
        let parsed_flags = match parse_tx_vector_flags(flags_str) {
            TxVectorFlagParse::Parsed(flags) => {
                stats.parsed_vectors += 1;
                flags
            }
            TxVectorFlagParse::Skip(TxVectorSkipReason::BadTx) => {
                stats.skipped_badtx += 1;
                continue;
            }
            TxVectorFlagParse::Skip(TxVectorSkipReason::UnknownToken(token)) => {
                stats.skipped_unknown += 1;
                *stats.unknown_token_counts.entry(token).or_insert(0) += 1;
                continue;
            }
        };
        let prevouts = parse_tx_vector_prevouts(&arr[0]);
        let tx_hex = arr[1].as_str().expect("serialized tx string");
        let tx: Transaction = btc_consensus::deserialize(
            &Vec::from_hex(tx_hex).expect("core tx vector serialized transaction hex"),
        )
        .expect("core tx vector serialized transaction decode");

        if tx.input.len() != prevouts.len() {
            continue;
        }

        if expect_success {
            // In Core's tx_valid corpus the JSON field carries excluded flags.
            let included_flags = ALL_TX_VECTOR_FLAGS & !parsed_flags;
            if fill_flags(included_flags) != included_flags {
                stats.skipped_noncanonical += 1;
                continue;
            }
            let fixed_non_consensus = included_flags & !CONSENSUS_FLAGS_MASK;
            let included_consensus = included_flags & CONSENSUS_FLAGS_MASK;

            for consensus_bits in &consensus_flags {
                if (consensus_bits & included_consensus) != *consensus_bits {
                    continue;
                }
                let flags = trim_flags(fixed_non_consensus | *consensus_bits);
                for input_index in 0..tx.input.len() {
                    let result = verify_case(&tx, &prevouts, input_index, flags);
                    assert!(
                        result.is_ok(),
                        "core tx-valid monotonicity mismatch: input={input_index} excluded_flags={parsed_flags:#x} flags={flags:#x} tx={tx_hex} result={result:?}"
                    );
                }
                checked += 1;
                stats.checked_vectors += 1;
            }
        } else {
            // In Core's tx_invalid corpus the JSON field carries direct required
            // flags. Failure should hold for supersets.
            let required_flags = fill_flags(parsed_flags);
            if required_flags != parsed_flags {
                stats.skipped_noncanonical += 1;
                continue;
            }
            let fixed_non_consensus = required_flags & !CONSENSUS_FLAGS_MASK;
            let required_consensus = required_flags & CONSENSUS_FLAGS_MASK;

            for consensus_bits in &consensus_flags {
                if (consensus_bits & required_consensus) != required_consensus {
                    continue;
                }
                let flags = fill_flags(fixed_non_consensus | *consensus_bits);
                let mut any_failed = false;
                for input_index in 0..tx.input.len() {
                    let result = verify_case(&tx, &prevouts, input_index, flags);
                    if result.is_err() {
                        any_failed = true;
                        break;
                    }
                }
                assert!(
                    any_failed,
                    "core tx-invalid monotonicity mismatch: required_flags={parsed_flags:#x} flags={flags:#x} tx={tx_hex}"
                );
                checked += 1;
                stats.checked_vectors += 1;
            }
        }
    }

    assert!(
        checked > 0,
        "core tx monotonicity checks must execute cases"
    );
    assert!(
        stats.unknown_token_counts.is_empty(),
        "unknown tx-vector flag tokens in monotonicity harness: {:?}",
        stats.unknown_token_counts
    );
    println!(
        "script_assets coverage (expect_success={}): total={} parsed={} checked={} skipped_badtx={} skipped_noncanonical={}",
        expect_success,
        stats.total_vectors,
        stats.parsed_vectors,
        stats.checked_vectors,
        stats.skipped_badtx,
        stats.skipped_noncanonical
    );
}

#[test]
fn parse_tx_vector_flags_accepts_none_and_known_tokens() {
    assert!(matches!(
        parse_tx_vector_flags("NONE"),
        TxVectorFlagParse::Parsed(0)
    ));
    assert!(matches!(
        parse_tx_vector_flags("P2SH,WITNESS"),
        TxVectorFlagParse::Parsed(flags) if flags == (VERIFY_P2SH | VERIFY_WITNESS)
    ));
}

#[test]
fn parse_tx_vector_flags_rejects_unknown_tokens() {
    assert!(matches!(
        parse_tx_vector_flags("P2SH,NO_SUCH_FLAG"),
        TxVectorFlagParse::Skip(TxVectorSkipReason::UnknownToken(_))
    ));
    assert!(matches!(
        parse_tx_vector_flags("P2SH,STRICTENC"),
        TxVectorFlagParse::Parsed(flags) if flags == (VERIFY_P2SH | VERIFY_STRICTENC)
    ));
}

fn run_script_assets_entries_monotonicity(entries: &[Value], label: &str) {
    let consensus_flags = all_consensus_flags();
    let total_cases = entries.len();
    let progress_every = script_assets_progress_every();
    let started = Instant::now();
    println!(
        "script_assets progress start: corpus=`{label}` cases={} progress_every={}",
        total_cases, progress_every
    );
    let _ = io::stdout().flush();

    for (idx, case) in entries.iter().enumerate() {
        let obj = case
            .as_object()
            .unwrap_or_else(|| panic!("script asset case #{idx} must be an object"));
        let base_tx_hex = obj
            .get("tx")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("script asset case #{idx} missing tx"));
        let tx_bytes = Vec::from_hex(base_tx_hex)
            .unwrap_or_else(|_| panic!("script asset case #{idx} has invalid tx hex"));
        let mut tx = btc_consensus::deserialize::<Transaction>(&tx_bytes)
            .unwrap_or_else(|_| panic!("script asset case #{idx} tx failed to deserialize"));
        let prevouts = parse_prevouts(
            obj.get("prevouts")
                .unwrap_or_else(|| panic!("script asset case #{idx} missing prevouts")),
        );
        let input_index = obj
            .get("index")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("script asset case #{idx} missing index"))
            as usize;
        assert_eq!(
            prevouts.len(),
            tx.input.len(),
            "script asset case #{idx} prevout count mismatch"
        );
        assert!(
            input_index < tx.input.len(),
            "script asset case #{idx} input index out of range"
        );

        let test_flags = parse_flags(
            obj.get("flags")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("script asset case #{idx} missing flags")),
        );
        let final_case = obj.get("final").and_then(Value::as_bool).unwrap_or(false);

        if let Some(success) = obj.get("success") {
            let success_obj = success
                .as_object()
                .unwrap_or_else(|| panic!("script asset case #{idx} success must be object"));
            let script_sig_hex = success_obj
                .get("scriptSig")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("script asset case #{idx} success missing scriptSig"));
            let script_sig =
                ScriptBuf::from_bytes(Vec::from_hex(script_sig_hex).unwrap_or_else(|_| {
                    panic!("script asset case #{idx} has invalid success scriptSig")
                }));
            let witness = parse_witness(
                success_obj
                    .get("witness")
                    .unwrap_or_else(|| panic!("script asset case #{idx} success missing witness")),
            );
            tx.input[input_index].script_sig = script_sig;
            tx.input[input_index].witness = witness;

            for flags in &consensus_flags {
                if final_case || ((flags & test_flags) == *flags) {
                    let result = verify_case(&tx, &prevouts, input_index, *flags);
                    assert!(
                        result.is_ok(),
                        "script asset case #{idx} expected success for flags {flags:#x}, got {result:?}"
                    );
                }
            }
        }

        if let Some(failure) = obj.get("failure") {
            let failure_obj = failure
                .as_object()
                .unwrap_or_else(|| panic!("script asset case #{idx} failure must be object"));
            let script_sig_hex = failure_obj
                .get("scriptSig")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("script asset case #{idx} failure missing scriptSig"));
            let script_sig =
                ScriptBuf::from_bytes(Vec::from_hex(script_sig_hex).unwrap_or_else(|_| {
                    panic!("script asset case #{idx} has invalid failure scriptSig")
                }));
            let witness = parse_witness(
                failure_obj
                    .get("witness")
                    .unwrap_or_else(|| panic!("script asset case #{idx} failure missing witness")),
            );
            tx.input[input_index].script_sig = script_sig;
            tx.input[input_index].witness = witness;

            for flags in &consensus_flags {
                if (flags & test_flags) == test_flags {
                    let result = verify_case(&tx, &prevouts, input_index, *flags);
                    assert!(
                        result.is_err(),
                        "script asset case #{idx} expected failure for flags {flags:#x}"
                    );
                }
            }
        }

        let completed = idx + 1;
        if progress_every > 0 && (completed % progress_every == 0 || completed == total_cases) {
            let elapsed = started.elapsed().as_secs_f64();
            let percent = (completed as f64 * 100.0) / total_cases as f64;
            println!(
                "script_assets progress: corpus=`{label}` completed={}/{} ({percent:.1}%) elapsed={elapsed:.2}s",
                completed, total_cases
            );
            let _ = io::stdout().flush();
        }
    }

    println!(
        "script_assets corpus `{label}` monotonicity complete: cases={} elapsed={:.2}s",
        entries.len(),
        started.elapsed().as_secs_f64()
    );
}

fn print_curated_summary(cases: usize, path: &Path) {
    println!(
        "script_assets source=curated-smoke path={} cases={} generation_skips=0",
        path.display(),
        cases
    );
}

fn print_large_source_summary(
    source: &LargeCorpusSource,
    entries: usize,
    stats: &GeneratedCorpusStats,
) {
    match source {
        LargeCorpusSource::UpstreamMinimizer(path) => {
            println!(
                "script_assets source=upstream-minimizer path={} cases={} generation_skips=0",
                path.display(),
                entries
            );
        }
        LargeCorpusSource::DerivedExternalFile(path) => {
            println!(
                "script_assets source=derived-external path={} cases={} generation_skips=0",
                path.display(),
                entries
            );
        }
        LargeCorpusSource::DerivedFromCoreVectors => {
            println!(
                "script_assets source=derived-from-core-vectors cases={} vectors_total={} vectors_parsed={} success_cases={} failure_cases={} skipped_badtx={} skipped_unknown={} skipped_noncanonical={} skipped_incompatible_inputs={}",
                entries,
                stats.total_vectors,
                stats.parsed_vectors,
                stats.generated_success_cases,
                stats.generated_failure_cases,
                stats.skipped_badtx,
                stats.skipped_unknown,
                stats.skipped_noncanonical,
                stats.skipped_incompatible_inputs
            );
        }
    }
}

fn enforce_large_corpus_profile_requirements(source: &LargeCorpusSource, entries: &[Value]) {
    if script_assets_parity_profile_enabled() {
        let min_cases = parity_min_large_cases();
        assert!(
            entries.len() >= min_cases,
            "large script-assets corpus is too small: {} cases (minimum required: {})",
            entries.len(),
            min_cases
        );

        if script_assets_require_upstream_corpus() {
            assert!(
                matches!(source, LargeCorpusSource::UpstreamMinimizer(_)),
                "parity profile requires upstream minimizer corpus (set SCRIPT_ASSETS_UPSTREAM_JSON)"
            );
        }
    } else {
        assert!(
            entries.len() > 50,
            "large script-assets corpus is too small for non-parity run ({} cases)",
            entries.len()
        );
    }
}

fn assert_generated_metadata_integrity_for_entries(entries: &[Value]) {
    let metadata_path = generated_metadata_path();
    assert!(
        metadata_path.exists(),
        "generated metadata file does not exist: {}",
        metadata_path.display()
    );
    let metadata = parse_generated_corpus_metadata(&metadata_path);

    let tx_valid_hash = sha256::Hash::hash(CORE_TX_VALID.as_bytes()).to_string();
    let tx_invalid_hash = sha256::Hash::hash(CORE_TX_INVALID.as_bytes()).to_string();
    assert_eq!(
        metadata.source_tx_valid_sha256,
        tx_valid_hash,
        "generated metadata tx_valid hash mismatch in {}",
        metadata_path.display()
    );
    assert_eq!(
        metadata.source_tx_invalid_sha256,
        tx_invalid_hash,
        "generated metadata tx_invalid hash mismatch in {}",
        metadata_path.display()
    );
    assert_eq!(
        metadata.generated_case_count,
        entries.len(),
        "generated metadata case-count mismatch in {}",
        metadata_path.display()
    );
    assert_eq!(
        metadata.generated_sha256,
        hash_json_entries(entries),
        "generated metadata corpus hash mismatch in {}",
        metadata_path.display()
    );
    assert!(
        !metadata.source_core_commit.is_empty(),
        "generated metadata source_core_commit must be non-empty"
    );
}

fn assert_upstream_metadata_integrity_for_entries(path: &Path, entries: &[Value]) {
    let metadata_path = upstream_metadata_path(path).unwrap_or_else(|| {
        panic!(
            "upstream script-assets corpus requires metadata file (set SCRIPT_ASSETS_UPSTREAM_METADATA_JSON or provide sibling {})",
            UPSTREAM_MINIMIZER_METADATA_DEFAULT_NAME
        )
    });
    assert!(
        metadata_path.exists(),
        "upstream metadata file does not exist: {}",
        metadata_path.display()
    );
    let metadata = parse_upstream_corpus_metadata(&metadata_path);
    assert!(
        !metadata.source_core_commit.is_empty(),
        "upstream metadata source_core_commit must be non-empty"
    );
    assert!(
        !metadata.source_generation.is_empty(),
        "upstream metadata source_generation must be non-empty"
    );
    assert_eq!(
        metadata.artifact_case_count,
        entries.len(),
        "upstream metadata case-count mismatch in {}",
        metadata_path.display()
    );
    assert_eq!(
        metadata.artifact_sha256,
        hash_json_entries(entries),
        "upstream metadata corpus hash mismatch in {}",
        metadata_path.display()
    );
}

fn assert_large_corpus_integrity(source: &LargeCorpusSource, entries: &[Value]) {
    match source {
        LargeCorpusSource::UpstreamMinimizer(path) => {
            assert_upstream_metadata_integrity_for_entries(path, entries);
        }
        LargeCorpusSource::DerivedExternalFile(_) | LargeCorpusSource::DerivedFromCoreVectors => {
            // Derived corpus integrity is pinned to tx corpus fixtures and generated metadata.
            assert_generated_metadata_integrity_for_entries(entries);
        }
    }
}

fn maybe_export_large_corpus_entries(entries: &[Value], source: &LargeCorpusSource) {
    let Ok(path) = env::var("SCRIPT_ASSETS_WRITE_UPSTREAM_JSON") else {
        return;
    };
    let output_path = PathBuf::from(path);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|err| {
            panic!(
                "failed to create parent directory for {}: {err}",
                output_path.display()
            )
        });
    }
    let encoded =
        serde_json::to_vec_pretty(entries).expect("script-assets upstream corpus serialization");
    fs::write(&output_path, encoded).unwrap_or_else(|err| {
        panic!(
            "failed to write script-assets upstream corpus {}: {err}",
            output_path.display()
        )
    });
    println!(
        "wrote script-assets upstream corpus to {} (cases={}, source={:?})",
        output_path.display(),
        entries.len(),
        source
    );
}

#[test]
fn script_assets_curated_smoke_monotonicity() {
    let path = curated_asset_path();
    assert!(
        path.exists(),
        "curated script assets file does not exist: {}",
        path.display()
    );
    let entries = load_script_asset_entries(&path);
    print_curated_summary(entries.len(), &path);
    run_script_assets_entries_monotonicity(&entries, "curated-smoke");
}

#[test]
fn script_assets_generated_corpus_monotonicity() {
    let (entries, source, stats) = load_or_generate_large_script_assets_entries();
    let label = match &source {
        LargeCorpusSource::UpstreamMinimizer(path) => {
            format!("upstream-minimizer:{}", path.display())
        }
        LargeCorpusSource::DerivedExternalFile(path) => {
            format!("derived-external-file:{}", path.display())
        }
        LargeCorpusSource::DerivedFromCoreVectors => "derived-from-core-vectors".to_string(),
    };
    match &source {
        LargeCorpusSource::DerivedFromCoreVectors => {
            assert!(
                stats.unknown_token_counts.is_empty(),
                "generated corpus encountered unknown tx-vector flags: {:?}",
                stats.unknown_token_counts
            );
        }
        LargeCorpusSource::UpstreamMinimizer(_) => {}
        LargeCorpusSource::DerivedExternalFile(_) => {
            println!("using externally supplied derived script_assets corpus");
        }
    }
    enforce_large_corpus_profile_requirements(&source, &entries);
    assert_large_corpus_integrity(&source, &entries);
    maybe_export_large_corpus_entries(&entries, &source);
    print_large_source_summary(&source, entries.len(), &stats);
    run_script_assets_entries_monotonicity(&entries, &label);
}

#[test]
fn script_assets_generated_metadata_integrity() {
    if generated_asset_path().is_some() || upstream_minimizer_asset_path().is_some() {
        eprintln!(
            "skipping derived metadata integrity check (external large script-assets corpus supplied)"
        );
        return;
    }

    let (entries, stats) = generate_script_assets_entries();
    assert!(
        stats.unknown_token_counts.is_empty(),
        "generated corpus encountered unknown tx-vector flags: {:?}",
        stats.unknown_token_counts
    );
    assert_generated_metadata_integrity_for_entries(&entries);
}

#[test]
fn script_assets_upstream_metadata_integrity() {
    let Some(path) = upstream_minimizer_asset_path() else {
        eprintln!(
            "skipping upstream metadata integrity check (set SCRIPT_ASSETS_UPSTREAM_JSON to enable)"
        );
        return;
    };
    let entries = load_script_asset_entries(&path);
    assert_upstream_metadata_integrity_for_entries(&path, &entries);
}

#[test]
fn script_assets_monotonicity_over_core_tx_valid_vectors() {
    run_core_tx_monotonicity(CORE_TX_VALID, true);
}

#[test]
fn script_assets_core_tx_invalid_exact_flag_failures() {
    run_core_tx_monotonicity(CORE_TX_INVALID, false);
}

#[test]
fn script_assets_upstream_case_116_siglen_popbyte_csa_neg() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/script_assets_upstream.json");
    if !path.exists() {
        eprintln!(
            "skipping upstream case-116 regression (missing {})",
            path.display()
        );
        return;
    }

    let entries = load_script_asset_entries(&path);
    let case = entries
        .get(116)
        .unwrap_or_else(|| panic!("upstream corpus missing case #116 in {}", path.display()));
    let obj = case
        .as_object()
        .unwrap_or_else(|| panic!("upstream case #116 must be an object"));

    let tx_hex = obj
        .get("tx")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("upstream case #116 missing tx"));
    let tx_bytes =
        Vec::from_hex(tx_hex).unwrap_or_else(|_| panic!("upstream case #116 has invalid tx hex"));
    let mut tx = btc_consensus::deserialize::<Transaction>(&tx_bytes)
        .unwrap_or_else(|_| panic!("upstream case #116 tx failed to deserialize"));

    let prevouts = parse_prevouts(
        obj.get("prevouts")
            .unwrap_or_else(|| panic!("upstream case #116 missing prevouts")),
    );
    let input_index = obj
        .get("index")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("upstream case #116 missing index")) as usize;
    assert_eq!(
        input_index, 0,
        "upstream case #116 index changed unexpectedly"
    );
    assert_eq!(
        tx.input.len(),
        prevouts.len(),
        "upstream case #116 prevout count mismatch"
    );
    let flags = parse_flags(
        obj.get("flags")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("upstream case #116 missing flags")),
    );
    assert_eq!(
        flags, 0x20e15,
        "upstream case #116 flags changed unexpectedly"
    );

    let success = obj
        .get("success")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("upstream case #116 missing success branch"));
    tx.input[input_index].script_sig = ScriptBuf::from_bytes(
        Vec::from_hex(
            success
                .get("scriptSig")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("upstream case #116 success missing scriptSig")),
        )
        .unwrap_or_else(|_| panic!("upstream case #116 success scriptSig hex invalid")),
    );
    tx.input[input_index].witness = parse_witness(
        success
            .get("witness")
            .unwrap_or_else(|| panic!("upstream case #116 success missing witness")),
    );
    let success_result = verify_case(&tx, &prevouts, input_index, flags);
    assert!(
        success_result.is_ok(),
        "upstream case #116 success branch should pass, got {success_result:?}"
    );

    let failure = obj
        .get("failure")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("upstream case #116 missing failure branch"));
    tx.input[input_index].script_sig = ScriptBuf::from_bytes(
        Vec::from_hex(
            failure
                .get("scriptSig")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("upstream case #116 failure missing scriptSig")),
        )
        .unwrap_or_else(|_| panic!("upstream case #116 failure scriptSig hex invalid")),
    );
    tx.input[input_index].witness = parse_witness(
        failure
            .get("witness")
            .unwrap_or_else(|| panic!("upstream case #116 failure missing witness")),
    );
    let failure_result = verify_case(&tx, &prevouts, input_index, flags)
        .expect_err("upstream case #116 failure branch must fail");
    assert_eq!(failure_result.script_error, consensus::ScriptError::SchnorrSig);
}
