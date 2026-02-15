#![cfg(feature = "core-diff")]

use libloading::Library;
use std::{
    env,
    ffi::c_int,
    fs,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::OnceLock,
};

pub const LEGACY_LIBCONSENSUS_SUPPORTED_FLAGS: u32 = consensus::VERIFY_P2SH
    | consensus::VERIFY_DERSIG
    | consensus::VERIFY_NULLDUMMY
    | consensus::VERIFY_CHECKLOCKTIMEVERIFY
    | consensus::VERIFY_CHECKSEQUENCEVERIFY
    | consensus::VERIFY_WITNESS
    | consensus::VERIFY_TAPROOT;

pub const ALL_KNOWN_SCRIPT_VERIFY_FLAGS: u32 = consensus::VERIFY_P2SH
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
pub struct CoreUtxo {
    pub script_pubkey: *const u8,
    pub script_pubkey_len: u32,
    pub value: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct CoreVerifyResult {
    pub ok: bool,
    pub err_code: i32,
}

type VerifyWithAmountFn =
    unsafe extern "C" fn(*const u8, u32, i64, *const u8, u32, u32, u32, *mut c_int) -> c_int;

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

pub struct CoreDiffHarness {
    backend: CoreDiffBackend,
}

enum CoreDiffBackend {
    LegacyLib(LegacyConsensusLib),
    Helper(CoreHelperProcess),
}

struct LegacyConsensusLib {
    lib: Library,
    library_path: PathBuf,
    version: Option<u32>,
    has_spent_outputs_api: bool,
}

struct CoreHelperProcess {
    helper_path: PathBuf,
    _child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl CoreDiffHarness {
    pub fn from_env() -> Result<Option<Self>, String> {
        let backend_pref = env::var("CORE_CPP_DIFF_BACKEND").ok();
        let helper_candidate = Self::helper_candidate()?;
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

    pub fn backend_label(&self) -> String {
        match &self.backend {
            CoreDiffBackend::LegacyLib(backend) => format!(
                "legacy-libbitcoinconsensus:{} version={:?}",
                backend.library_path.display(),
                backend.version
            ),
            CoreDiffBackend::Helper(backend) => {
                format!("core-helper:{}", backend.helper_path.display())
            }
        }
    }

    pub fn is_helper_backend(&self) -> bool {
        matches!(self.backend, CoreDiffBackend::Helper(_))
    }

    pub fn has_spent_outputs_api(&self) -> bool {
        match &self.backend {
            CoreDiffBackend::LegacyLib(backend) => backend.has_spent_outputs_api,
            CoreDiffBackend::Helper(_) => true,
        }
    }

    pub fn supported_flags_mask(&self) -> u32 {
        match &self.backend {
            CoreDiffBackend::LegacyLib(_) => LEGACY_LIBCONSENSUS_SUPPORTED_FLAGS,
            CoreDiffBackend::Helper(_) => ALL_KNOWN_SCRIPT_VERIFY_FLAGS,
        }
    }

    pub fn verify(
        &mut self,
        script_pubkey: &[u8],
        amount_sat: u64,
        tx_bytes: &[u8],
        spent_outputs: Option<&[CoreUtxo]>,
        input_index: usize,
        flags: u32,
    ) -> Result<CoreVerifyResult, String> {
        let (ok, err_code) = match &mut self.backend {
            CoreDiffBackend::LegacyLib(backend) => backend.verify(
                script_pubkey,
                amount_sat,
                tx_bytes,
                spent_outputs,
                input_index,
                flags,
            )?,
            CoreDiffBackend::Helper(backend) => backend.verify(
                script_pubkey,
                amount_sat,
                tx_bytes,
                spent_outputs,
                input_index,
                flags,
            )?,
        };
        Ok(CoreVerifyResult { ok, err_code })
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

    fn helper_candidate() -> Result<Option<PathBuf>, String> {
        if let Some(path) = Self::discover_helper_binary_path() {
            return Ok(Some(path));
        }
        static CACHED_HELPER_BUILD: OnceLock<Result<Option<PathBuf>, String>> = OnceLock::new();
        CACHED_HELPER_BUILD
            .get_or_init(Self::maybe_build_helper)
            .clone()
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
        // SAFETY: Loading a dynamic library is inherently unsafe; symbols are validated below.
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
            lib.get::<VerifyWithSpentOutputsFn>(
                b"bitcoinconsensus_verify_script_with_spent_outputs\0",
            )
            .is_ok()
        };

        // SAFETY: Optional symbol probe, type matches expected ABI.
        let version = unsafe {
            lib.get::<VersionFn>(b"bitcoinconsensus_version\0")
                .ok()
                .map(|sym| sym())
        };

        Ok(Self {
            backend: CoreDiffBackend::LegacyLib(LegacyConsensusLib {
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
        let child_stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("failed to open stdin for helper process {}", path.display()))?;
        let child_stdout = child.stdout.take().ok_or_else(|| {
            format!(
                "failed to open stdout for helper process {}",
                path.display()
            )
        })?;
        Ok(Self {
            backend: CoreDiffBackend::Helper(CoreHelperProcess {
                helper_path: path,
                _child: child,
                stdin: BufWriter::new(child_stdin),
                stdout: BufReader::new(child_stdout),
            }),
        })
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
                // SAFETY: Symbol exists and pointer/length pairs are valid for this call.
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

        // SAFETY: Symbol exists and pointer/length pairs are valid for this call.
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

impl CoreHelperProcess {
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
                // SAFETY: The caller provides stable script pointers for this call.
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
                        ));
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
