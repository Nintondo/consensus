use bitcoin::hashes::{sha256, Hash};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const SNAPSHOT_CORE_COMMIT: &str = "4d7d5f6b79d4c11c47e7a828d81296918fd11d4d";

struct FixtureHash {
    vendored_path: &'static str,
    core_relative_path: &'static str,
    sha256_hex: &'static str,
}

const FIXTURES: &[FixtureHash] = &[
    FixtureHash {
        vendored_path: "tests/data/script_tests.json",
        core_relative_path: "src/test/data/script_tests.json",
        sha256_hex: "8c1bcaac9f16f8c85f601e08f80e28072ad9cabd8a2f631206579f818187dead",
    },
    FixtureHash {
        vendored_path: "tests/data/sighash.json",
        core_relative_path: "src/test/data/sighash.json",
        sha256_hex: "52cf23c2076e7f129c71d5508631d3e5ae3be1b1cb0585c0e23bbb4bb373e924",
    },
    FixtureHash {
        vendored_path: "tests/data/tx_valid.json",
        core_relative_path: "src/test/data/tx_valid.json",
        sha256_hex: "ff64dc1f77d1970b7767ec15630903024c1aa9efd3a6201ab0ade6bf78a4ad63",
    },
    FixtureHash {
        vendored_path: "tests/data/tx_invalid.json",
        core_relative_path: "src/test/data/tx_invalid.json",
        sha256_hex: "0c02ce44ff3a880458f9569a25589315a07f924fcaadac828613d4615776ca52",
    },
    FixtureHash {
        vendored_path: "tests/data/bip341_wallet_vectors.json",
        core_relative_path: "src/test/data/bip341_wallet_vectors.json",
        sha256_hex: "403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f",
    },
];

fn hash_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    sha256::Hash::hash(&bytes).to_string()
}

fn find_core_repo() -> Option<PathBuf> {
    let path = env::var("BITCOIN_CORE_REPO").ok()?;
    let candidate = PathBuf::from(path);
    if candidate.join(".git").exists() && candidate.join("src/test/data").exists() {
        Some(candidate)
    } else {
        None
    }
}

#[test]
fn vendored_core_fixtures_match_pinned_hashes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for fixture in FIXTURES {
        let vendored = root.join(fixture.vendored_path);
        let actual = hash_file(&vendored);
        assert_eq!(
            actual, fixture.sha256_hex,
            "vendored fixture hash mismatch for {} (expected {}, got {}). \
             If you intentionally updated this fixture from Core, update the pinned hash in {}.",
            fixture.vendored_path, fixture.sha256_hex, actual, file!()
        );
    }
}

#[test]
fn vendored_core_fixtures_match_local_core_snapshot_when_available() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(core_repo) = find_core_repo() else {
        eprintln!(
            "skipping local Core fixture hash check (set BITCOIN_CORE_REPO to enable explicit source comparison)"
        );
        return;
    };

    for fixture in FIXTURES {
        let vendored = root.join(fixture.vendored_path);
        let core_file = core_repo.join(fixture.core_relative_path);
        let vendored_hash = hash_file(&vendored);
        let core_hash = hash_file(&core_file);
        assert_eq!(
            core_hash, vendored_hash,
            "fixture drift detected: {} != {}. \
             Refresh from Core snapshot (commit {}) or adjust pinned hashes intentionally.",
            core_file.display(),
            vendored.display(),
            SNAPSHOT_CORE_COMMIT
        );
    }
}
