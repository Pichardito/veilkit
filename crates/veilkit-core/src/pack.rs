//! Built-in rule packs, embedded at compile time and version-checked.

use crate::rule::RuleFile;
use crate::{Error, Result};

/// The version every shipped pack file must declare. Bumped together.
pub const PACKS_VERSION: &str = "2026.10";

/// Built-in packs. The string form (`"pii"`) is what the CLI and the npm
/// wrapper accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pack {
    Pii,
    PhiUs,
    Secrets,
    Finance,
}

impl Pack {
    pub const ALL: [Pack; 4] = [Pack::Pii, Pack::PhiUs, Pack::Secrets, Pack::Finance];

    pub fn name(self) -> &'static str {
        match self {
            Pack::Pii => "pii",
            Pack::PhiUs => "phi-us",
            Pack::Secrets => "secrets",
            Pack::Finance => "finance",
        }
    }

    /// The raw TOML source, embedded with `include_str!` so the binary is
    /// self-contained.
    pub fn source(self) -> &'static str {
        match self {
            Pack::Pii => include_str!("../../../packs/pii.toml"),
            Pack::PhiUs => include_str!("../../../packs/phi-us.toml"),
            Pack::Secrets => include_str!("../../../packs/secrets.toml"),
            Pack::Finance => include_str!("../../../packs/finance.toml"),
        }
    }

    /// Parse the pack and assert its declared version matches
    /// [`PACKS_VERSION`]. A mismatch is a build defect, surfaced as an error
    /// rather than a panic so the WASM boundary never traps.
    pub fn load(self) -> Result<RuleFile> {
        let file = RuleFile::parse_toml(self.source())?;
        if file.version != PACKS_VERSION {
            return Err(Error::Parse(format!(
                "pack `{}` declares version {} but the engine expects {}",
                self.name(),
                file.version,
                PACKS_VERSION
            )));
        }
        Ok(file)
    }
}

impl std::str::FromStr for Pack {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "pii" => Ok(Pack::Pii),
            "phi-us" | "phi_us" | "phi" => Ok(Pack::PhiUs),
            "secrets" | "secret" => Ok(Pack::Secrets),
            "finance" | "fin" => Ok(Pack::Finance),
            other => Err(Error::UnknownPack(other.to_string())),
        }
    }
}
