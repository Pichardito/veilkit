//! Error type for engine construction. Scanning and redaction never fail:
//! once an [`crate::Engine`] exists, every input is valid.

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("rule `{id}` has an invalid regex: {source}")]
    InvalidPattern {
        id: String,
        #[source]
        source: Box<regex::Error>,
    },
    #[error("duplicate rule id `{0}` within one source")]
    DuplicateRule(String),
    #[error("rule `{id}` names unknown validator `{validator}`")]
    UnknownValidator { id: String, validator: String },
    #[error("unknown pack `{0}`")]
    UnknownPack(String),
    #[error("could not parse rule file: {0}")]
    Parse(String),
    #[error("input of {0} bytes exceeds the {1} byte limit")]
    InputTooLarge(usize, usize),
}

pub type Result<T> = std::result::Result<T, Error>;
