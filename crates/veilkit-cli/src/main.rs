//! `veilkit`: scan or redact text from stdin or files.
//!
//! Exit codes: 0 ok, 1 usage or I/O error, 2 when `--fail-on <severity>` is
//! set and a span at or above that severity was found.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use veilkit_core::{Engine, Pack, RedactOptions, Severity, Style, DEFAULT_MAX_INPUT_BYTES};

#[derive(Parser)]
#[command(
    name = "veilkit",
    version,
    about = "Find and redact PII, PHI, secrets and financial identifiers"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List spans found in the input
    Scan {
        #[command(flatten)]
        common: Common,
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Replace spans with placeholders and print the result
    Redact {
        #[command(flatten)]
        common: Common,
        #[arg(long, value_enum, default_value_t = StyleArg::Label)]
        style: StyleArg,
        /// With --style mask: how many trailing alphanumerics to keep
        #[arg(long, default_value_t = 4)]
        keep_last: usize,
        /// Print the redaction as JSON (text, spans, map) instead of plain text
        #[arg(long)]
        json: bool,
        /// Include the placeholder → original map in --json output
        #[arg(long)]
        reversible: bool,
    },
    /// List the rules in the selected packs
    Packs {
        /// Comma-separated packs (default: all)
        #[arg(long, value_delimiter = ',')]
        packs: Vec<String>,
        /// Emit a Markdown table (used to generate docs/packs.md)
        #[arg(long)]
        markdown: bool,
    },
}

#[derive(Args)]
struct Common {
    /// Files to read; stdin when none given
    files: Vec<PathBuf>,
    /// Comma-separated packs: pii, phi-us, secrets, finance (default: all)
    #[arg(long, value_delimiter = ',')]
    packs: Vec<String>,
    /// TOML file with custom rules (overrides built-ins by id)
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Exit 2 if any span at or above this severity is found
    #[arg(long, value_enum)]
    fail_on: Option<SeverityArg>,
    /// Only report spans at or above this severity
    #[arg(long, value_enum)]
    min_severity: Option<SeverityArg>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum StyleArg {
    Label,
    Numbered,
    Mask,
    Hash,
}

#[derive(Clone, Copy, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
        }
    }
}

fn build_engine(pack_names: &[String], rules: Option<&PathBuf>) -> Result<Engine> {
    let packs: Vec<Pack> = if pack_names.is_empty() {
        Pack::ALL.to_vec()
    } else {
        pack_names
            .iter()
            .map(|p| p.parse::<Pack>())
            .collect::<std::result::Result<_, _>>()?
    };
    let mut b = Engine::builder().packs(packs);
    if let Some(path) = rules {
        let src =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        b = b.custom_rules_toml(&src)?;
    }
    Ok(b.build()?)
}

fn read_input(files: &[PathBuf]) -> Result<String> {
    let mut buf = String::new();
    if files.is_empty() {
        io::stdin()
            .read_to_string(&mut buf)
            .context("reading stdin")?;
    } else {
        for f in files {
            let s =
                std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
            buf.push_str(&s);
            if !s.ends_with('\n') {
                buf.push('\n');
            }
        }
    }
    Engine::ensure_within_limit(&buf, DEFAULT_MAX_INPUT_BYTES)?;
    Ok(buf)
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let mut out = io::stdout().lock();
    match cli.cmd {
        Cmd::Scan { common, format } => {
            let engine = build_engine(&common.packs, common.rules.as_ref())?;
            let text = read_input(&common.files)?;
            let min = common.min_severity.map(Severity::from);
            let spans: Vec<_> = engine
                .scan(&text)
                .into_iter()
                .filter(|s| min.is_none_or(|m| s.severity >= m))
                .collect();
            match format {
                Format::Json => writeln!(out, "{}", serde_json::to_string_pretty(&spans)?)?,
                Format::Text => {
                    for s in &spans {
                        writeln!(
                            out,
                            "{}\t{:?}\t{:?}\t{}..{}\t{}",
                            s.id,
                            s.severity,
                            s.confidence,
                            s.start,
                            s.end,
                            s.slice(&text)
                        )?;
                    }
                }
            }
            Ok(gate(common.fail_on, spans.iter().map(|s| s.severity)))
        }
        Cmd::Redact {
            common,
            style,
            keep_last,
            json,
            reversible,
        } => {
            let engine = build_engine(&common.packs, common.rules.as_ref())?;
            let text = read_input(&common.files)?;
            let opts = RedactOptions {
                style: match style {
                    StyleArg::Label => Style::Label,
                    StyleArg::Numbered => Style::Numbered,
                    StyleArg::Mask => Style::Mask { keep_last },
                    StyleArg::Hash => Style::Hash,
                },
                reversible,
                min_severity: common.min_severity.map(Severity::from),
                min_confidence: None,
            };
            let red = engine.redact(&text, &opts);
            if json {
                writeln!(out, "{}", serde_json::to_string_pretty(&red)?)?;
            } else {
                write!(out, "{}", red.text)?;
            }
            Ok(gate(
                common.fail_on,
                red.spans.iter().map(|s| s.span.severity),
            ))
        }
        Cmd::Packs { packs, markdown } => {
            let engine = build_engine(&packs, None)?;
            if markdown {
                writeln!(
                    out,
                    "| Rule id | Label | Severity | Validator | Needs context | Description |"
                )?;
                writeln!(out, "|---|---|---|---|---|---|")?;
            }
            for r in engine.rules() {
                let v = r.validator.unwrap_or_default();
                if markdown {
                    writeln!(
                        out,
                        "| `{}` | `{}` | {:?} | {} | {} | {} |",
                        r.id,
                        r.label,
                        r.severity,
                        if v.is_empty() {
                            "—".to_string()
                        } else {
                            format!("`{v}`")
                        },
                        if r.requires_context { "yes" } else { "" },
                        r.description
                    )?;
                } else {
                    writeln!(out, "{}\t{:?}\t{}\t{}", r.id, r.severity, v, r.description)?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn gate(fail_on: Option<SeverityArg>, found: impl Iterator<Item = Severity>) -> ExitCode {
    match fail_on {
        Some(threshold) => {
            let t = Severity::from(threshold);
            let mut found = found;
            if found.any(|s| s >= t) {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        None => ExitCode::SUCCESS,
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("veilkit: {e:#}");
            ExitCode::from(1)
        }
    }
}
