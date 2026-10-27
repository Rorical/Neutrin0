#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! `neutrin0-cli`: operator tooling for bringing up a network.
//!
//! ```text
//! neutrin0-cli keygen --out <dir> [--name <name>]
//! neutrin0-cli genesis --spec <chain-spec.toml> [--write]
//! neutrin0-cli node-config --spec <chain-spec.toml> --out <config.toml> [options]
//! neutrin0-cli runtime-package --wasm <file> --block <ELF> --genesis <file> --out <file>
//! neutrin0-cli keys inspect | signing export | signing import [options]
//! neutrin0-cli fork programs --spec <chain-spec.toml>
//! ```
//!
//! `keygen` writes a BLS proposer IKM, an Ethereum secp256k1 account key and a
//! libp2p identity as owner-only files and prints the public identities the
//! chain spec and other nodes' bootnode lists need. `signing` moves a stopped
//! validator's anti-equivocation state between data directories.
//! `genesis` derives the genesis state root and chain-spec hash from the
//! allocation in the spec file and can pin the root into the file.
//! `node-config` emits a node configuration that references the key file
//! instead of embedding the secret.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use neutrin0_node::ChainSpecFile;

mod artifacts;
mod files;
mod fork;
mod genesis;
mod keygen;
mod keys;
mod node_config;
mod operator;
mod secret;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|command| operator::is_command(command))
    {
        return match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime.block_on(operator::execute(&args)),
            Err(error) => {
                eprintln!("error: start operator runtime: {error}");
                ExitCode::FAILURE
            }
        };
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            eprintln!();
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return Err("missing command".to_owned());
    }
    let command = args.remove(0);
    let subcommand = (matches!(command.as_str(), "keys" | "signing" | "fork") && !args.is_empty())
        .then(|| args.remove(0));
    let opts = Options::parse(&args)?;
    match command.as_str() {
        "keygen" => keygen::keygen(&opts),
        "genesis" => genesis::genesis(&opts),
        "node-config" => node_config(&opts),
        "program-hash" => artifacts::program_hash(&opts),
        "runtime-package" => artifacts::runtime_package(&opts),
        "keys" if subcommand.as_deref() == Some("inspect") => keys::inspect(&opts),
        "keys" if subcommand.as_deref() == Some("encrypt") => keys::encrypt(&opts),
        "signing" if subcommand.as_deref() == Some("export") => keys::export(&opts),
        "signing" if subcommand.as_deref() == Some("import") => keys::import(&opts),
        "fork" if subcommand.as_deref() == Some("programs") => fork::programs(&opts),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

fn print_usage() {
    eprintln!("usage: neutrin0-cli <command> [options]");
    eprintln!();
    eprintln!("commands:");
    operator::print_usage();
    eprintln!("  keygen --out <dir> [--name <name>] [--keystore-password-file <file>]");
    eprintln!("      Write <name>.ikm (BLS proposer IKM), <name>.secp256k1 (Ethereum account key)");
    eprintln!("      and <name>.p2p (libp2p identity) as owner-only files; with a password file,");
    eprintln!("      <name>.keystore.json (EIP-2335) holds the BLS key instead of the IKM.");
    eprintln!("  keys encrypt --ikm-path <file> --password-file <file> --out <keystore.json>");
    eprintln!("      Write an IKM file's BLS key as an EIP-2335 keystore.");
    eprintln!("  keys inspect [--ikm-path <file>] [--keystore <file>] [--key-file <file>]");
    eprintln!("      [--network-key <file>]");
    eprintln!("      Print the public identities of key files: BLS key, address, peer ID.");
    eprintln!("  signing export --data-dir <dir> --out <file>");
    eprintln!("  signing import --data-dir <dir> --file <file>");
    eprintln!("      Move a stopped validator's signing journal, BFT sessions and pause");
    eprintln!("      policy to a new data directory; import never merges journals.");
    eprintln!("  fork programs --spec <chain-spec.toml>");
    eprintln!("      Print the programs this binary pins as a hard fork's successor and the");
    eprintln!("      commitment a fork proposal names; see the operator runbook.");
    eprintln!("  genesis --spec <chain-spec.toml> [--write]");
    eprintln!("      Derive the genesis state root, validator-set root and chain-spec hash.");
    eprintln!("      --write pins genesis_state_root_hex into the spec file.");
    eprintln!("  node-config --spec <chain-spec.toml> --out <config.toml>");
    eprintln!("      [--role validator|full|archive|light-client|reporter] [--data-dir <dir>]");
    eprintln!("      [--reporter-reward-address <32-byte hex>]  # required for reporter");
    eprintln!("      [--ikm-path <file>] [--proposer-index <n>] [--listen <multiaddr>]...");
    eprintln!("      [--management-socket <absolute path>] [--network-key-path <file>]");
    eprintln!("      [--prover-address <32-byte hex>]");
    eprintln!("      [--trusted-checkpoint <file> --trusted-at <unix secs>]");
    eprintln!("      [--bootnode <multiaddr>]... [--rpc <host:port>] [--metrics <host:port>]");
    eprintln!("      [--proving cpu|cuda]");
    eprintln!("      Emit a node config; the proposer key stays in the referenced file.");
    eprintln!("  runtime-package --wasm <file> --block <ELF> --genesis <Borsh file> --out <file>");
    eprintln!("      [--fact <ELF>] [--evidence <ELF>]  # defaults to the shared Guests");
    eprintln!("      Derive SP1 identities locally and write a verified runtime package;");
    eprintln!("      `governance propose-upgrade --package <file>` proposes it.");
    eprintln!("  program-hash --file <path>");
    eprintln!("      Print the content hash and kind of an upgrade artifact (WASM or Guest ELF).");
}

/// Minimal `--flag value` / `--flag` parser; repeated flags accumulate.
struct Options {
    values: Vec<(String, Option<String>)>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut values = Vec::new();
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            let Some(flag) = arg.strip_prefix("--") else {
                return Err(format!("unexpected argument `{arg}`"));
            };
            let value = match iter.peek() {
                Some(next) if !next.starts_with("--") => iter.next().cloned(),
                _ => None,
            };
            values.push((flag.to_owned(), value));
        }
        Ok(Self { values })
    }

    fn get(&self, flag: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(name, _)| name == flag)
            .and_then(|(_, value)| value.as_deref())
    }

    fn all(&self, flag: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(name, _)| name == flag)
            .filter_map(|(_, value)| value.as_deref())
            .collect()
    }

    fn has(&self, flag: &str) -> bool {
        self.values.iter().any(|(name, _)| name == flag)
    }

    fn require(&self, flag: &str) -> Result<&str, String> {
        self.get(flag)
            .ok_or_else(|| format!("missing required --{flag} <value>"))
    }
}

// ----------------------------------------------------------- node-config

fn node_config(opts: &Options) -> Result<(), String> {
    let spec_path = PathBuf::from(opts.require("spec")?);
    let out = PathBuf::from(opts.require("out")?);
    let file = ChainSpecFile::load_from_path(&spec_path).map_err(|err| err.to_string())?;
    let text = node_config::render(opts, &spec_path, &file)?;
    files::replace_file(&out, text.as_bytes())?;
    println!("wrote {}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "../tests/support/node_config_cases.rs"]
mod node_config_test_cases;

#[cfg(test)]
mod node_config_regression_tests;
