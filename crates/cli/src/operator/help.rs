//! Usage lines and the `--help` reference of the operator commands.

pub(crate) fn print_usage() {
    eprintln!("  node control-status|shutdown; validator pause-signing|resume-signing");
    eprintln!("      validator pause-production|resume-production --management-socket <path>");
    eprintln!("  node export-snapshot --out <file> [--anchor-chunks N] --management-socket <path>");
    eprintln!("  node status|watch|doctor          Inspect a running node");
    eprintln!("  chain head|finalized|genesis|validators   Query canonical chain summaries");
    eprintln!("  chunk get|certificate|proof [--id N]; proof get --kind block|chunk|certificate");
    eprintln!("  chain events|watch-events [--after-stream HEX --after-sequence N]");
    eprintln!("  block get|header [--at <selector>]");
    eprintln!("  account get --address <hex> [--at <selector>]");
    eprintln!("  validator list|status|register|stake|unstake|exit|withdraw");
    eprintln!("  tx get|receipt|wait|submit|transfer|send");
    eprintln!("  governance status|policy|vote|propose-upgrade|cancel-upgrade|propose-policy");
    eprintln!("  governance propose-fork|cancel-fork");
    eprintln!("  programs status; proving status; history retention|latest|checkpoint");
    eprintln!("  runtime call --method <name> [--args <hex>] [--at <selector>]");
    eprintln!("      RPC commands: --rpc <http(s) URL> --timeout-secs <n> --json");
    eprintln!("      RPC URL defaults to NEUTRIN0_RPC_URL, then http://127.0.0.1:9933");
    eprintln!("      Signing: --key-file <path> [--nonce <n>]");
    eprintln!(
        "      Amounts are integer wei (18 decimals). Prepare by default; --submit broadcasts."
    );
    eprintln!("      Confirmation: --wait included|finalized --wait-timeout-secs <n>");
    eprintln!("      Use --help after any RPC command for the command reference.");
}

pub(super) const HELP: &str =
    "Local management (Unix only; --management-socket PATH or NEUTRIN0_MANAGEMENT_SOCKET):
  node control-status | shutdown
  node export-snapshot --out FILE [--anchor-chunks N]
  validator pause-signing | resume-signing | pause-production | resume-production
Local controls support --timeout-secs and --json; they do not use public RPC.

RPC commands:
  node status | doctor | watch [--interval-secs 2] [--count N]
  chain head | finalized | genesis | validators
  chunk get | certificate | proof [--id N] [--out FILE for proof]
  proof get --kind block --hash HEX | --kind chunk|certificate --id N [--out FILE]
  chain events [--after-stream HEX --after-sequence N] [--limit 128]
  chain watch-events [--after-stream HEX --after-sequence N] [--count N] [--interval-secs 1]
  block get | header [--at latest|safe|finalized|HEIGHT|0xHASH]
  account get --address HEX [--at SELECTOR]
  validator list
  validator status [--address HEX] [--at SELECTOR]
  validator register --ikm-path FILE --amount N --key-file FILE
  validator rotate-key --keystore FILE --password-file FILE | --ikm-path FILE --key-file FILE
  validator stake | unstake --amount N --key-file FILE
  validator exit | withdraw --key-file FILE
  tx transfer --to HEX --amount N --key-file FILE
  tx send --to HEX [--amount N] [--data HEX] --key-file FILE
  tx submit --bytes HEX | --file FILE [--wait included|finalized]
  tx get | receipt --hash 0xHASH
  tx wait --hash 0xHASH [--wait included|finalized]
  governance status | policy [--at SELECTOR]
  governance vote --proposal-id 0xHASH --key-file FILE
  governance propose-upgrade --package FILE --activate-at-chunk N --key-file FILE
  governance cancel-upgrade --key-file FILE (the scheduled switch at the latest head)
  governance propose-fork --fork-chunk N --successor HEX --key-file FILE
      (HEX from `neutrin0-cli fork programs` run with the successor's binary)
  governance cancel-fork --key-file FILE (the scheduled fork at the latest head)
  governance propose-policy [--min-validator-stake N] [--evidence-max-age-blocks N]
      [--evidence-max-pending N] [--evidence-admissions-per-block N]
      [--evidence-executions-per-block N] [--inactivity-leak-amount N]
      [--reporter-reward-bps N] [--chunk-prover-fee-bps N] [--annual-issuance-bps N]
      [--abandonment-penalty-amount N] --key-file FILE (unset fields keep the policy in force)
  programs status
  proving status
  history retention
  history latest [--out FILE] (latest chunk receipt; writes exact Borsh bytes)
  history checkpoint --out FILE (trusted bootstrap anchor: the latest proven endpoint)
  runtime call --method NAME [--args HEX] [--at SELECTOR]

Common: --rpc URL, --timeout-secs 10, --json. State queries default to finalized.
Signing prepares a transaction; add --submit to broadcast. --out writes signed bytes.
Signing options: --gas-limit N, --max-fee-per-gas N, --max-priority-fee-per-gas N,
optional --nonce N and --chain-id N (must match the connected node).
Wait defaults: finalized, --wait-timeout-secs 1800, --poll-secs 1. Waiting reports
inclusion and finality through the transaction receipt.
JSON watch emits one complete JSON object per line. Ctrl-C stops watch/wait.
Exit codes: 0 success, 1 failure, 2 invalid command/arguments, 3 diagnostic or execution failure.
";
