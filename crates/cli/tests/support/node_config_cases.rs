//! Expected node-config renderings and validation errors.
#![allow(clippy::redundant_pub_crate)] // The binary's private test modules share these fixtures.

pub(super) struct SuccessCase {
    pub(super) name: &'static str,
    pub(super) flags: &'static [&'static str],
    pub(super) expected: &'static str,
}

pub(super) struct FailureCase {
    pub(super) name: &'static str,
    pub(super) flags: &'static [&'static str],
    pub(super) error: &'static str,
}

pub(super) const SUCCESS_CASES: &[SuccessCase] = &[
    SuccessCase {
        name: "default",
        flags: &[],
        expected: include_str!("../fixtures/node_config/default.toml"),
    },
    SuccessCase {
        name: "validator",
        flags: &[
            "--role",
            "validator",
            "--data-dir",
            "node data",
            "--ikm-path",
            "keys/validator.ikm",
            "--proposer-index",
            "2",
            "--listen",
            "/ip4/0.0.0.0/tcp/30303",
            "--listen",
            "/ip4/127.0.0.1/tcp/30304",
            "--bootnode",
            "/ip4/127.0.0.1/tcp/30305",
            "--bootnode",
            "/ip4/127.0.0.1/tcp/30306",
            "--rpc",
            "127.0.0.1:9933",
            "--metrics",
            "127.0.0.1:9615",
        ],
        expected: include_str!("../fixtures/node_config/validator.toml"),
    },
    SuccessCase {
        name: "reporter",
        flags: &[
            "--role",
            "reporter",
            "--reporter-reward-address",
            "000000000000000000000000ABABABABABABABABABABABABABABABABABABABAB",
            "--proving",
            "cuda",
            "--metrics",
            "127.0.0.1:9615",
        ],
        expected: include_str!("../fixtures/node_config/reporter.toml"),
    },
    SuccessCase {
        name: "full",
        flags: &[
            "--role",
            "full",
            "--proposer-index",
            "bad",
            "--ikm-path",
            "ignored.ikm",
        ],
        expected: include_str!("../fixtures/node_config/full.toml"),
    },
    SuccessCase {
        name: "archive",
        flags: &["--role", "archive"],
        expected: include_str!("../fixtures/node_config/archive.toml"),
    },
    SuccessCase {
        name: "light-client",
        flags: &["--role", "light-client"],
        expected: include_str!("../fixtures/node_config/light-client.toml"),
    },
    SuccessCase {
        name: "full-checkpoint",
        flags: &[
            "--role",
            "full",
            "--network-key-path",
            "keys/full.p2p",
            "--prover-address",
            "000000000000000000000000ABABABABABABABABABABABABABABABABABABABAB",
            "--trusted-checkpoint",
            "checkpoint.borsh",
            "--trusted-at",
            "1760000000",
        ],
        expected: include_str!("../fixtures/node_config/full-checkpoint.toml"),
    },
    SuccessCase {
        name: "index-spelling",
        flags: &["--proposer-index", "00"],
        expected: include_str!("../fixtures/node_config/index-spelling.toml"),
    },
    SuccessCase {
        name: "last-scalar",
        flags: &[
            "--role",
            "bad",
            "--role",
            "full",
            "--proving",
            "bad",
            "--proving",
            "cpu",
        ],
        expected: include_str!("../fixtures/node_config/last-scalar.toml"),
    },
];

pub(super) const FAILURE_CASES: &[FailureCase] = &[
    FailureCase {
        name: "bad-role-first",
        flags: &["--role", "bad", "--proving", "bad"],
        error: "unknown --role `bad`",
    },
    FailureCase {
        name: "bad-proving-first",
        flags: &["--proving", "bad", "--proposer-index", "bad"],
        error: "unknown --proving `bad`",
    },
    FailureCase {
        name: "bad-index",
        flags: &["--proposer-index", "bad"],
        error: "--proposer-index must be an integer, got `bad`",
    },
    FailureCase {
        name: "missing-reporter",
        flags: &["--role", "reporter"],
        error: "--role reporter requires --reporter-reward-address <32-byte hex>",
    },
    FailureCase {
        name: "zero-reporter",
        flags: &[
            "--role",
            "reporter",
            "--reporter-reward-address",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
        error: "reporter.reward_address_hex must be a nonzero runtime account (twelve zero bytes, then the 20-byte address)",
    },
    FailureCase {
        name: "reporter-on-full",
        flags: &[
            "--role",
            "full",
            "--reporter-reward-address",
            "abababababababababababababababababababababababababababababababab",
        ],
        error: "--reporter-reward-address requires --role reporter",
    },
    FailureCase {
        name: "checkpoint-without-time",
        flags: &["--role", "full", "--trusted-checkpoint", "checkpoint.borsh"],
        error: "--trusted-checkpoint and --trusted-at must be given together",
    },
    FailureCase {
        name: "archive-checkpoint",
        flags: &[
            "--role",
            "archive",
            "--trusted-checkpoint",
            "checkpoint.borsh",
            "--trusted-at",
            "1760000000",
        ],
        error: "archive nodes replay from genesis and take no checkpoint",
    },
    FailureCase {
        name: "unpayable-prover",
        flags: &[
            "--prover-address",
            "abababababababababababababababababababababababababababababababab",
        ],
        error: "chain spec validation failed: proving.prover_address must be a runtime account (twelve zero bytes, then the 20-byte address)",
    },
];
