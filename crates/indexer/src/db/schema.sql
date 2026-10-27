CREATE TABLE IF NOT EXISTS index_meta (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    schema_hash TEXT NOT NULL,
    state JSONB
);
CREATE TABLE IF NOT EXISTS blocks (
    hash TEXT PRIMARY KEY,
    height NUMERIC(20,0) NOT NULL CHECK (height > 0),
    parent_hash TEXT NOT NULL,
    timestamp NUMERIC(20,0) NOT NULL,
    gas_used NUMERIC(20,0) NOT NULL,
    runtime_hash TEXT NOT NULL,
    decoding TEXT NOT NULL,
    header JSONB NOT NULL,
    artifacts BYTEA NOT NULL,
    transaction_count BIGINT NOT NULL,
    log_count BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS blocks_timestamp ON blocks(timestamp DESC);
CREATE INDEX IF NOT EXISTS blocks_height ON blocks (height DESC);
CREATE TABLE IF NOT EXISTS canonical_blocks (
    height NUMERIC(20,0) PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE REFERENCES blocks(hash)
);
CREATE TABLE IF NOT EXISTS transactions (
    block_hash TEXT NOT NULL REFERENCES blocks(hash) ON DELETE CASCADE,
    position BIGINT NOT NULL,
    height NUMERIC(20,0) NOT NULL,
    hash TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    from_address TEXT,
    to_address TEXT,
    contract_address TEXT,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    data JSONB NOT NULL,
    raw BYTEA NOT NULL,
    PRIMARY KEY (block_hash, position)
);
CREATE INDEX IF NOT EXISTS tx_hash ON transactions (hash);
CREATE INDEX IF NOT EXISTS tx_envelope_hash ON transactions (envelope_hash);
CREATE INDEX IF NOT EXISTS tx_from ON transactions (from_address, height DESC, position DESC);
CREATE INDEX IF NOT EXISTS tx_to ON transactions (to_address, height DESC, position DESC);
CREATE INDEX IF NOT EXISTS tx_contract ON transactions(contract_address,height DESC,position DESC);
CREATE INDEX IF NOT EXISTS tx_height ON transactions (height DESC, position DESC);
CREATE TABLE IF NOT EXISTS logs (
    block_hash TEXT NOT NULL,
    log_index BIGINT NOT NULL,
    transaction_position BIGINT NOT NULL,
    height NUMERIC(20,0) NOT NULL,
    address TEXT NOT NULL,
    topics TEXT[] NOT NULL,
    data JSONB NOT NULL,
    PRIMARY KEY (block_hash, log_index),
    FOREIGN KEY (block_hash, transaction_position) REFERENCES transactions(block_hash,position) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS logs_address ON logs (address, height DESC, log_index DESC);
CREATE INDEX IF NOT EXISTS logs_topic0 ON logs ((topics[1]), height DESC, log_index DESC);
CREATE INDEX IF NOT EXISTS logs_height ON logs (height DESC, log_index DESC);
CREATE TABLE IF NOT EXISTS token_transfers (
    block_hash TEXT NOT NULL,
    log_index BIGINT NOT NULL,
    item_index BIGINT NOT NULL,
    height NUMERIC(20,0) NOT NULL,
    contract TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    standard TEXT NOT NULL,
    data JSONB NOT NULL,
    PRIMARY KEY (block_hash,log_index,item_index),
    FOREIGN KEY (block_hash,log_index) REFERENCES logs(block_hash,log_index) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS transfers_contract ON token_transfers (contract,height DESC,log_index DESC,item_index DESC);
CREATE INDEX IF NOT EXISTS transfers_from ON token_transfers (from_address,height DESC,log_index DESC,item_index DESC);
CREATE INDEX IF NOT EXISTS transfers_to ON token_transfers (to_address,height DESC,log_index DESC,item_index DESC);
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id NUMERIC(20,0) PRIMARY KEY,
    end_height NUMERIC(20,0) NOT NULL,
    data JSONB NOT NULL,
    certificate JSONB
);
CREATE TABLE IF NOT EXISTS proof_metadata (
    locator TEXT PRIMARY KEY,
    height NUMERIC(20,0) NOT NULL,
    kind TEXT NOT NULL,
    block_hash TEXT,
    data JSONB,
    availability TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS proof_height ON proof_metadata (height DESC,kind);
CREATE TABLE IF NOT EXISTS validator_snapshots (
    finalized_chunks NUMERIC(20,0) PRIMARY KEY,
    finalized_hash TEXT NOT NULL,
    data JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
