#!/usr/bin/env python3
"""Project official EEST v5.4.0 application transitions into Neutrin0's trie tests.

Usage: python3 scripts/fixtures/import-evm-fixtures.py target/fixtures OUTPUT
Ethereum beacon-root/request/blockhash system transitions are intentionally omitted.
Raw user transactions, application pre/post accounts and expected gas are unchanged.
"""
import hashlib
import json
import pathlib
import sys

SYSTEMS = {
    '0x00000000219ab540356cbb839cbe05303d7705fa',
    '0x00000961ef480eb55e80d19ad83579a64c007002',
    '0x0000bbddc7ce488642fb579f8b00f3a590007251',
    '0x0000f90827f1c53a10cb7a02335b175320002935',
    '0x000f3df6d732807ef1319fb7b8bb8522d0beac02',
}
FILES = [
    'osaka/eip7939_count_leading_zeros/test_clz_opcode_scenarios.json',
    'osaka/eip7939_count_leading_zeros/test_clz_gas_cost.json',
    'osaka/eip7939_count_leading_zeros/test_clz_initcode_create.json',
    'osaka/eip7939_count_leading_zeros/test_clz_from_set_code.json',
    'osaka/eip7939_count_leading_zeros/test_clz_call_operation.json',
    'osaka/eip7825_transaction_gas_limit_cap/test_maximum_gas_refund.json',
    'cancun/eip1153_tstore/test_transient_storage_unset_values.json',
    'prague/eip7702_set_code_tx/test_delegation_clearing_failing_tx.json',
]

def rlp(data, offset=0):
    """Return raw encoding, payload/children and end position; no re-encoding."""
    start = offset
    tag = data[offset]
    offset += 1
    if tag < 0x80:
        return data[start:offset], data[start:offset], offset
    if tag < 0xb8:
        length, sequence = tag - 0x80, False
    elif tag < 0xc0:
        size = tag - 0xb7
        length, sequence = int.from_bytes(data[offset:offset + size]), False
        offset += size
    elif tag < 0xf8:
        length, sequence = tag - 0xc0, True
    else:
        size = tag - 0xf7
        length, sequence = int.from_bytes(data[offset:offset + size]), True
        offset += size
    end = offset + length
    if sequence:
        children = []
        while offset < end:
            child = rlp(data, offset)
            children.append(child)
            offset = child[2]
        payload = children
    else:
        payload = data[offset:end]
    return data[start:end], payload, end

root, destination = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
result = []
for filename in FILES:
    path = root / 'blockchain_tests' / filename
    raw = path.read_bytes()
    tests = json.loads(raw)
    eligible = [(name, test) for name, test in tests.items()
                if test['network'] == 'Osaka' and len(test['blocks']) == 1
                and 'blockHeader' in test['blocks'][0]]
    if not eligible:
        raise ValueError(f'no Osaka cases in {path}')
    # Deterministic samples spread across all parameterizations, including endpoints.
    selected = sorted({index * (len(eligible) - 1) // min(7, len(eligible) - 1)
                       for index in range(min(8, len(eligible)))}) if len(eligible) > 1 else [0]
    for index in selected:
        name, test = eligible[index]
        block = test['blocks'][0]
        transactions = rlp(bytes.fromhex(block['rlp'][2:]))[1][1][1]
        exact = [node[0] if isinstance(node[1], list) else node[1] for node in transactions]
        header = block['blockHeader']
        result.append({
            'name': name, 'file': filename, 'sha256': hashlib.sha256(raw).hexdigest(),
            'pre': {address: account for address, account in test['pre'].items() if address not in SYSTEMS},
            'post': {address: account for address, account in test['postState'].items() if address not in SYSTEMS},
            'transactions': ['0x' + transaction.hex() for transaction in exact],
            'gas': header['gasUsed'], 'gas_limit': header['gasLimit'], 'timestamp': header['timestamp'],
            'base_fee': header['baseFeePerGas'], 'coinbase': header['coinbase'],
            'seed': header['mixHash'], 'parent': header['parentHash'],
        })
destination.write_text(json.dumps(result, indent=2) + '\n')
print(f'Imported {len(result)} exact Osaka application transitions')
