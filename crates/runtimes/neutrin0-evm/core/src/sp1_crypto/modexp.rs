//! Bounded 256-bit modular exponentiation over the constrained BIGINT wrapper.

use crypto_bigint::{Encoding, U256};

pub(super) fn read_u256(bytes: &[u8]) -> U256 {
    let mut padded = [0; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    U256::from_be_bytes(padded)
}

pub(super) fn significant_bytes(bytes: &[u8]) -> &[u8] {
    let leading = bytes.iter().take_while(|byte| **byte == 0).count();
    &bytes[leading..]
}

fn exponent_bit(bytes: &[u8], index: usize) -> u8 {
    (bytes[index / 8] >> (7 - index % 8)) & 1
}

pub(super) fn exponentiate_u256(base: U256, exponent: &[u8], modulus: &U256) -> U256 {
    let multiply = |a: &U256, b: &U256| crypto_bigint::succinct::modmul_u256(a, b, modulus);
    let exponent = significant_bytes(exponent);
    let population: u32 = exponent.iter().map(|byte| byte.count_ones()).sum();
    let mut result = U256::ONE;
    if exponent.len() < 16 || population <= 16 {
        // Short/sparse exponents avoid precomputation; zero remains one mod m.
        for byte in exponent {
            for bit in (0..8).rev() {
                result = multiply(&result, &result);
                if byte & (1 << bit) != 0 {
                    result = multiply(&result, &base);
                }
            }
        }
        return result;
    }
    // Eight odd powers support a bounded four-bit sliding window. Each result
    // is constrained/reduced by the official wrapper, also for even moduli.
    let square = multiply(&base, &base);
    let mut powers = [base; 8];
    for index in 1..powers.len() {
        powers[index] = multiply(&powers[index - 1], &square);
    }
    let bits = exponent.len() * 8;
    let mut position = 0;
    while position < bits {
        if exponent_bit(exponent, position) == 0 {
            result = multiply(&result, &result);
            position += 1;
            continue;
        }
        let mut end = (position + 4).min(bits);
        while exponent_bit(exponent, end - 1) == 0 {
            end -= 1;
        }
        let mut digit = 0_usize;
        for index in position..end {
            result = multiply(&result, &result);
            digit = (digit << 1) | usize::from(exponent_bit(exponent, index));
        }
        result = multiply(&result, &powers[digit / 2]);
        position = end;
    }
    result
}
