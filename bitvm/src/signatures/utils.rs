use crate::treepp::*;

/// Calculates ceil(log_base(n))
pub(super) const fn log_base_ceil(n: u32, base: u32) -> u32 {
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    res
}

/// Converts the given `checksum` into a vector of digits.
///
/// ## Output format
///
/// - sequence of `n_digits` many digits
/// - each digit a `u32` value in range `0..base`
/// - checksum converted into BE bytes, in turn converted into digits
pub(super) fn checksum_to_digits(mut checksum: u32, base: u32, n_digits: u32) -> Vec<u32> {
    debug_assert!((16..=256).contains(&base));
    debug_assert!(
        base.checked_pow(n_digits)
            .map(|upper_limit| checksum < upper_limit)
            .unwrap_or(true),
        "Checksum is too large to fit into the given number of digits"
    );

    let mut digits = vec![0; n_digits as usize]; // cast safety: 32-bit machine or higher

    for digit in digits.iter_mut().rev() {
        *digit = checksum % base;
        checksum = (checksum - *digit) / base;
    }

    digits
}

/// Converts the given `message` into a vector of digits.
///
/// ## Output format
///
/// - sequence of `n_digits` many digits
/// - each digit a `u32` value in range `0..2.pow(log2_base)`
/// - message bytes are reversed (but not their nibbles!)
pub(crate) fn message_to_digits(n_digits: u32, log2_base: u32, message: &[u8]) -> Vec<u32> {
    debug_assert!((4..=8).contains(&log2_base));
    debug_assert!(
        message.len() as u32 * 8 <= n_digits * log2_base,
        "Message is too long to fit into the given number of digits"
    );

    let mut digits = vec![0u32; n_digits as usize]; // cast safety: 32-bit machine or higher
    let mut digit_idx: u32 = 0;
    let mut bit_idx: u32 = 0;

    for mut byte in message.iter().copied() {
        for _ in 0..8 {
            if bit_idx == log2_base {
                bit_idx = 0;
                digit_idx += 1;
            }
            digits[digit_idx as usize] |= ((byte & 1) as u32) << bit_idx; // cast safety: 32-bit machine or higher
            byte >>= 1;
            bit_idx += 1;
        }
    }

    digits.reverse();
    digits
}

/// Returns a Bitcoin script that converts a message into a number.
///
/// ## Precondition
///
/// - message is at stack top
/// - message is split into `N_DIGITS` digits
/// - each digit is in range `0..2.pow(LOG2_BASE)`
///
/// ## Postcondition
///
/// - converted number is at stack top
pub fn digits_to_number<const N_DIGITS: usize, const LOG2_BASE: usize>() -> Script {
    script! {
        for _ in 0..N_DIGITS - 1 {
          OP_TOALTSTACK
        }
        for _ in 0..N_DIGITS - 1 {
            for _ in 0..LOG2_BASE {
                OP_DUP OP_ADD // simulating OP_MUL
            }
            OP_FROMALTSTACK
            OP_ADD
        }
    }
}

pub fn bitcoin_representation(x: u32) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let len = bitcoin::script::write_scriptint(&mut buf, x as i64);
    return buf[0..len].to_vec();
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::run;

    #[test]
    fn test_bitcoin_representation() {
        for i in 0..256 {
            run(script! {
                { i }
                { bitcoin_representation(i) }
                OP_EQUAL
            })
        }
    }

    #[test]
    fn checksum_to_digits_endianness() {
        // Integer is encoded as BE digit sequence
        assert_eq!(
            checksum_to_digits(0x12345678, 16, 8),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );
    }

    #[test]
    fn message_to_digits_endianness() {
        let message: u32 = 0x12345678;
        // Bytes are reversed from BE to LE
        // Digits stay BE
        // The result is a weird mix of endianness
        assert_eq!(
            message_to_digits(8, 4, &message.to_be_bytes()),
            vec![7, 8, 5, 6, 3, 4, 1, 2],
        );
        // Bytes are reversed from LE to BE
        // Digits stay BE
        // The result is a BE sequence
        assert_eq!(
            message_to_digits(8, 4, &message.to_le_bytes()),
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );
    }

    #[test]
    fn digits_to_number_endianness() {
        // LE input is glued together as LE
        let script = script! {
            { vec![0x07, 0x08, 0x05, 0x06, 0x03, 0x04, 0x01, 0x02] }
            { digits_to_number::<8, 4>() }
            { 0x78563412 }
            OP_EQUAL
        };
        run(script);
        // BE input is glued together as BE
        let script = script! {
            { vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] }
            { digits_to_number::<8, 4>() }
            { 0x12345678 }
            OP_EQUAL
        };
        run(script);
    }

    #[test]
    fn message_digits_roundtrip() {
        let message: u32 = 0x12345678;
        let digits = message_to_digits(8, 4, &message.to_le_bytes());
        let script = script! {
            { digits }
            { digits_to_number::<8, 4>() }
            { message }
            OP_EQUAL
        };
        run(script);
    }
}
