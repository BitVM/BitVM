pub(super) const fn log_base_ceil(n: u32, base: u32) -> u32 { 
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    return res;
}

pub(super) fn to_digits(mut number: u32, base: u32, digit_count: i32) -> Vec<u32> {
    let mut digits = Vec::new();
    if digit_count == -1 {
        while number > 0 {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }   
    } else {
        digits.reserve(digit_count as usize);
        for _ in 0..digit_count {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    }
    digits
}

//This function can change dramatically (for example it can be reversed, those kind of things can reduce the script size a lot but current optimizations are for the straightforward transformation)
pub(super) fn bytes_to_u32s(len: u32, bits_per_item: u32, bytes: &Vec<u8>) -> Vec<u32> {
    assert!(bytes.len() as u32 * 8 <= len * bits_per_item, "Message length is too large for the parameters"); 
    let mut res = vec![0u32; len as usize];
    let mut cur_index: u32 = 0;
    let mut cur_bit: u32 = 0;
    for byte in bytes {
        let mut x: u8 = *byte;
        for _ in 0..8 {
            if cur_bit == bits_per_item {
                cur_bit = 0;
                cur_index += 1;
            }
            res[cur_index as usize] |= ((x & 1) as u32) << cur_bit;
            x >>= 1;
            cur_bit += 1;
        }
    }
    res
}

pub(super) fn get_type_name<T>() -> String {
    let full_type_name = std::any::type_name::<T>();
    let res = full_type_name.split("::").last().unwrap_or(full_type_name);
    res.to_string()
}