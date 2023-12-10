

export const u32_zip = (a, b) => {
    if (a > b) [a, b] = [b, a];

    a = (a + 1) * 4 - 1
    b = (b + 1) * 4 - 1
    return [
        a+0, OP_ROLL, b, OP_ROLL,
        a+1, OP_ROLL, b, OP_ROLL,
        a+2, OP_ROLL, b, OP_ROLL,
        a+3, OP_ROLL, b, OP_ROLL,
    ]
}

export const u32_copy_zip = (a, b) => 
	a < b ? _u32_copy_zip(a, b) : _u32_zip_copy(b, a);

const _u32_copy_zip = (a, b) => {
    if (a >= b)
        throw 'Error: a >= b'

    a = (a + 1) * 4 - 1
    b = (b + 1) * 4 - 1
    return [
        a+0, OP_PICK, b+1, OP_ROLL,
        a+1, OP_PICK, b+2, OP_ROLL,
        a+2, OP_PICK, b+3, OP_ROLL,
        a+3, OP_PICK, b+4, OP_ROLL,
    ]
}

const _u32_zip_copy = (a, b) => {
    if (a >= b)
        throw 'Error: a >= b'

    a = (a + 1) * 4 - 1
    b = (b + 1) * 4 - 1
    return [
        a+0, OP_ROLL, b, OP_PICK,
        a+1, OP_ROLL, b, OP_PICK,
        a+2, OP_ROLL, b, OP_PICK,
        a+3, OP_ROLL, b, OP_PICK,
    ]
}