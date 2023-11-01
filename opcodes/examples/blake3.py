def mask32(x: int) -> int:
    return x & 0xFFFFFFFF


def add32(x: int, y: int) -> int:
    return mask32(x + y)


def rightrotate32(x: int, n: int) -> int:
    return mask32(x << (32 - n)) | (x >> n)


# The mixing function, G, which mixes either a column or a diagonal.
def g(a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    a = add32(a, add32(b, mx))
    d = rightrotate32(d ^ a, 16)
    c = add32(c, d)
    b = rightrotate32(b ^ c, 12)
    a = add32(a, add32(b, my))
    d = rightrotate32(d ^ a, 8)
    c = add32(c, d)
    b = rightrotate32(b ^ c, 7)
    print(hex(a),hex(d),hex(c),hex(b), hex(mx), hex(my))


g(0x04030201, 0x14131211, 0x24232221, 0x34333231, 0x44434241, 0x54535251)




