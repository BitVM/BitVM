
const u256_equalverify = loop(8, i => [
    u32_zip(0, 8 - i),
    u32_equalverify,
]);
