const u256_equalverify = loop(8, i => [
    u32_roll(8 - i),
    u32_equalverify,
]);