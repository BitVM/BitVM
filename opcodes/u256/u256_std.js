import {loop} from '../utils.js'
import {u32_equalverify} from '../u32/u32_std.js'
import {u32_roll} from '../u32/u32_std.js'

export const u256_equalverify = loop(8, i => [
    u32_roll(8 - i),
    u32_equalverify,
]);