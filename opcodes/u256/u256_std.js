import {loop} from '../utils.js'
import {u32_equalverify} from '../u32/u32_std.js'
import {u32_zip} from '../u32/u32_zip.js'

export const u256_equalverify = loop(8, i => [
    u32_zip(0, 8 - i),
    u32_equalverify,
]);
