function number$3(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`Wrong positive integer: ${n}`);
}
function bool$3(b) {
    if (typeof b !== 'boolean')
        throw new Error(`Expected boolean, not ${b}`);
}
function bytes$3(b, ...lengths) {
    if (!(b instanceof Uint8Array))
        throw new TypeError('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
function hash$4(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number$3(hash.outputLen);
    number$3(hash.blockLen);
}
function exists$3(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
function output$3(out, instance) {
    bytes$3(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
const assert$1$2 = {
    number: number$3,
    bool: bool$3,
    bytes: bytes$3,
    hash: hash$4,
    exists: exists$3,
    output: output$3,
};
var assert$2$1 = assert$1$2;

/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Cast array to view
const createView$3 = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
// The rotate right (circular right shift) operation for uint32
const rotr$3 = (word, shift) => (word << (32 - shift)) | (word >>> shift);
// big-endian hardware is rare. Just in case someone still decides to run hashes:
// early-throw an error because we don't support BE yet.
const isLE$3 = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
if (!isLE$3)
    throw new Error('Non little-endian hardware is not supported');
Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function utf8ToBytes$4(str) {
    if (typeof str !== 'string') {
        throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
    }
    return new TextEncoder().encode(str);
}
function toBytes$5(data) {
    if (typeof data === 'string')
        data = utf8ToBytes$4(data);
    if (!(data instanceof Uint8Array))
        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
    return data;
}
// For runtime check if class implements interface
let Hash$3 = class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
};
function wrapConstructor$3(hashConstructor) {
    const hashC = (message) => hashConstructor().update(toBytes$5(message)).digest();
    const tmp = hashConstructor();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashConstructor();
    return hashC;
}

// Polyfill for Safari 14
function setBigUint64$3(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
let SHA2$3 = class SHA2 extends Hash$3 {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView$3(this.buffer);
    }
    update(data) {
        assert$2$1.exists(this);
        const { view, buffer, blockLen } = this;
        data = toBytes$5(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = createView$3(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        assert$2$1.exists(this);
        assert$2$1.output(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64$3(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = createView$3(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
};

// Choice: a ? b : c
const Chi$3 = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj$3 = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K$3 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV$3 = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W$3 = new Uint32Array(64);
let SHA256$3 = class SHA256 extends SHA2$3 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV$3[0] | 0;
        this.B = IV$3[1] | 0;
        this.C = IV$3[2] | 0;
        this.D = IV$3[3] | 0;
        this.E = IV$3[4] | 0;
        this.F = IV$3[5] | 0;
        this.G = IV$3[6] | 0;
        this.H = IV$3[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W$3[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W$3[i - 15];
            const W2 = SHA256_W$3[i - 2];
            const s0 = rotr$3(W15, 7) ^ rotr$3(W15, 18) ^ (W15 >>> 3);
            const s1 = rotr$3(W2, 17) ^ rotr$3(W2, 19) ^ (W2 >>> 10);
            SHA256_W$3[i] = (s1 + SHA256_W$3[i - 7] + s0 + SHA256_W$3[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = rotr$3(E, 6) ^ rotr$3(E, 11) ^ rotr$3(E, 25);
            const T1 = (H + sigma1 + Chi$3(E, F, G) + SHA256_K$3[i] + SHA256_W$3[i]) | 0;
            const sigma0 = rotr$3(A, 2) ^ rotr$3(A, 13) ^ rotr$3(A, 22);
            const T2 = (sigma0 + Maj$3(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W$3.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
};
// Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
let SHA224$3 = class SHA224 extends SHA256$3 {
    constructor() {
        super();
        this.A = 0xc1059ed8 | 0;
        this.B = 0x367cd507 | 0;
        this.C = 0x3070dd17 | 0;
        this.D = 0xf70e5939 | 0;
        this.E = 0xffc00b31 | 0;
        this.F = 0x68581511 | 0;
        this.G = 0x64f98fa7 | 0;
        this.H = 0xbefa4fa4 | 0;
        this.outputLen = 28;
    }
};
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
const sha256$4 = wrapConstructor$3(() => new SHA256$3());
// import {sha256 as _sha256} from 'https://bitvm.github.io/sha256/sha256.js'
// const sha256$4 = _sha256;

wrapConstructor$3(() => new SHA224$3());

function within_size$1(data, size) {
    if (data.length > size) {
        throw new TypeError(`Data is larger than array size: ${data.length} > ${size}`);
    }
}
function is_hex$1(hex) {
    if (hex.match(/[^a-fA-f0-9]/) !== null) {
        throw new TypeError('Invalid characters in hex string: ' + hex);
    }
    if (hex.length % 2 !== 0) {
        throw new Error(`Length of hex string is invalid: ${hex.length}`);
    }
}
function is_safe_num$1(num) {
    if (num > Number.MAX_SAFE_INTEGER) {
        throw new TypeError('Number exceeds safe bounds!');
    }
}

const { getRandomValues: getRandomValues$1 } = crypto ?? globalThis.crypto ?? window.crypto;
function random$2(size = 32) {
    if (typeof getRandomValues$1 === 'function') {
        return crypto.getRandomValues(new Uint8Array(size));
    }
    throw new Error('Crypto module missing getRandomValues!');
}
function set_buffer$1(data, size, endian = 'be') {
    if (size === undefined)
        size = data.length;
    within_size$1(data, size);
    const buffer = new Uint8Array(size).fill(0);
    const offset = (endian === 'be') ? 0 : size - data.length;
    buffer.set(data, offset);
    return buffer;
}
function join_array$1(arr) {
    let i, offset = 0;
    const size = arr.reduce((len, arr) => len + arr.length, 0);
    const buff = new Uint8Array(size);
    for (i = 0; i < arr.length; i++) {
        const a = arr[i];
        buff.set(a, offset);
        offset += a.length;
    }
    return buff;
}

const ec$2$1 = new TextEncoder();
const ALPHABETS$1 = [
    {
        name: 'base58',
        charset: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    }
];
function getAlphabet$1(name) {
    for (const alpha of ALPHABETS$1) {
        if (alpha.name === name) {
            return alpha.charset;
        }
    }
    throw TypeError('Charset does not exist: ' + name);
}
function encode$1$2(data, charset, padding = false) {
    if (typeof data === 'string')
        data = ec$2$1.encode(data);
    const alphabet = getAlphabet$1(charset);
    const len = alphabet.length;
    const d = [];
    let s = '', i, j = 0, c, n;
    for (i = 0; i < data.length; i++) {
        j = 0;
        c = data[i];
        s += (c > 0 || (s.length ^ i) > 0) ? '' : '1';
        while (j in d || c > 0) {
            n = d[j];
            n = n > 0 ? n * 256 + c : c;
            c = n / len | 0;
            d[j] = n % len;
            j++;
        }
    }
    while (j-- > 0) {
        s += alphabet[d[j]];
    }
    return (padding && s.length % 4 > 0)
        ? s + '='.repeat(4 - s.length % 4)
        : s;
}
function decode$1$2(encoded, charset) {
    const alphabet = getAlphabet$1(charset);
    const len = alphabet.length, d = [], b = [];
    encoded = encoded.replace('=', '');
    let i, j = 0, c, n;
    for (i = 0; i < encoded.length; i++) {
        j = 0;
        c = alphabet.indexOf(encoded[i]);
        if (c < 0) {
            throw new Error(`Character range out of bounds: ${c}`);
        }
        if (!(c > 0 || (b.length ^ i) > 0))
            b.push(0);
        while (j in d || c > 0) {
            n = d[j];
            n = n > 0 ? n * len + c : c;
            c = n >> 8;
            d[j] = n % 256;
            j++;
        }
    }
    while (j-- > 0) {
        b.push(d[j]);
    }
    return new Uint8Array(b);
}
function hash256$2(data) {
    return sha256$4(sha256$4(data));
}
function addChecksum$1(data) {
    const sum = hash256$2(data);
    return join_array$1([data, sum.slice(0, 4)]);
}
function checkTheSum$1(data) {
    const ret = data.slice(0, -4);
    const chk = data.slice(-4);
    const sum = hash256$2(ret).slice(0, 4);
    if (sum.toString() !== chk.toString()) {
        throw new Error('Invalid checksum!');
    }
    return ret;
}
const BaseX$1 = {
    encode: encode$1$2,
    decode: decode$1$2
};
const Base58C$1 = {
    encode: (data) => {
        const withSum = addChecksum$1(data);
        return BaseX$1.encode(withSum, 'base58');
    },
    decode: (data) => {
        const decoded = BaseX$1.decode(data, 'base58');
        return checkTheSum$1(decoded);
    }
};

const CHARSET$1 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR$1 = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const ENCODINGS$1 = [
    { version: 0, name: 'bech32', const: 1 },
    { version: 1, name: 'bech32m', const: 0x2bc830a3 }
];
function polymod$1(values) {
    let chk = 1;
    for (let p = 0; p < values.length; ++p) {
        const top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ values[p];
        for (let i = 0; i < 5; ++i) {
            if (((top >> i) & 1) !== 0) {
                chk ^= GENERATOR$1[i];
            }
        }
    }
    return chk;
}
function hrpExpand$1(hrp) {
    const ret = [];
    let p;
    for (p = 0; p < hrp.length; ++p) {
        ret.push(hrp.charCodeAt(p) >> 5);
    }
    ret.push(0);
    for (p = 0; p < hrp.length; ++p) {
        ret.push(hrp.charCodeAt(p) & 31);
    }
    return ret;
}
function verifyChecksum$1(hrp, data, enc) {
    const combined = hrpExpand$1(hrp).concat(data);
    return polymod$1(combined) === enc.const;
}
function createChecksum$1(hrp, data, enc) {
    const values = hrpExpand$1(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    const mod = polymod$1(values) ^ enc.const;
    const ret = [];
    for (let p = 0; p < 6; ++p) {
        ret.push((mod >> 5 * (5 - p)) & 31);
    }
    return ret;
}
function convertBits$1(data, fromBits, toBits, pad = true) {
    const ret = [];
    let acc = 0;
    let bits = 0;
    const maxVal = (1 << toBits) - 1;
    const maxAcc = (1 << (fromBits + toBits - 1)) - 1;
    for (const val of data) {
        if (val < 0 || (val >> fromBits) > 0) {
            throw new Error('Failed to perform base conversion. Invalid value: ' + String(val));
        }
        acc = ((acc << fromBits) | val) & maxAcc;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            ret.push((acc >> bits) & maxVal);
        }
    }
    if (pad) {
        if (bits > 0) {
            ret.push((acc << (toBits - bits)) & maxVal);
        }
    }
    else if (bits >= fromBits || ((acc << (toBits - bits)) & maxVal) > 0) {
        throw new Error('Failed to perform base conversion. Invalid Size!');
    }
    return ret;
}
function encode$6(hrp, data, enc) {
    const combined = data.concat(createChecksum$1(hrp, data, enc));
    let ret = hrp + '1';
    for (let p = 0; p < combined.length; ++p) {
        ret += CHARSET$1.charAt(combined[p]);
    }
    return ret;
}
function decode$6(bechstr) {
    if (!checkBounds$1(bechstr)) {
        throw new Error('Encoded string goes out of bounds!');
    }
    bechstr = bechstr.toLowerCase();
    if (!checkSeparatorPos$1(bechstr)) {
        throw new Error('Encoded string has invalid separator!');
    }
    const data = [];
    const pos = bechstr.lastIndexOf('1');
    const hrp = bechstr.substring(0, pos);
    for (let p = pos + 1; p < bechstr.length; ++p) {
        const d = CHARSET$1.indexOf(bechstr.charAt(p));
        if (d === -1) {
            throw new Error('Character idx out of bounds: ' + String(p));
        }
        data.push(d);
    }
    const enc = ENCODINGS$1.find(e => e.version === data[0]) ?? ENCODINGS$1[0];
    if (!verifyChecksum$1(hrp, data, enc)) {
        throw new Error('Checksum verification failed!');
    }
    return [hrp, data.slice(0, data.length - 6)];
}
function checkBounds$1(bechstr) {
    let p;
    let char;
    let hasLower = false;
    let hasUpper = false;
    for (p = 0; p < bechstr.length; ++p) {
        char = bechstr.charCodeAt(p);
        if (char < 33 || char > 126) {
            return false;
        }
        if (char >= 97 && char <= 122) {
            hasLower = true;
        }
        if (char >= 65 && char <= 90) {
            hasUpper = true;
        }
    }
    if (hasLower && hasUpper)
        return false;
    return true;
}
function checkSeparatorPos$1(bechstr) {
    const pos = bechstr.lastIndexOf('1');
    return !(pos < 1 ||
        pos + 7 > bechstr.length ||
        bechstr.length > 90);
}
function b32encode$1(data, hrp = 'bc', version = 0) {
    const dat = [version, ...convertBits$1([...data], 8, 5)];
    const enc = ENCODINGS$1.find(e => e.version === version) ?? ENCODINGS$1[0];
    const str = encode$6(hrp, dat, enc);
    b32decode$1(str);
    return str;
}
function b32decode$1(str) {
    str = str.toLowerCase();
    const hrp = str.split('1', 1)[0];
    const [hrpgot, data] = decode$6(str);
    const decoded = convertBits$1(data.slice(1), 5, 8, false);
    const length = decoded.length;
    switch (true) {
        case (hrp !== hrpgot):
            throw new Error('Returned hrp string is invalid.');
        case (decoded === null || length < 2 || length > 40):
            throw new Error('Decoded string is invalid or out of spec.');
        case (data[0] > 16):
            throw new Error('Returned version bit is out of range.');
        default:
            return Uint8Array.from(decoded);
    }
}
function getVersion$2(str) {
    str = str.toLowerCase();
    const [_, data] = decode$6(str);
    return data[0];
}
const Bech32$1 = {
    encode: b32encode$1,
    decode: b32decode$1,
    version: getVersion$2
};

const BASE64_MAP$1 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64URL_MAP$1 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const ec$1$1 = new TextEncoder();
function b64encode$1(input, urlSafe = false, padding = true) {
    if (typeof input === 'string')
        input = ec$1$1.encode(input);
    const map = urlSafe ? B64URL_MAP$1 : BASE64_MAP$1;
    let output = '';
    let bits = 0;
    let buffer = 0;
    for (let i = 0; i < input.length; i++) {
        buffer = (buffer << 8) | input[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            output += map[(buffer >> bits) & 0x3f];
        }
    }
    if (bits > 0) {
        buffer <<= 6 - bits;
        output += map[buffer & 0x3f];
        while (bits < 6) {
            output += padding ? '=' : '';
            bits += 2;
        }
    }
    return output;
}
function b64decode$1(input, urlSafe = false) {
    const map = (urlSafe || input.includes('-') || input.includes('_'))
        ? B64URL_MAP$1.split('')
        : BASE64_MAP$1.split('');
    input = input.replace(/=+$/, '');
    const chars = input.split('');
    let bits = 0;
    let value = 0;
    const bytes = [];
    for (let i = 0; i < chars.length; i++) {
        const c = chars[i];
        const index = map.indexOf(c);
        if (index === -1) {
            throw new Error('Invalid character: ' + c);
        }
        bits += 6;
        value <<= 6;
        value |= index;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((value >>> bits) & 0xff);
        }
    }
    return new Uint8Array(bytes);
}
const Base64$1 = {
    encode: b64encode$1,
    decode: b64decode$1
};
const B64URL$1 = {
    encode: (data) => b64encode$1(data, true, false),
    decode: (data) => b64decode$1(data, true)
};

const _0n = BigInt(0);
const _255n$1 = BigInt(255);
const _256n$1 = BigInt(256);
function big_size$1(big) {
    if (big <= 0xffn)
        return 1;
    if (big <= 0xffffn)
        return 2;
    if (big <= 0xffffffffn)
        return 4;
    if (big <= 0xffffffffffffffffn)
        return 8;
    if (big <= 0xffffffffffffffffffffffffffffffffn)
        return 16;
    if (big <= 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn) {
        return 32;
    }
    throw new TypeError('Must specify a fixed buffer size for bigints greater than 32 bytes.');
}
function bigToBytes$1(big, size, endian = 'be') {
    if (size === undefined)
        size = big_size$1(big);
    const use_le = (endian === 'le');
    const buffer = new ArrayBuffer(size);
    const dataView = new DataView(buffer);
    let offset = (use_le) ? 0 : size - 1;
    while (big > _0n) {
        const byte = big & _255n$1;
        const num = Number(byte);
        if (use_le) {
            dataView.setUint8(offset++, num);
        }
        else {
            dataView.setUint8(offset--, num);
        }
        big = (big - byte) / _256n$1;
    }
    return new Uint8Array(buffer);
}
function bytesToBig$1(bytes) {
    let num = BigInt(0);
    for (let i = bytes.length - 1; i >= 0; i--) {
        num = (num * _256n$1) + BigInt(bytes[i]);
    }
    return BigInt(num);
}

function binToBytes$1(binary) {
    const bins = binary.split('').map(Number);
    if (bins.length % 8 !== 0) {
        throw new Error(`Binary array is invalid length: ${binary.length}`);
    }
    const bytes = new Uint8Array(bins.length / 8);
    for (let i = 0, ct = 0; i < bins.length; i += 8, ct++) {
        let byte = 0;
        for (let j = 0; j < 8; j++) {
            byte |= (bins[i + j] << (7 - j));
        }
        bytes[ct] = byte;
    }
    return bytes;
}
function bytesToBin$1(bytes) {
    const bin = new Array(bytes.length * 8);
    let count = 0;
    for (const num of bytes) {
        if (num > 255) {
            throw new Error(`Invalid byte value: ${num}. Byte values must be between 0 and 255.`);
        }
        for (let i = 7; i >= 0; i--, count++) {
            bin[count] = (num >> i) & 1;
        }
    }
    return bin.join('');
}

function num_size$1(num) {
    if (num <= 0xFF)
        return 1;
    if (num <= 0xFFFF)
        return 2;
    if (num <= 0xFFFFFFFF)
        return 4;
    throw new TypeError('Numbers larger than 4 bytes must specify a fixed size!');
}
function numToBytes$1(num, size, endian = 'be') {
    if (size === undefined)
        size = num_size$1(num);
    const use_le = (endian === 'le');
    const buffer = new ArrayBuffer(size);
    const dataView = new DataView(buffer);
    let offset = (use_le) ? 0 : size - 1;
    while (num > 0) {
        const byte = num & 255;
        if (use_le) {
            dataView.setUint8(offset++, num);
        }
        else {
            dataView.setUint8(offset--, num);
        }
        num = (num - byte) / 256;
    }
    return new Uint8Array(buffer);
}
function bytesToNum$1(bytes) {
    let num = 0;
    for (let i = bytes.length - 1; i >= 0; i--) {
        num = (num * 256) + bytes[i];
        is_safe_num$1(num);
    }
    return num;
}

const ec$3 = new TextEncoder();
const dc$1 = new TextDecoder();
function strToBytes$1(str) {
    return ec$3.encode(str);
}
function bytesToStr$1(bytes) {
    return dc$1.decode(bytes);
}
function hex_size$1(hexstr, size) {
    is_hex$1(hexstr);
    const len = hexstr.length / 2;
    if (size === undefined)
        size = len;
    if (len > size) {
        throw new TypeError(`Hex string is larger than array size: ${len} > ${size}`);
    }
    return size;
}
function hexToBytes$2(hexstr, size, endian = 'le') {
    size = hex_size$1(hexstr, size);
    const use_le = (endian === 'le');
    const buffer = new ArrayBuffer(size);
    const dataView = new DataView(buffer);
    let offset = (use_le) ? 0 : size - 1;
    for (let i = 0; i < hexstr.length; i += 2) {
        const char = hexstr.substring(i, i + 2);
        const num = parseInt(char, 16);
        if (use_le) {
            dataView.setUint8(offset++, num);
        }
        else {
            dataView.setUint8(offset--, num);
        }
    }
    return new Uint8Array(buffer);
}
function bytesToHex$2(bytes) {
    let chars = '';
    for (let i = 0; i < bytes.length; i++) {
        chars += bytes[i].toString(16).padStart(2, '0');
    }
    return chars;
}
function jsonToBytes$1(obj) {
    const str = JSON.stringify(obj, (_, v) => {
        return typeof v === 'bigint'
            ? `${v}n`
            : v;
    });
    return strToBytes$1(str);
}

function buffer$1(data, size, endian) {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }
    if (data instanceof Uint8Array) {
        return set_buffer$1(data, size, endian);
    }
    if (typeof data === 'string') {
        return hexToBytes$2(data, size, endian);
    }
    if (typeof data === 'bigint') {
        return bigToBytes$1(data, size, endian);
    }
    if (typeof data === 'number') {
        return numToBytes$1(data, size, endian);
    }
    if (typeof data === 'boolean') {
        return Uint8Array.of(data ? 1 : 0);
    }
    throw TypeError('Unsupported format:' + String(typeof data));
}

let Buff$1 = class Buff extends Uint8Array {
    static { this.num = numToBuff$1; }
    static { this.big = bigToBuff$1; }
    static { this.bin = binToBuff$1; }
    static { this.raw = rawToBuff$1; }
    static { this.str = strToBuff$1; }
    static { this.hex = hexToBuff$1; }
    static { this.bytes = bytesToBuff$1; }
    static { this.json = jsonToBuff$1; }
    static { this.base64 = base64ToBuff$1; }
    static { this.b64url = b64urlToBuff$1; }
    static { this.bech32 = bech32ToBuff$1; }
    static { this.b58chk = b58chkToBuff$1; }
    static { this.encode = strToBytes$1; }
    static { this.decode = bytesToStr$1; }
    static random(size = 32) {
        const rand = random$2(size);
        return new Buff(rand, size);
    }
    constructor(data, size, endian) {
        const buffer$1$1 = buffer$1(data, size, endian);
        super(buffer$1$1);
    }
    get arr() {
        return [...this];
    }
    get num() {
        return this.toNum();
    }
    get big() {
        return this.toBig();
    }
    get str() {
        return this.toStr();
    }
    get hex() {
        return this.toHex();
    }
    get raw() {
        return new Uint8Array(this);
    }
    get bin() {
        return this.toBin();
    }
    get b58chk() {
        return this.tob58chk();
    }
    get base64() {
        return this.toBase64();
    }
    get b64url() {
        return this.toB64url();
    }
    get digest() {
        return this.toHash();
    }
    get id() {
        return this.toHash().hex;
    }
    get stream() {
        return new Stream$1(this);
    }
    toNum(endian = 'be') {
        const bytes = (endian === 'be')
            ? this.reverse()
            : this;
        return bytesToNum$1(bytes);
    }
    toBin() {
        return bytesToBin$1(this);
    }
    toBig(endian = 'be') {
        const bytes = (endian === 'be')
            ? this.reverse()
            : this;
        return bytesToBig$1(bytes);
    }
    toHash() {
        const digest = sha256$4(this);
        return new Buff(digest);
    }
    toJson() {
        const str = bytesToStr$1(this);
        return JSON.parse(str);
    }
    toBech32(hrp, version = 0) {
        return Bech32$1.encode(this, hrp, version);
    }
    toStr() { return bytesToStr$1(this); }
    toHex() { return bytesToHex$2(this); }
    toBytes() { return new Uint8Array(this); }
    tob58chk() { return Base58C$1.encode(this); }
    toBase64() { return Base64$1.encode(this); }
    toB64url() { return B64URL$1.encode(this); }
    prepend(data) {
        return Buff.join([Buff.bytes(data), this]);
    }
    append(data) {
        return Buff.join([this, Buff.bytes(data)]);
    }
    slice(start, end) {
        const arr = new Uint8Array(this).slice(start, end);
        return new Buff(arr);
    }
    subarray(begin, end) {
        const arr = new Uint8Array(this).subarray(begin, end);
        return new Buff(arr);
    }
    reverse() {
        const arr = new Uint8Array(this).reverse();
        return new Buff(arr);
    }
    write(bytes, offset) {
        const b = Buff.bytes(bytes);
        this.set(b, offset);
    }
    prefixSize(endian) {
        const size = Buff.varInt(this.length, endian);
        return Buff.join([size, this]);
    }
    static from(data) {
        return new Buff(Uint8Array.from(data));
    }
    static of(...args) {
        return new Buff(Uint8Array.of(...args));
    }
    static join(arr) {
        const bytes = arr.map(e => Buff.bytes(e));
        const joined = join_array$1(bytes);
        return new Buff(joined);
    }
    static varInt(num, endian) {
        if (num < 0xFD) {
            return Buff.num(num, 1);
        }
        else if (num < 0x10000) {
            return Buff.of(0xFD, ...Buff.num(num, 2, endian));
        }
        else if (num < 0x100000000) {
            return Buff.of(0xFE, ...Buff.num(num, 4, endian));
        }
        else if (BigInt(num) < 0x10000000000000000n) {
            return Buff.of(0xFF, ...Buff.num(num, 8, endian));
        }
        else {
            throw new Error(`Value is too large: ${num}`);
        }
    }
};
function numToBuff$1(number, size, endian) {
    return new Buff$1(number, size, endian);
}
function binToBuff$1(data, size, endian) {
    return new Buff$1(binToBytes$1(data), size, endian);
}
function bigToBuff$1(bigint, size, endian) {
    return new Buff$1(bigint, size, endian);
}
function rawToBuff$1(data, size, endian) {
    return new Buff$1(data, size, endian);
}
function strToBuff$1(data, size, endian) {
    return new Buff$1(strToBytes$1(data), size, endian);
}
function hexToBuff$1(data, size, endian) {
    return new Buff$1(data, size, endian);
}
function bytesToBuff$1(data, size, endian) {
    return new Buff$1(data, size, endian);
}
function jsonToBuff$1(data) {
    return new Buff$1(jsonToBytes$1(data));
}
function base64ToBuff$1(data) {
    return new Buff$1(Base64$1.decode(data));
}
function b64urlToBuff$1(data) {
    return new Buff$1(B64URL$1.decode(data));
}
function bech32ToBuff$1(data) {
    return new Buff$1(Bech32$1.decode(data));
}
function b58chkToBuff$1(data) {
    return new Buff$1(Base58C$1.decode(data));
}
let Stream$1 = class Stream {
    constructor(data) {
        this.data = Buff$1.bytes(data);
        this.size = this.data.length;
    }
    peek(size) {
        if (size > this.size) {
            throw new Error(`Size greater than stream: ${size} > ${this.size}`);
        }
        return new Buff$1(this.data.slice(0, size));
    }
    read(size) {
        size = size ?? this.readSize();
        const chunk = this.peek(size);
        this.data = this.data.slice(size);
        this.size = this.data.length;
        return chunk;
    }
    readSize(endian) {
        const num = this.read(1).num;
        switch (true) {
            case (num >= 0 && num < 0xFD):
                return num;
            case (num === 0xFD):
                return this.read(2).toNum(endian);
            case (num === 0xFE):
                return this.read(4).toNum(endian);
            case (num === 0xFF):
                return this.read(8).toNum(endian);
            default:
                throw new Error(`Varint is out of range: ${num}`);
        }
    }
};

function checkSize(input, size) {
    const bytes = Buff$1.bytes(input);
    if (bytes.length !== size) {
        throw new Error(`Invalid input size: ${bytes.hex} !== ${size}`);
    }
}
function safeThrow(errorMsg, shouldThrow) {
    if (shouldThrow) {
        throw new Error(errorMsg);
    }
    else {
        return false;
    }
}
function hashTag(tag, ...data) {
    const htag = Buff$1.str(tag).digest.raw;
    const buff = data.map(e => Buff$1.bytes(e));
    return Buff$1.join([htag, htag, Buff$1.join(buff)]).digest;
}

const OPCODE_MAP = {
    OP_0: 0,
    OP_PUSHDATA1: 76,
    OP_PUSHDATA2: 77,
    OP_PUSHDATA4: 78,
    OP_1NEGATE: 79,
    OP_SUCCESS80: 80,
    OP_1: 81,
    OP_2: 82,
    OP_3: 83,
    OP_4: 84,
    OP_5: 85,
    OP_6: 86,
    OP_7: 87,
    OP_8: 88,
    OP_9: 89,
    OP_10: 90,
    OP_11: 91,
    OP_12: 92,
    OP_13: 93,
    OP_14: 94,
    OP_15: 95,
    OP_16: 96,
    OP_NOP: 97,
    OP_SUCCESS98: 98,
    OP_IF: 99,
    OP_NOTIF: 100,
    OP_ELSE: 103,
    OP_ENDIF: 104,
    OP_VERIFY: 105,
    OP_RETURN: 106,
    OP_TOALTSTACK: 107,
    OP_FROMALTSTACK: 108,
    OP_2DROP: 109,
    OP_2DUP: 110,
    OP_3DUP: 111,
    OP_2OVER: 112,
    OP_2ROT: 113,
    OP_2SWAP: 114,
    OP_IFDUP: 115,
    OP_DEPTH: 116,
    OP_DROP: 117,
    OP_DUP: 118,
    OP_NIP: 119,
    OP_OVER: 120,
    OP_PICK: 121,
    OP_ROLL: 122,
    OP_ROT: 123,
    OP_SWAP: 124,
    OP_TUCK: 125,
    OP_SUCCESS126: 126,
    OP_SUCCESS127: 127,
    OP_SUCCESS128: 128,
    OP_SUCCESS129: 129,
    OP_SIZE: 130,
    OP_SUCCESS131: 131,
    OP_SUCCESS132: 132,
    OP_SUCCESS133: 133,
    OP_SUCCESS134: 134,
    OP_EQUAL: 135,
    OP_EQUALVERIFY: 136,
    OP_SUCCESS137: 137,
    OP_SUCCESS138: 138,
    OP_1ADD: 139,
    OP_1SUB: 140,
    OP_SUCCESS141: 141,
    OP_SUCCESS142: 142,
    OP_NEGATE: 143,
    OP_ABS: 144,
    OP_NOT: 145,
    OP_0NOTEQUAL: 146,
    OP_ADD: 147,
    OP_SUB: 148,
    OP_SUCCESS149: 149,
    OP_SUCCESS150: 150,
    OP_SUCCESS151: 151,
    OP_SUCCESS152: 152,
    OP_SUCCESS153: 153,
    OP_BOOLAND: 154,
    OP_BOOLOR: 155,
    OP_NUMEQUAL: 156,
    OP_NUMEQUALVERIFY: 157,
    OP_NUMNOTEQUAL: 158,
    OP_LESSTHAN: 159,
    OP_GREATERTHAN: 160,
    OP_LESSTHANOREQUAL: 161,
    OP_GREATERTHANOREQUAL: 162,
    OP_MIN: 163,
    OP_MAX: 164,
    OP_WITHIN: 165,
    OP_RIPEMD160: 166,
    OP_SHA1: 167,
    OP_SHA256: 168,
    OP_HASH160: 169,
    OP_HASH256: 170,
    OP_CODESEPARATOR: 171,
    OP_CHECKSIG: 172,
    OP_CHECKSIGVERIFY: 173,
    OP_CHECKMULTISIG: 174,
    OP_CHECKMULTISIGVERIFY: 175,
    OP_NOP1: 176,
    OP_CHECKLOCKTIMEVERIFY: 177,
    OP_CHECKSEQUENCEVERIFY: 178,
    OP_NOP4: 179,
    OP_NOP5: 180,
    OP_NOP6: 181,
    OP_NOP7: 182,
    OP_NOP8: 183,
    OP_NOP9: 184,
    OP_NOP10: 185,
    OP_CHECKSIGADD: 186
};
function getOpLabel(num) {
    if (num > 186 && num < 255) {
        return 'OP_SUCCESS' + String(num);
    }
    for (const [k, v] of Object.entries(OPCODE_MAP)) {
        if (v === num)
            return k;
    }
    throw new Error('OPCODE not found:' + String(num));
}
function getOpCode(string) {
    for (const [k, v] of Object.entries(OPCODE_MAP)) {
        if (k === string)
            return Number(v);
    }
    throw new Error('OPCODE not found:' + string);
}
function getWordType(word) {
    switch (true) {
        case (word === 0):
            return 'opcode';
        case (word >= 1 && word <= 75):
            return 'varint';
        case (word === 76):
            return 'pushdata1';
        case (word === 77):
            return 'pushdata2';
        case (word === 78):
            return 'pushdata4';
        case (word <= 254):
            return 'opcode';
        default:
            throw new Error(`Invalid word range: ${word}`);
    }
}
function isValidWord(word) {
    const MIN_RANGE = 75;
    const MAX_RANGE = 254;
    const DISABLED_OPCODES = [];
    switch (true) {
        case (typeof (word) !== 'number'):
            return false;
        case (word === 0):
            return true;
        case (DISABLED_OPCODES.includes(word)):
            return false;
        case (MIN_RANGE < word && word < MAX_RANGE):
            return true;
        default:
            return false;
    }
}

function isHex(value) {
    return (typeof value === 'string' &&
        value.length % 2 === 0 &&
        /[0-9a-fA-F]/.test(value));
}
function isBytes$1(value) {
    return (isHex(value) || value instanceof Uint8Array);
}

const MAX_WORD_SIZE = 0x208;
function encodeScript(script = [], varint = true) {
    let buff = Buff$1.num(0);
    if (Array.isArray(script)) {
        buff = Buff$1.raw(encodeWords(script));
    }
    if (isHex(script)) {
        buff = Buff$1.hex(script);
    }
    if (script instanceof Uint8Array) {
        buff = Buff$1.raw(script);
    }
    if (varint) {
        buff = buff.prefixSize('le');
    }
    return buff;
}
function encodeWords(wordArray) {
    const words = [];
    for (const word of wordArray) {
        words.push(encodeWord(word));
    }
    return (words.length > 0)
        ? Buff$1.join(words)
        : new Uint8Array();
}
function encodeWord(word) {
    let buff = new Uint8Array();
    if (typeof (word) === 'string') {
        if (word.startsWith('OP_')) {
            return Buff$1.num(getOpCode(word), 1);
        }
        else if (isHex(word)) {
            buff = Buff$1.hex(word);
        }
        else {
            buff = Buff$1.str(word);
        }
    }
    else {
        buff = Buff$1.bytes(word);
        if (buff.length === 1 && buff[0] <= 16) {
            if (buff[0] !== 0)
                buff[0] += 0x50;
            return buff;
        }
    }
    if (buff.length > MAX_WORD_SIZE) {
        const words = splitWord(buff);
        return encodeWords(words);
    }
    return Buff$1.join([encodeSize(buff.length), buff]);
}
function encodeSize(size) {
    const OP_DATAPUSH1 = Buff$1.num(0x4c, 1);
    const OP_DATAPUSH2 = Buff$1.num(0x4d, 1);
    switch (true) {
        case (size <= 0x4b):
            return Buff$1.num(size);
        case (size > 0x4b && size < 0x100):
            return Buff$1.join([OP_DATAPUSH1, Buff$1.num(size, 1, 'le')]);
        case (size >= 0x100 && size <= MAX_WORD_SIZE):
            return Buff$1.join([OP_DATAPUSH2, Buff$1.num(size, 2, 'le')]);
        default:
            throw new Error('Invalid word size:' + size.toString());
    }
}
function splitWord(word) {
    const words = [];
    const buff = new Stream$1(word);
    while (buff.size > MAX_WORD_SIZE) {
        words.push(buff.read(MAX_WORD_SIZE));
    }
    words.push(buff.read(buff.size));
    return words;
}

function decodeScript(script, varint = false) {
    let buff = Buff$1.bytes(script);
    if (varint) {
        const stream = buff.stream;
        const len = stream.readSize('le');
        if (buff.length !== len) {
            throw new Error(`Varint does not match stream size: ${len} !== ${buff.length}`);
        }
        buff = buff.slice(1);
    }
    return decodeWords(buff);
}
function decodeWords(words) {
    const stream = new Stream$1(words);
    const stack = [];
    const stackSize = stream.size;
    let word;
    let wordType;
    let wordSize;
    let count = 0;
    while (count < stackSize) {
        word = stream.read(1).num;
        wordType = getWordType(word);
        count++;
        switch (wordType) {
            case 'varint':
                stack.push(stream.read(word).hex);
                count += word;
                break;
            case 'pushdata1':
                wordSize = stream.read(1).reverse().num;
                stack.push(stream.read(wordSize).hex);
                count += wordSize + 1;
                break;
            case 'pushdata2':
                wordSize = stream.read(2).reverse().num;
                stack.push(stream.read(wordSize).hex);
                count += wordSize + 2;
                break;
            case 'pushdata4':
                wordSize = stream.read(4).reverse().num;
                stack.push(stream.read(wordSize).hex);
                count += wordSize + 4;
                break;
            case 'opcode':
                if (!isValidWord(word)) {
                    throw new Error(`Invalid OPCODE: ${word}`);
                }
                stack.push(getOpLabel(word));
                break;
            default:
                throw new Error(`Word type undefined: ${word}`);
        }
    }
    return stack;
}

function toAsm(script, varint) {
    if (Array.isArray(script)) {
        script = encodeScript(script, varint);
    }
    if (script instanceof Uint8Array ||
        isHex(script)) {
        return decodeScript(script, varint);
    }
    throw new Error('Invalid format: ' + String(typeof script));
}
function toBytes$4(script, varint) {
    if (script instanceof Uint8Array ||
        isHex(script)) {
        script = decodeScript(script, varint);
    }
    if (Array.isArray(script)) {
        return encodeScript(script, varint);
    }
    throw new Error('Invalid format: ' + String(typeof script));
}
function toParam(script) {
    if (!Array.isArray(script)) {
        return Buff$1.bytes(script);
    }
    throw new Error('Invalid format: ' + String(typeof script));
}
const FmtScript = {
    toAsm,
    toBytes: toBytes$4,
    toParam
};

const Script = {
    encode: encodeScript,
    decode: decodeScript,
    fmt: FmtScript
};

function number$2(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`Wrong positive integer: ${n}`);
}
function bool$2(b) {
    if (typeof b !== 'boolean')
        throw new Error(`Expected boolean, not ${b}`);
}
function bytes$2(b, ...lengths) {
    if (!(b instanceof Uint8Array))
        throw new TypeError('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
function hash$3(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number$2(hash.outputLen);
    number$2(hash.blockLen);
}
function exists$2(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
function output$2(out, instance) {
    bytes$2(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
const assert$3 = {
    number: number$2,
    bool: bool$2,
    bytes: bytes$2,
    hash: hash$3,
    exists: exists$2,
    output: output$2,
};
var assert$4 = assert$3;

const crypto$1 = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;

/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// We use `globalThis.crypto`, but node.js versions earlier than v19 don't
// declare it in global scope. For node.js, package.json#exports field mapping
// rewrites import from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated, we can just drop the import.
// Cast array to view
const createView$2 = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
// The rotate right (circular right shift) operation for uint32
const rotr$2 = (word, shift) => (word << (32 - shift)) | (word >>> shift);
// big-endian hardware is rare. Just in case someone still decides to run hashes:
// early-throw an error because we don't support BE yet.
const isLE$2 = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
if (!isLE$2)
    throw new Error('Non little-endian hardware is not supported');
Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function utf8ToBytes$3(str) {
    if (typeof str !== 'string') {
        throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
    }
    return new TextEncoder().encode(str);
}
function toBytes$2(data) {
    if (typeof data === 'string')
        data = utf8ToBytes$3(data);
    if (!(data instanceof Uint8Array))
        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
    return data;
}
/**
 * Concats Uint8Array-s into one; like `Buffer.concat([buf1, buf2])`
 * @example concatBytes(buf1, buf2)
 */
function concatBytes$1(...arrays) {
    if (!arrays.every((a) => a instanceof Uint8Array))
        throw new Error('Uint8Array list expected');
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
// For runtime check if class implements interface
let Hash$2 = class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
};
function wrapConstructor$2(hashConstructor) {
    const hashC = (message) => hashConstructor().update(toBytes$2(message)).digest();
    const tmp = hashConstructor();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashConstructor();
    return hashC;
}
/**
 * Secure PRNG. Uses `globalThis.crypto` or node.js crypto module.
 */
function randomBytes(bytesLength = 32) {
    if (crypto$1 && typeof crypto$1.getRandomValues === 'function') {
        return crypto$1.getRandomValues(new Uint8Array(bytesLength));
    }
    throw new Error('crypto.getRandomValues must be defined');
}

// Polyfill for Safari 14
function setBigUint64$2(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
let SHA2$2 = class SHA2 extends Hash$2 {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView$2(this.buffer);
    }
    update(data) {
        assert$4.exists(this);
        const { view, buffer, blockLen } = this;
        data = toBytes$2(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = createView$2(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        assert$4.exists(this);
        assert$4.output(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64$2(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = createView$2(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
};

// Choice: a ? b : c
const Chi$2 = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj$2 = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K$2 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV$2 = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W$2 = new Uint32Array(64);
let SHA256$2 = class SHA256 extends SHA2$2 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV$2[0] | 0;
        this.B = IV$2[1] | 0;
        this.C = IV$2[2] | 0;
        this.D = IV$2[3] | 0;
        this.E = IV$2[4] | 0;
        this.F = IV$2[5] | 0;
        this.G = IV$2[6] | 0;
        this.H = IV$2[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W$2[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W$2[i - 15];
            const W2 = SHA256_W$2[i - 2];
            const s0 = rotr$2(W15, 7) ^ rotr$2(W15, 18) ^ (W15 >>> 3);
            const s1 = rotr$2(W2, 17) ^ rotr$2(W2, 19) ^ (W2 >>> 10);
            SHA256_W$2[i] = (s1 + SHA256_W$2[i - 7] + s0 + SHA256_W$2[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = rotr$2(E, 6) ^ rotr$2(E, 11) ^ rotr$2(E, 25);
            const T1 = (H + sigma1 + Chi$2(E, F, G) + SHA256_K$2[i] + SHA256_W$2[i]) | 0;
            const sigma0 = rotr$2(A, 2) ^ rotr$2(A, 13) ^ rotr$2(A, 22);
            const T2 = (sigma0 + Maj$2(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W$2.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
};
// Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
let SHA224$2 = class SHA224 extends SHA256$2 {
    constructor() {
        super();
        this.A = 0xc1059ed8 | 0;
        this.B = 0x367cd507 | 0;
        this.C = 0x3070dd17 | 0;
        this.D = 0xf70e5939 | 0;
        this.E = 0xffc00b31 | 0;
        this.F = 0x68581511 | 0;
        this.G = 0x64f98fa7 | 0;
        this.H = 0xbefa4fa4 | 0;
        this.outputLen = 28;
    }
};
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
const sha256$3 = wrapConstructor$2(() => new SHA256$2());
wrapConstructor$2(() => new SHA224$2());

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
const _0n$8 = BigInt(0);
const _1n$5 = BigInt(1);
const _2n$4 = BigInt(2);
const u8a$1 = (a) => a instanceof Uint8Array;
const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function bytesToHex$1(bytes) {
    if (!u8a$1(bytes))
        throw new Error('Uint8Array expected');
    // pre-caching improves the speed 6x
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
}
function numberToHexUnpadded(num) {
    const hex = num.toString(16);
    return hex.length & 1 ? `0${hex}` : hex;
}
function hexToNumber(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    // Big Endian
    return BigInt(hex === '' ? '0' : `0x${hex}`);
}
// Caching slows it down 2-3x
function hexToBytes$1(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    if (hex.length % 2)
        throw new Error('hex string is invalid: unpadded ' + hex.length);
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        const hexByte = hex.slice(j, j + 2);
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0)
            throw new Error('invalid byte sequence');
        array[i] = byte;
    }
    return array;
}
// Big Endian
function bytesToNumberBE(bytes) {
    return hexToNumber(bytesToHex$1(bytes));
}
function bytesToNumberLE(bytes) {
    if (!u8a$1(bytes))
        throw new Error('Uint8Array expected');
    return hexToNumber(bytesToHex$1(Uint8Array.from(bytes).reverse()));
}
const numberToBytesBE = (n, len) => hexToBytes$1(n.toString(16).padStart(len * 2, '0'));
const numberToBytesLE = (n, len) => numberToBytesBE(n, len).reverse();
// Returns variable number bytes (minimal bigint encoding?)
const numberToVarBytesBE = (n) => hexToBytes$1(numberToHexUnpadded(n));
function ensureBytes(title, hex, expectedLength) {
    let res;
    if (typeof hex === 'string') {
        try {
            res = hexToBytes$1(hex);
        }
        catch (e) {
            throw new Error(`${title} must be valid hex string, got "${hex}". Cause: ${e}`);
        }
    }
    else if (u8a$1(hex)) {
        // Uint8Array.from() instead of hash.slice() because node.js Buffer
        // is instance of Uint8Array, and its slice() creates **mutable** copy
        res = Uint8Array.from(hex);
    }
    else {
        throw new Error(`${title} must be hex string or Uint8Array`);
    }
    const len = res.length;
    if (typeof expectedLength === 'number' && len !== expectedLength)
        throw new Error(`${title} expected ${expectedLength} bytes, got ${len}`);
    return res;
}
// Copies several Uint8Arrays into one.
function concatBytes(...arrs) {
    const r = new Uint8Array(arrs.reduce((sum, a) => sum + a.length, 0));
    let pad = 0; // walk through each item, ensure they have proper type
    arrs.forEach((a) => {
        if (!u8a$1(a))
            throw new Error('Uint8Array expected');
        r.set(a, pad);
        pad += a.length;
    });
    return r;
}
function equalBytes(b1, b2) {
    // We don't care about timing attacks here
    if (b1.length !== b2.length)
        return false;
    for (let i = 0; i < b1.length; i++)
        if (b1[i] !== b2[i])
            return false;
    return true;
}
function utf8ToBytes$2(str) {
    if (typeof str !== 'string') {
        throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
    }
    return new TextEncoder().encode(str);
}
// Bit operations
// Amount of bits inside bigint (Same as n.toString(2).length)
function bitLen(n) {
    let len;
    for (len = 0; n > 0n; n >>= _1n$5, len += 1)
        ;
    return len;
}
// Gets single bit at position. NOTE: first bit position is 0 (same as arrays)
// Same as !!+Array.from(n.toString(2)).reverse()[pos]
const bitGet = (n, pos) => (n >> BigInt(pos)) & 1n;
// Sets single bit at position
const bitSet = (n, pos, value) => n | ((value ? _1n$5 : _0n$8) << BigInt(pos));
// Return mask for N bits (Same as BigInt(`0b${Array(i).fill('1').join('')}`))
// Not using ** operator with bigints for old engines.
const bitMask = (n) => (_2n$4 << BigInt(n - 1)) - _1n$5;
// DRBG
const u8n = (data) => new Uint8Array(data); // creates Uint8Array
const u8fr = (arr) => Uint8Array.from(arr); // another shortcut
/**
 * Minimal HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
 * @returns function that will call DRBG until 2nd arg returns something meaningful
 * @example
 *   const drbg = createHmacDRBG<Key>(32, 32, hmac);
 *   drbg(seed, bytesToKey); // bytesToKey must return Key or undefined
 */
function createHmacDrbg(hashLen, qByteLen, hmacFn) {
    if (typeof hashLen !== 'number' || hashLen < 2)
        throw new Error('hashLen must be a number');
    if (typeof qByteLen !== 'number' || qByteLen < 2)
        throw new Error('qByteLen must be a number');
    if (typeof hmacFn !== 'function')
        throw new Error('hmacFn must be a function');
    // Step B, Step C: set hashLen to 8*ceil(hlen/8)
    let v = u8n(hashLen); // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
    let k = u8n(hashLen); // Steps B and C of RFC6979 3.2: set hashLen, in our case always same
    let i = 0; // Iterations counter, will throw when over 1000
    const reset = () => {
        v.fill(1);
        k.fill(0);
        i = 0;
    };
    const h = (...b) => hmacFn(k, v, ...b); // hmac(k)(v, ...values)
    const reseed = (seed = u8n()) => {
        // HMAC-DRBG reseed() function. Steps D-G
        k = h(u8fr([0x00]), seed); // k = hmac(k || v || 0x00 || seed)
        v = h(); // v = hmac(k || v)
        if (seed.length === 0)
            return;
        k = h(u8fr([0x01]), seed); // k = hmac(k || v || 0x01 || seed)
        v = h(); // v = hmac(k || v)
    };
    const gen = () => {
        // HMAC-DRBG generate() function
        if (i++ >= 1000)
            throw new Error('drbg: tried 1000 values');
        let len = 0;
        const out = [];
        while (len < qByteLen) {
            v = h();
            const sl = v.slice();
            out.push(sl);
            len += v.length;
        }
        return concatBytes(...out);
    };
    const genUntil = (seed, pred) => {
        reset();
        reseed(seed); // Steps D-G
        let res = undefined; // Step H: grind until k is in [1..n-1]
        while (!(res = pred(gen())))
            reseed();
        reset();
        return res;
    };
    return genUntil;
}
// Validating curves and fields
const validatorFns = {
    bigint: (val) => typeof val === 'bigint',
    function: (val) => typeof val === 'function',
    boolean: (val) => typeof val === 'boolean',
    string: (val) => typeof val === 'string',
    isSafeInteger: (val) => Number.isSafeInteger(val),
    array: (val) => Array.isArray(val),
    field: (val, object) => object.Fp.isValid(val),
    hash: (val) => typeof val === 'function' && Number.isSafeInteger(val.outputLen),
};
// type Record<K extends string | number | symbol, T> = { [P in K]: T; }
function validateObject(object, validators, optValidators = {}) {
    const checkField = (fieldName, type, isOptional) => {
        const checkVal = validatorFns[type];
        if (typeof checkVal !== 'function')
            throw new Error(`Invalid validator "${type}", expected function`);
        const val = object[fieldName];
        if (isOptional && val === undefined)
            return;
        if (!checkVal(val, object)) {
            throw new Error(`Invalid param ${String(fieldName)}=${val} (${typeof val}), expected ${type}`);
        }
    };
    for (const [fieldName, type] of Object.entries(validators))
        checkField(fieldName, type, false);
    for (const [fieldName, type] of Object.entries(optValidators))
        checkField(fieldName, type, true);
    return object;
}
// validate type tests
// const o: { a: number; b: number; c: number } = { a: 1, b: 5, c: 6 };
// const z0 = validateObject(o, { a: 'isSafeInteger' }, { c: 'bigint' }); // Ok!
// // Should fail type-check
// const z1 = validateObject(o, { a: 'tmp' }, { c: 'zz' });
// const z2 = validateObject(o, { a: 'isSafeInteger' }, { c: 'zz' });
// const z3 = validateObject(o, { test: 'boolean', z: 'bug' });
// const z4 = validateObject(o, { a: 'boolean', z: 'bug' });

var ut = /*#__PURE__*/Object.freeze({
    __proto__: null,
    bitGet: bitGet,
    bitLen: bitLen,
    bitMask: bitMask,
    bitSet: bitSet,
    bytesToHex: bytesToHex$1,
    bytesToNumberBE: bytesToNumberBE,
    bytesToNumberLE: bytesToNumberLE,
    concatBytes: concatBytes,
    createHmacDrbg: createHmacDrbg,
    ensureBytes: ensureBytes,
    equalBytes: equalBytes,
    hexToBytes: hexToBytes$1,
    hexToNumber: hexToNumber,
    numberToBytesBE: numberToBytesBE,
    numberToBytesLE: numberToBytesLE,
    numberToHexUnpadded: numberToHexUnpadded,
    numberToVarBytesBE: numberToVarBytesBE,
    utf8ToBytes: utf8ToBytes$2,
    validateObject: validateObject
});

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Utilities for modular arithmetics and finite fields
// prettier-ignore
const _0n$7 = BigInt(0), _1n$4 = BigInt(1), _2n$3 = BigInt(2), _3n$2 = BigInt(3);
// prettier-ignore
const _4n$2 = BigInt(4), _5n = BigInt(5), _8n = BigInt(8);
// prettier-ignore
BigInt(9); BigInt(16);
// Calculates a modulo b
function mod(a, b) {
    const result = a % b;
    return result >= _0n$7 ? result : b + result;
}
/**
 * Efficiently exponentiate num to power and do modular division.
 * Unsafe in some contexts: uses ladder, so can expose bigint bits.
 * @example
 * powMod(2n, 6n, 11n) // 64n % 11n == 9n
 */
// TODO: use field version && remove
function pow(num, power, modulo) {
    if (modulo <= _0n$7 || power < _0n$7)
        throw new Error('Expected power/modulo > 0');
    if (modulo === _1n$4)
        return _0n$7;
    let res = _1n$4;
    while (power > _0n$7) {
        if (power & _1n$4)
            res = (res * num) % modulo;
        num = (num * num) % modulo;
        power >>= _1n$4;
    }
    return res;
}
// Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
function pow2(x, power, modulo) {
    let res = x;
    while (power-- > _0n$7) {
        res *= res;
        res %= modulo;
    }
    return res;
}
// Inverses number over modulo
function invert(number, modulo) {
    if (number === _0n$7 || modulo <= _0n$7) {
        throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
    }
    // Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
    // Fermat's little theorem "CT-like" version inv(n) = n^(m-2) mod m is 30x slower.
    let a = mod(number, modulo);
    let b = modulo;
    // prettier-ignore
    let x = _0n$7, u = _1n$4;
    while (a !== _0n$7) {
        // JIT applies optimization if those two lines follow each other
        const q = b / a;
        const r = b % a;
        const m = x - u * q;
        // prettier-ignore
        b = a, a = r, x = u, u = m;
    }
    const gcd = b;
    if (gcd !== _1n$4)
        throw new Error('invert: does not exist');
    return mod(x, modulo);
}
// Tonelli-Shanks algorithm
// Paper 1: https://eprint.iacr.org/2012/685.pdf (page 12)
// Paper 2: Square Roots from 1; 24, 51, 10 to Dan Shanks
function tonelliShanks(P) {
    // Legendre constant: used to calculate Legendre symbol (a | p),
    // which denotes the value of a^((p-1)/2) (mod p).
    // (a | p) ≡ 1    if a is a square (mod p)
    // (a | p) ≡ -1   if a is not a square (mod p)
    // (a | p) ≡ 0    if a ≡ 0 (mod p)
    const legendreC = (P - _1n$4) / _2n$3;
    let Q, S, Z;
    // Step 1: By factoring out powers of 2 from p - 1,
    // find q and s such that p - 1 = q*(2^s) with q odd
    for (Q = P - _1n$4, S = 0; Q % _2n$3 === _0n$7; Q /= _2n$3, S++)
        ;
    // Step 2: Select a non-square z such that (z | p) ≡ -1 and set c ≡ zq
    for (Z = _2n$3; Z < P && pow(Z, legendreC, P) !== P - _1n$4; Z++)
        ;
    // Fast-path
    if (S === 1) {
        const p1div4 = (P + _1n$4) / _4n$2;
        return function tonelliFast(Fp, n) {
            const root = Fp.pow(n, p1div4);
            if (!Fp.eql(Fp.sqr(root), n))
                throw new Error('Cannot find square root');
            return root;
        };
    }
    // Slow-path
    const Q1div2 = (Q + _1n$4) / _2n$3;
    return function tonelliSlow(Fp, n) {
        // Step 0: Check that n is indeed a square: (n | p) should not be ≡ -1
        if (Fp.pow(n, legendreC) === Fp.neg(Fp.ONE))
            throw new Error('Cannot find square root');
        let r = S;
        // TODO: will fail at Fp2/etc
        let g = Fp.pow(Fp.mul(Fp.ONE, Z), Q); // will update both x and b
        let x = Fp.pow(n, Q1div2); // first guess at the square root
        let b = Fp.pow(n, Q); // first guess at the fudge factor
        while (!Fp.eql(b, Fp.ONE)) {
            if (Fp.eql(b, Fp.ZERO))
                return Fp.ZERO; // https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm (4. If t = 0, return r = 0)
            // Find m such b^(2^m)==1
            let m = 1;
            for (let t2 = Fp.sqr(b); m < r; m++) {
                if (Fp.eql(t2, Fp.ONE))
                    break;
                t2 = Fp.sqr(t2); // t2 *= t2
            }
            // NOTE: r-m-1 can be bigger than 32, need to convert to bigint before shift, otherwise there will be overflow
            const ge = Fp.pow(g, _1n$4 << BigInt(r - m - 1)); // ge = 2^(r-m-1)
            g = Fp.sqr(ge); // g = ge * ge
            x = Fp.mul(x, ge); // x *= ge
            b = Fp.mul(b, g); // b *= g
            r = m;
        }
        return x;
    };
}
function FpSqrt(P) {
    // NOTE: different algorithms can give different roots, it is up to user to decide which one they want.
    // For example there is FpSqrtOdd/FpSqrtEven to choice root based on oddness (used for hash-to-curve).
    // P ≡ 3 (mod 4)
    // √n = n^((P+1)/4)
    if (P % _4n$2 === _3n$2) {
        // Not all roots possible!
        // const ORDER =
        //   0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
        // const NUM = 72057594037927816n;
        const p1div4 = (P + _1n$4) / _4n$2;
        return function sqrt3mod4(Fp, n) {
            const root = Fp.pow(n, p1div4);
            // Throw if root**2 != n
            if (!Fp.eql(Fp.sqr(root), n))
                throw new Error('Cannot find square root');
            return root;
        };
    }
    // Atkin algorithm for q ≡ 5 (mod 8), https://eprint.iacr.org/2012/685.pdf (page 10)
    if (P % _8n === _5n) {
        const c1 = (P - _5n) / _8n;
        return function sqrt5mod8(Fp, n) {
            const n2 = Fp.mul(n, _2n$3);
            const v = Fp.pow(n2, c1);
            const nv = Fp.mul(n, v);
            const i = Fp.mul(Fp.mul(nv, _2n$3), v);
            const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
            if (!Fp.eql(Fp.sqr(root), n))
                throw new Error('Cannot find square root');
            return root;
        };
    }
    // Other cases: Tonelli-Shanks algorithm
    return tonelliShanks(P);
}
// prettier-ignore
const FIELD_FIELDS = [
    'create', 'isValid', 'is0', 'neg', 'inv', 'sqrt', 'sqr',
    'eql', 'add', 'sub', 'mul', 'pow', 'div',
    'addN', 'subN', 'mulN', 'sqrN'
];
function validateField(field) {
    const initial = {
        ORDER: 'bigint',
        MASK: 'bigint',
        BYTES: 'isSafeInteger',
        BITS: 'isSafeInteger',
    };
    const opts = FIELD_FIELDS.reduce((map, val) => {
        map[val] = 'function';
        return map;
    }, initial);
    return validateObject(field, opts);
}
// Generic field functions
function FpPow(f, num, power) {
    // Should have same speed as pow for bigints
    // TODO: benchmark!
    if (power < _0n$7)
        throw new Error('Expected power > 0');
    if (power === _0n$7)
        return f.ONE;
    if (power === _1n$4)
        return num;
    let p = f.ONE;
    let d = num;
    while (power > _0n$7) {
        if (power & _1n$4)
            p = f.mul(p, d);
        d = f.sqr(d);
        power >>= _1n$4;
    }
    return p;
}
// 0 is non-invertible: non-batched version will throw on 0
function FpInvertBatch(f, nums) {
    const tmp = new Array(nums.length);
    // Walk from first to last, multiply them by each other MOD p
    const lastMultiplied = nums.reduce((acc, num, i) => {
        if (f.is0(num))
            return acc;
        tmp[i] = acc;
        return f.mul(acc, num);
    }, f.ONE);
    // Invert last element
    const inverted = f.inv(lastMultiplied);
    // Walk from last to first, multiply them by inverted each other MOD p
    nums.reduceRight((acc, num, i) => {
        if (f.is0(num))
            return acc;
        tmp[i] = f.mul(acc, tmp[i]);
        return f.mul(acc, num);
    }, inverted);
    return tmp;
}
// CURVE.n lengths
function nLength(n, nBitLength) {
    // Bit size, byte size of CURVE.n
    const _nBitLength = nBitLength !== undefined ? nBitLength : n.toString(2).length;
    const nByteLength = Math.ceil(_nBitLength / 8);
    return { nBitLength: _nBitLength, nByteLength };
}
/**
 * Initializes a galois field over prime. Non-primes are not supported for now.
 * Do not init in loop: slow. Very fragile: always run a benchmark on change.
 * Major performance gains:
 * a) non-normalized operations like mulN instead of mul
 * b) `Object.freeze`
 * c) Same object shape: never add or remove keys
 * @param ORDER prime positive bigint
 * @param bitLen how many bits the field consumes
 * @param isLE (def: false) if encoding / decoding should be in little-endian
 * @param redef optional faster redefinitions of sqrt and other methods
 */
function Field$1(ORDER, bitLen, isLE = false, redef = {}) {
    if (ORDER <= _0n$7)
        throw new Error(`Expected Fp ORDER > 0, got ${ORDER}`);
    const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen);
    if (BYTES > 2048)
        throw new Error('Field lengths over 2048 bytes are not supported');
    const sqrtP = FpSqrt(ORDER);
    const f = Object.freeze({
        ORDER,
        BITS,
        BYTES,
        MASK: bitMask(BITS),
        ZERO: _0n$7,
        ONE: _1n$4,
        create: (num) => mod(num, ORDER),
        isValid: (num) => {
            if (typeof num !== 'bigint')
                throw new Error(`Invalid field element: expected bigint, got ${typeof num}`);
            return _0n$7 <= num && num < ORDER; // 0 is valid element, but it's not invertible
        },
        is0: (num) => num === _0n$7,
        isOdd: (num) => (num & _1n$4) === _1n$4,
        neg: (num) => mod(-num, ORDER),
        eql: (lhs, rhs) => lhs === rhs,
        sqr: (num) => mod(num * num, ORDER),
        add: (lhs, rhs) => mod(lhs + rhs, ORDER),
        sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
        mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
        pow: (num, power) => FpPow(f, num, power),
        div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
        // Same as above, but doesn't normalize
        sqrN: (num) => num * num,
        addN: (lhs, rhs) => lhs + rhs,
        subN: (lhs, rhs) => lhs - rhs,
        mulN: (lhs, rhs) => lhs * rhs,
        inv: (num) => invert(num, ORDER),
        sqrt: redef.sqrt || ((n) => sqrtP(f, n)),
        invertBatch: (lst) => FpInvertBatch(f, lst),
        // TODO: do we really need constant cmov?
        // We don't have const-time bigints anyway, so probably will be not very useful
        cmov: (a, b, c) => (c ? b : a),
        toBytes: (num) => (isLE ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES)),
        fromBytes: (bytes) => {
            if (bytes.length !== BYTES)
                throw new Error(`Fp.fromBytes: expected ${BYTES}, got ${bytes.length}`);
            return isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
        },
    });
    return Object.freeze(f);
}
/**
 * FIPS 186 B.4.1-compliant "constant-time" private key generation utility.
 * Can take (n+8) or more bytes of uniform input e.g. from CSPRNG or KDF
 * and convert them into private scalar, with the modulo bias being neglible.
 * Needs at least 40 bytes of input for 32-byte private key.
 * https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/
 * @param hash hash output from SHA3 or a similar function
 * @returns valid private scalar
 */
function hashToPrivateScalar(hash, groupOrder, isLE = false) {
    hash = ensureBytes('privateHash', hash);
    const hashLen = hash.length;
    const minLen = nLength(groupOrder).nByteLength + 8;
    if (minLen < 24 || hashLen < minLen || hashLen > 1024)
        throw new Error(`hashToPrivateScalar: expected ${minLen}-1024 bytes of input, got ${hashLen}`);
    const num = isLE ? bytesToNumberLE(hash) : bytesToNumberBE(hash);
    return mod(num, groupOrder - _1n$4) + _1n$4;
}

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Abelian group utilities
const _0n$6 = BigInt(0);
const _1n$3 = BigInt(1);
// Elliptic curve multiplication of Point by scalar. Fragile.
// Scalars should always be less than curve order: this should be checked inside of a curve itself.
// Creates precomputation tables for fast multiplication:
// - private scalar is split by fixed size windows of W bits
// - every window point is collected from window's table & added to accumulator
// - since windows are different, same point inside tables won't be accessed more than once per calc
// - each multiplication is 'Math.ceil(CURVE_ORDER / 𝑊) + 1' point additions (fixed for any scalar)
// - +1 window is neccessary for wNAF
// - wNAF reduces table size: 2x less memory + 2x faster generation, but 10% slower multiplication
// TODO: Research returning 2d JS array of windows, instead of a single window. This would allow
// windows to be in different memory locations
function wNAF(c, bits) {
    const constTimeNegate = (condition, item) => {
        const neg = item.negate();
        return condition ? neg : item;
    };
    const opts = (W) => {
        const windows = Math.ceil(bits / W) + 1; // +1, because
        const windowSize = 2 ** (W - 1); // -1 because we skip zero
        return { windows, windowSize };
    };
    return {
        constTimeNegate,
        // non-const time multiplication ladder
        unsafeLadder(elm, n) {
            let p = c.ZERO;
            let d = elm;
            while (n > _0n$6) {
                if (n & _1n$3)
                    p = p.add(d);
                d = d.double();
                n >>= _1n$3;
            }
            return p;
        },
        /**
         * Creates a wNAF precomputation window. Used for caching.
         * Default window size is set by `utils.precompute()` and is equal to 8.
         * Number of precomputed points depends on the curve size:
         * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
         * - 𝑊 is the window size
         * - 𝑛 is the bitlength of the curve order.
         * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
         * @returns precomputed point tables flattened to a single array
         */
        precomputeWindow(elm, W) {
            const { windows, windowSize } = opts(W);
            const points = [];
            let p = elm;
            let base = p;
            for (let window = 0; window < windows; window++) {
                base = p;
                points.push(base);
                // =1, because we skip zero
                for (let i = 1; i < windowSize; i++) {
                    base = base.add(p);
                    points.push(base);
                }
                p = base.double();
            }
            return points;
        },
        /**
         * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
         * @param W window size
         * @param precomputes precomputed tables
         * @param n scalar (we don't check here, but should be less than curve order)
         * @returns real and fake (for const-time) points
         */
        wNAF(W, precomputes, n) {
            // TODO: maybe check that scalar is less than group order? wNAF behavious is undefined otherwise
            // But need to carefully remove other checks before wNAF. ORDER == bits here
            const { windows, windowSize } = opts(W);
            let p = c.ZERO;
            let f = c.BASE;
            const mask = BigInt(2 ** W - 1); // Create mask with W ones: 0b1111 for W=4 etc.
            const maxNumber = 2 ** W;
            const shiftBy = BigInt(W);
            for (let window = 0; window < windows; window++) {
                const offset = window * windowSize;
                // Extract W bits.
                let wbits = Number(n & mask);
                // Shift number by W bits.
                n >>= shiftBy;
                // If the bits are bigger than max size, we'll split those.
                // +224 => 256 - 32
                if (wbits > windowSize) {
                    wbits -= maxNumber;
                    n += _1n$3;
                }
                // This code was first written with assumption that 'f' and 'p' will never be infinity point:
                // since each addition is multiplied by 2 ** W, it cannot cancel each other. However,
                // there is negate now: it is possible that negated element from low value
                // would be the same as high element, which will create carry into next window.
                // It's not obvious how this can fail, but still worth investigating later.
                // Check if we're onto Zero point.
                // Add random point inside current window to f.
                const offset1 = offset;
                const offset2 = offset + Math.abs(wbits) - 1; // -1 because we skip zero
                const cond1 = window % 2 !== 0;
                const cond2 = wbits < 0;
                if (wbits === 0) {
                    // The most important part for const-time getPublicKey
                    f = f.add(constTimeNegate(cond1, precomputes[offset1]));
                }
                else {
                    p = p.add(constTimeNegate(cond2, precomputes[offset2]));
                }
            }
            // JIT-compiler should not eliminate f here, since it will later be used in normalizeZ()
            // Even if the variable is still unused, there are some checks which will
            // throw an exception, so compiler needs to prove they won't happen, which is hard.
            // At this point there is a way to F be infinity-point even if p is not,
            // which makes it less const-time: around 1 bigint multiply.
            return { p, f };
        },
        wNAFCached(P, precomputesMap, n, transform) {
            // @ts-ignore
            const W = P._WINDOW_SIZE || 1;
            // Calculate precomputes on a first run, reuse them after
            let comp = precomputesMap.get(P);
            if (!comp) {
                comp = this.precomputeWindow(P, W);
                if (W !== 1) {
                    precomputesMap.set(P, transform(comp));
                }
            }
            return this.wNAF(W, comp, n);
        },
    };
}
function validateBasic(curve) {
    validateField(curve.Fp);
    validateObject(curve, {
        n: 'bigint',
        h: 'bigint',
        Gx: 'field',
        Gy: 'field',
    }, {
        nBitLength: 'isSafeInteger',
        nByteLength: 'isSafeInteger',
    });
    // Set defaults
    return Object.freeze({
        ...nLength(curve.n, curve.nBitLength),
        ...curve,
        ...{ p: curve.Fp.ORDER },
    });
}

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Short Weierstrass curve. The formula is: y² = x³ + ax + b
function validatePointOpts(curve) {
    const opts = validateBasic(curve);
    validateObject(opts, {
        a: 'field',
        b: 'field',
    }, {
        allowedPrivateKeyLengths: 'array',
        wrapPrivateKey: 'boolean',
        isTorsionFree: 'function',
        clearCofactor: 'function',
        allowInfinityPoint: 'boolean',
        fromBytes: 'function',
        toBytes: 'function',
    });
    const { endo, Fp, a } = opts;
    if (endo) {
        if (!Fp.eql(a, Fp.ZERO)) {
            throw new Error('Endomorphism can only be defined for Koblitz curves that have a=0');
        }
        if (typeof endo !== 'object' ||
            typeof endo.beta !== 'bigint' ||
            typeof endo.splitScalar !== 'function') {
            throw new Error('Expected endomorphism with beta: bigint and splitScalar: function');
        }
    }
    return Object.freeze({ ...opts });
}
// ASN.1 DER encoding utilities
const { bytesToNumberBE: b2n, hexToBytes: h2b } = ut;
const DER = {
    // asn.1 DER encoding utils
    Err: class DERErr extends Error {
        constructor(m = '') {
            super(m);
        }
    },
    _parseInt(data) {
        const { Err: E } = DER;
        if (data.length < 2 || data[0] !== 0x02)
            throw new E('Invalid signature integer tag');
        const len = data[1];
        const res = data.subarray(2, len + 2);
        if (!len || res.length !== len)
            throw new E('Invalid signature integer: wrong length');
        if (res[0] === 0x00 && res[1] <= 0x7f)
            throw new E('Invalid signature integer: trailing length');
        // ^ Weird condition: not about length, but about first bytes of number.
        return { d: b2n(res), l: data.subarray(len + 2) }; // d is data, l is left
    },
    toSig(hex) {
        // parse DER signature
        const { Err: E } = DER;
        const data = typeof hex === 'string' ? h2b(hex) : hex;
        if (!(data instanceof Uint8Array))
            throw new Error('ui8a expected');
        let l = data.length;
        if (l < 2 || data[0] != 0x30)
            throw new E('Invalid signature tag');
        if (data[1] !== l - 2)
            throw new E('Invalid signature: incorrect length');
        const { d: r, l: sBytes } = DER._parseInt(data.subarray(2));
        const { d: s, l: rBytesLeft } = DER._parseInt(sBytes);
        if (rBytesLeft.length)
            throw new E('Invalid signature: left bytes after parsing');
        return { r, s };
    },
    hexFromSig(sig) {
        const slice = (s) => (Number.parseInt(s[0], 16) >= 8 ? '00' + s : s); // slice DER
        const h = (num) => {
            const hex = num.toString(16);
            return hex.length & 1 ? `0${hex}` : hex;
        };
        const s = slice(h(sig.s));
        const r = slice(h(sig.r));
        const shl = s.length / 2;
        const rhl = r.length / 2;
        const sl = h(shl);
        const rl = h(rhl);
        return `30${h(rhl + shl + 4)}02${rl}${r}02${sl}${s}`;
    },
};
// Be friendly to bad ECMAScript parsers by not using bigint literals
// prettier-ignore
const _0n$5 = BigInt(0), _1n$2 = BigInt(1), _2n$2 = BigInt(2), _3n$1 = BigInt(3), _4n$1 = BigInt(4);
function weierstrassPoints(opts) {
    const CURVE = validatePointOpts(opts);
    const { Fp } = CURVE; // All curves has same field / group length as for now, but they can differ
    const toBytes = CURVE.toBytes ||
        ((c, point, isCompressed) => {
            const a = point.toAffine();
            return concatBytes(Uint8Array.from([0x04]), Fp.toBytes(a.x), Fp.toBytes(a.y));
        });
    const fromBytes = CURVE.fromBytes ||
        ((bytes) => {
            // const head = bytes[0];
            const tail = bytes.subarray(1);
            // if (head !== 0x04) throw new Error('Only non-compressed encoding is supported');
            const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
            const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
            return { x, y };
        });
    /**
     * y² = x³ + ax + b: Short weierstrass curve formula
     * @returns y²
     */
    function weierstrassEquation(x) {
        const { a, b } = CURVE;
        const x2 = Fp.sqr(x); // x * x
        const x3 = Fp.mul(x2, x); // x2 * x
        return Fp.add(Fp.add(x3, Fp.mul(x, a)), b); // x3 + a * x + b
    }
    // Valid group elements reside in range 1..n-1
    function isWithinCurveOrder(num) {
        return typeof num === 'bigint' && _0n$5 < num && num < CURVE.n;
    }
    function assertGE(num) {
        if (!isWithinCurveOrder(num))
            throw new Error('Expected valid bigint: 0 < bigint < curve.n');
    }
    // Validates if priv key is valid and converts it to bigint.
    // Supports options allowedPrivateKeyLengths and wrapPrivateKey.
    function normPrivateKeyToScalar(key) {
        const { allowedPrivateKeyLengths: lengths, nByteLength, wrapPrivateKey, n } = CURVE;
        if (lengths && typeof key !== 'bigint') {
            if (key instanceof Uint8Array)
                key = bytesToHex$1(key);
            // Normalize to hex string, pad. E.g. P521 would norm 130-132 char hex to 132-char bytes
            if (typeof key !== 'string' || !lengths.includes(key.length))
                throw new Error('Invalid key');
            key = key.padStart(nByteLength * 2, '0');
        }
        let num;
        try {
            num =
                typeof key === 'bigint'
                    ? key
                    : bytesToNumberBE(ensureBytes('private key', key, nByteLength));
        }
        catch (error) {
            throw new Error(`private key must be ${nByteLength} bytes, hex or bigint, not ${typeof key}`);
        }
        if (wrapPrivateKey)
            num = mod(num, n); // disabled by default, enabled for BLS
        assertGE(num); // num in range [1..N-1]
        return num;
    }
    const pointPrecomputes = new Map();
    function assertPrjPoint(other) {
        if (!(other instanceof Point))
            throw new Error('ProjectivePoint expected');
    }
    /**
     * Projective Point works in 3d / projective (homogeneous) coordinates: (x, y, z) ∋ (x=x/z, y=y/z)
     * Default Point works in 2d / affine coordinates: (x, y)
     * We're doing calculations in projective, because its operations don't require costly inversion.
     */
    class Point {
        constructor(px, py, pz) {
            this.px = px;
            this.py = py;
            this.pz = pz;
            if (px == null || !Fp.isValid(px))
                throw new Error('x required');
            if (py == null || !Fp.isValid(py))
                throw new Error('y required');
            if (pz == null || !Fp.isValid(pz))
                throw new Error('z required');
        }
        // Does not validate if the point is on-curve.
        // Use fromHex instead, or call assertValidity() later.
        static fromAffine(p) {
            const { x, y } = p || {};
            if (!p || !Fp.isValid(x) || !Fp.isValid(y))
                throw new Error('invalid affine point');
            if (p instanceof Point)
                throw new Error('projective point not allowed');
            const is0 = (i) => Fp.eql(i, Fp.ZERO);
            // fromAffine(x:0, y:0) would produce (x:0, y:0, z:1), but we need (x:0, y:1, z:0)
            if (is0(x) && is0(y))
                return Point.ZERO;
            return new Point(x, y, Fp.ONE);
        }
        get x() {
            return this.toAffine().x;
        }
        get y() {
            return this.toAffine().y;
        }
        /**
         * Takes a bunch of Projective Points but executes only one
         * inversion on all of them. Inversion is very slow operation,
         * so this improves performance massively.
         * Optimization: converts a list of projective points to a list of identical points with Z=1.
         */
        static normalizeZ(points) {
            const toInv = Fp.invertBatch(points.map((p) => p.pz));
            return points.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
        }
        /**
         * Converts hash string or Uint8Array to Point.
         * @param hex short/long ECDSA hex
         */
        static fromHex(hex) {
            const P = Point.fromAffine(fromBytes(ensureBytes('pointHex', hex)));
            P.assertValidity();
            return P;
        }
        // Multiplies generator point by privateKey.
        static fromPrivateKey(privateKey) {
            return Point.BASE.multiply(normPrivateKeyToScalar(privateKey));
        }
        // "Private method", don't use it directly
        _setWindowSize(windowSize) {
            this._WINDOW_SIZE = windowSize;
            pointPrecomputes.delete(this);
        }
        // A point on curve is valid if it conforms to equation.
        assertValidity() {
            // Zero is valid point too!
            if (this.is0()) {
                if (CURVE.allowInfinityPoint)
                    return;
                throw new Error('bad point: ZERO');
            }
            // Some 3rd-party test vectors require different wording between here & `fromCompressedHex`
            const { x, y } = this.toAffine();
            // Check if x, y are valid field elements
            if (!Fp.isValid(x) || !Fp.isValid(y))
                throw new Error('bad point: x or y not FE');
            const left = Fp.sqr(y); // y²
            const right = weierstrassEquation(x); // x³ + ax + b
            if (!Fp.eql(left, right))
                throw new Error('bad point: equation left != right');
            if (!this.isTorsionFree())
                throw new Error('bad point: not in prime-order subgroup');
        }
        hasEvenY() {
            const { y } = this.toAffine();
            if (Fp.isOdd)
                return !Fp.isOdd(y);
            throw new Error("Field doesn't support isOdd");
        }
        /**
         * Compare one point to another.
         */
        equals(other) {
            assertPrjPoint(other);
            const { px: X1, py: Y1, pz: Z1 } = this;
            const { px: X2, py: Y2, pz: Z2 } = other;
            const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
            const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
            return U1 && U2;
        }
        /**
         * Flips point to one corresponding to (x, -y) in Affine coordinates.
         */
        negate() {
            return new Point(this.px, Fp.neg(this.py), this.pz);
        }
        // Renes-Costello-Batina exception-free doubling formula.
        // There is 30% faster Jacobian formula, but it is not complete.
        // https://eprint.iacr.org/2015/1060, algorithm 3
        // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
        double() {
            const { a, b } = CURVE;
            const b3 = Fp.mul(b, _3n$1);
            const { px: X1, py: Y1, pz: Z1 } = this;
            let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
            let t0 = Fp.mul(X1, X1); // step 1
            let t1 = Fp.mul(Y1, Y1);
            let t2 = Fp.mul(Z1, Z1);
            let t3 = Fp.mul(X1, Y1);
            t3 = Fp.add(t3, t3); // step 5
            Z3 = Fp.mul(X1, Z1);
            Z3 = Fp.add(Z3, Z3);
            X3 = Fp.mul(a, Z3);
            Y3 = Fp.mul(b3, t2);
            Y3 = Fp.add(X3, Y3); // step 10
            X3 = Fp.sub(t1, Y3);
            Y3 = Fp.add(t1, Y3);
            Y3 = Fp.mul(X3, Y3);
            X3 = Fp.mul(t3, X3);
            Z3 = Fp.mul(b3, Z3); // step 15
            t2 = Fp.mul(a, t2);
            t3 = Fp.sub(t0, t2);
            t3 = Fp.mul(a, t3);
            t3 = Fp.add(t3, Z3);
            Z3 = Fp.add(t0, t0); // step 20
            t0 = Fp.add(Z3, t0);
            t0 = Fp.add(t0, t2);
            t0 = Fp.mul(t0, t3);
            Y3 = Fp.add(Y3, t0);
            t2 = Fp.mul(Y1, Z1); // step 25
            t2 = Fp.add(t2, t2);
            t0 = Fp.mul(t2, t3);
            X3 = Fp.sub(X3, t0);
            Z3 = Fp.mul(t2, t1);
            Z3 = Fp.add(Z3, Z3); // step 30
            Z3 = Fp.add(Z3, Z3);
            return new Point(X3, Y3, Z3);
        }
        // Renes-Costello-Batina exception-free addition formula.
        // There is 30% faster Jacobian formula, but it is not complete.
        // https://eprint.iacr.org/2015/1060, algorithm 1
        // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
        add(other) {
            assertPrjPoint(other);
            const { px: X1, py: Y1, pz: Z1 } = this;
            const { px: X2, py: Y2, pz: Z2 } = other;
            let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO; // prettier-ignore
            const a = CURVE.a;
            const b3 = Fp.mul(CURVE.b, _3n$1);
            let t0 = Fp.mul(X1, X2); // step 1
            let t1 = Fp.mul(Y1, Y2);
            let t2 = Fp.mul(Z1, Z2);
            let t3 = Fp.add(X1, Y1);
            let t4 = Fp.add(X2, Y2); // step 5
            t3 = Fp.mul(t3, t4);
            t4 = Fp.add(t0, t1);
            t3 = Fp.sub(t3, t4);
            t4 = Fp.add(X1, Z1);
            let t5 = Fp.add(X2, Z2); // step 10
            t4 = Fp.mul(t4, t5);
            t5 = Fp.add(t0, t2);
            t4 = Fp.sub(t4, t5);
            t5 = Fp.add(Y1, Z1);
            X3 = Fp.add(Y2, Z2); // step 15
            t5 = Fp.mul(t5, X3);
            X3 = Fp.add(t1, t2);
            t5 = Fp.sub(t5, X3);
            Z3 = Fp.mul(a, t4);
            X3 = Fp.mul(b3, t2); // step 20
            Z3 = Fp.add(X3, Z3);
            X3 = Fp.sub(t1, Z3);
            Z3 = Fp.add(t1, Z3);
            Y3 = Fp.mul(X3, Z3);
            t1 = Fp.add(t0, t0); // step 25
            t1 = Fp.add(t1, t0);
            t2 = Fp.mul(a, t2);
            t4 = Fp.mul(b3, t4);
            t1 = Fp.add(t1, t2);
            t2 = Fp.sub(t0, t2); // step 30
            t2 = Fp.mul(a, t2);
            t4 = Fp.add(t4, t2);
            t0 = Fp.mul(t1, t4);
            Y3 = Fp.add(Y3, t0);
            t0 = Fp.mul(t5, t4); // step 35
            X3 = Fp.mul(t3, X3);
            X3 = Fp.sub(X3, t0);
            t0 = Fp.mul(t3, t1);
            Z3 = Fp.mul(t5, Z3);
            Z3 = Fp.add(Z3, t0); // step 40
            return new Point(X3, Y3, Z3);
        }
        subtract(other) {
            return this.add(other.negate());
        }
        is0() {
            return this.equals(Point.ZERO);
        }
        wNAF(n) {
            return wnaf.wNAFCached(this, pointPrecomputes, n, (comp) => {
                const toInv = Fp.invertBatch(comp.map((p) => p.pz));
                return comp.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
            });
        }
        /**
         * Non-constant-time multiplication. Uses double-and-add algorithm.
         * It's faster, but should only be used when you don't care about
         * an exposed private key e.g. sig verification, which works over *public* keys.
         */
        multiplyUnsafe(n) {
            const I = Point.ZERO;
            if (n === _0n$5)
                return I;
            assertGE(n); // Will throw on 0
            if (n === _1n$2)
                return this;
            const { endo } = CURVE;
            if (!endo)
                return wnaf.unsafeLadder(this, n);
            // Apply endomorphism
            let { k1neg, k1, k2neg, k2 } = endo.splitScalar(n);
            let k1p = I;
            let k2p = I;
            let d = this;
            while (k1 > _0n$5 || k2 > _0n$5) {
                if (k1 & _1n$2)
                    k1p = k1p.add(d);
                if (k2 & _1n$2)
                    k2p = k2p.add(d);
                d = d.double();
                k1 >>= _1n$2;
                k2 >>= _1n$2;
            }
            if (k1neg)
                k1p = k1p.negate();
            if (k2neg)
                k2p = k2p.negate();
            k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
            return k1p.add(k2p);
        }
        /**
         * Constant time multiplication.
         * Uses wNAF method. Windowed method may be 10% faster,
         * but takes 2x longer to generate and consumes 2x memory.
         * Uses precomputes when available.
         * Uses endomorphism for Koblitz curves.
         * @param scalar by which the point would be multiplied
         * @returns New point
         */
        multiply(scalar) {
            assertGE(scalar);
            let n = scalar;
            let point, fake; // Fake point is used to const-time mult
            const { endo } = CURVE;
            if (endo) {
                const { k1neg, k1, k2neg, k2 } = endo.splitScalar(n);
                let { p: k1p, f: f1p } = this.wNAF(k1);
                let { p: k2p, f: f2p } = this.wNAF(k2);
                k1p = wnaf.constTimeNegate(k1neg, k1p);
                k2p = wnaf.constTimeNegate(k2neg, k2p);
                k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
                point = k1p.add(k2p);
                fake = f1p.add(f2p);
            }
            else {
                const { p, f } = this.wNAF(n);
                point = p;
                fake = f;
            }
            // Normalize `z` for both points, but return only real one
            return Point.normalizeZ([point, fake])[0];
        }
        /**
         * Efficiently calculate `aP + bQ`. Unsafe, can expose private key, if used incorrectly.
         * Not using Strauss-Shamir trick: precomputation tables are faster.
         * The trick could be useful if both P and Q are not G (not in our case).
         * @returns non-zero affine point
         */
        multiplyAndAddUnsafe(Q, a, b) {
            const G = Point.BASE; // No Strauss-Shamir trick: we have 10% faster G precomputes
            const mul = (P, a // Select faster multiply() method
            ) => (a === _0n$5 || a === _1n$2 || !P.equals(G) ? P.multiplyUnsafe(a) : P.multiply(a));
            const sum = mul(this, a).add(mul(Q, b));
            return sum.is0() ? undefined : sum;
        }
        // Converts Projective point to affine (x, y) coordinates.
        // Can accept precomputed Z^-1 - for example, from invertBatch.
        // (x, y, z) ∋ (x=x/z, y=y/z)
        toAffine(iz) {
            const { px: x, py: y, pz: z } = this;
            const is0 = this.is0();
            // If invZ was 0, we return zero point. However we still want to execute
            // all operations, so we replace invZ with a random number, 1.
            if (iz == null)
                iz = is0 ? Fp.ONE : Fp.inv(z);
            const ax = Fp.mul(x, iz);
            const ay = Fp.mul(y, iz);
            const zz = Fp.mul(z, iz);
            if (is0)
                return { x: Fp.ZERO, y: Fp.ZERO };
            if (!Fp.eql(zz, Fp.ONE))
                throw new Error('invZ was invalid');
            return { x: ax, y: ay };
        }
        isTorsionFree() {
            const { h: cofactor, isTorsionFree } = CURVE;
            if (cofactor === _1n$2)
                return true; // No subgroups, always torsion-free
            if (isTorsionFree)
                return isTorsionFree(Point, this);
            throw new Error('isTorsionFree() has not been declared for the elliptic curve');
        }
        clearCofactor() {
            const { h: cofactor, clearCofactor } = CURVE;
            if (cofactor === _1n$2)
                return this; // Fast-path
            if (clearCofactor)
                return clearCofactor(Point, this);
            return this.multiplyUnsafe(CURVE.h);
        }
        toRawBytes(isCompressed = true) {
            this.assertValidity();
            return toBytes(Point, this, isCompressed);
        }
        toHex(isCompressed = true) {
            return bytesToHex$1(this.toRawBytes(isCompressed));
        }
    }
    Point.BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
    Point.ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
    const _bits = CURVE.nBitLength;
    const wnaf = wNAF(Point, CURVE.endo ? Math.ceil(_bits / 2) : _bits);
    return {
        CURVE,
        ProjectivePoint: Point,
        normPrivateKeyToScalar,
        weierstrassEquation,
        isWithinCurveOrder,
    };
}
function validateOpts(curve) {
    const opts = validateBasic(curve);
    validateObject(opts, {
        hash: 'hash',
        hmac: 'function',
        randomBytes: 'function',
    }, {
        bits2int: 'function',
        bits2int_modN: 'function',
        lowS: 'boolean',
    });
    return Object.freeze({ lowS: true, ...opts });
}
function weierstrass(curveDef) {
    const CURVE = validateOpts(curveDef);
    const { Fp, n: CURVE_ORDER } = CURVE;
    const compressedLen = Fp.BYTES + 1; // e.g. 33 for 32
    const uncompressedLen = 2 * Fp.BYTES + 1; // e.g. 65 for 32
    function isValidFieldElement(num) {
        return _0n$5 < num && num < Fp.ORDER; // 0 is banned since it's not invertible FE
    }
    function modN(a) {
        return mod(a, CURVE_ORDER);
    }
    function invN(a) {
        return invert(a, CURVE_ORDER);
    }
    const { ProjectivePoint: Point, normPrivateKeyToScalar, weierstrassEquation, isWithinCurveOrder, } = weierstrassPoints({
        ...CURVE,
        toBytes(c, point, isCompressed) {
            const a = point.toAffine();
            const x = Fp.toBytes(a.x);
            const cat = concatBytes;
            if (isCompressed) {
                return cat(Uint8Array.from([point.hasEvenY() ? 0x02 : 0x03]), x);
            }
            else {
                return cat(Uint8Array.from([0x04]), x, Fp.toBytes(a.y));
            }
        },
        fromBytes(bytes) {
            const len = bytes.length;
            const head = bytes[0];
            const tail = bytes.subarray(1);
            // this.assertValidity() is done inside of fromHex
            if (len === compressedLen && (head === 0x02 || head === 0x03)) {
                const x = bytesToNumberBE(tail);
                if (!isValidFieldElement(x))
                    throw new Error('Point is not on curve');
                const y2 = weierstrassEquation(x); // y² = x³ + ax + b
                let y = Fp.sqrt(y2); // y = y² ^ (p+1)/4
                const isYOdd = (y & _1n$2) === _1n$2;
                // ECDSA
                const isHeadOdd = (head & 1) === 1;
                if (isHeadOdd !== isYOdd)
                    y = Fp.neg(y);
                return { x, y };
            }
            else if (len === uncompressedLen && head === 0x04) {
                const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
                const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
                return { x, y };
            }
            else {
                throw new Error(`Point of length ${len} was invalid. Expected ${compressedLen} compressed bytes or ${uncompressedLen} uncompressed bytes`);
            }
        },
    });
    const numToNByteStr = (num) => bytesToHex$1(numberToBytesBE(num, CURVE.nByteLength));
    function isBiggerThanHalfOrder(number) {
        const HALF = CURVE_ORDER >> _1n$2;
        return number > HALF;
    }
    function normalizeS(s) {
        return isBiggerThanHalfOrder(s) ? modN(-s) : s;
    }
    // slice bytes num
    const slcNum = (b, from, to) => bytesToNumberBE(b.slice(from, to));
    /**
     * ECDSA signature with its (r, s) properties. Supports DER & compact representations.
     */
    class Signature {
        constructor(r, s, recovery) {
            this.r = r;
            this.s = s;
            this.recovery = recovery;
            this.assertValidity();
        }
        // pair (bytes of r, bytes of s)
        static fromCompact(hex) {
            const l = CURVE.nByteLength;
            hex = ensureBytes('compactSignature', hex, l * 2);
            return new Signature(slcNum(hex, 0, l), slcNum(hex, l, 2 * l));
        }
        // DER encoded ECDSA signature
        // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
        static fromDER(hex) {
            const { r, s } = DER.toSig(ensureBytes('DER', hex));
            return new Signature(r, s);
        }
        assertValidity() {
            // can use assertGE here
            if (!isWithinCurveOrder(this.r))
                throw new Error('r must be 0 < r < CURVE.n');
            if (!isWithinCurveOrder(this.s))
                throw new Error('s must be 0 < s < CURVE.n');
        }
        addRecoveryBit(recovery) {
            return new Signature(this.r, this.s, recovery);
        }
        recoverPublicKey(msgHash) {
            const { r, s, recovery: rec } = this;
            const h = bits2int_modN(ensureBytes('msgHash', msgHash)); // Truncate hash
            if (rec == null || ![0, 1, 2, 3].includes(rec))
                throw new Error('recovery id invalid');
            const radj = rec === 2 || rec === 3 ? r + CURVE.n : r;
            if (radj >= Fp.ORDER)
                throw new Error('recovery id 2 or 3 invalid');
            const prefix = (rec & 1) === 0 ? '02' : '03';
            const R = Point.fromHex(prefix + numToNByteStr(radj));
            const ir = invN(radj); // r^-1
            const u1 = modN(-h * ir); // -hr^-1
            const u2 = modN(s * ir); // sr^-1
            const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2); // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
            if (!Q)
                throw new Error('point at infinify'); // unsafe is fine: no priv data leaked
            Q.assertValidity();
            return Q;
        }
        // Signatures should be low-s, to prevent malleability.
        hasHighS() {
            return isBiggerThanHalfOrder(this.s);
        }
        normalizeS() {
            return this.hasHighS() ? new Signature(this.r, modN(-this.s), this.recovery) : this;
        }
        // DER-encoded
        toDERRawBytes() {
            return hexToBytes$1(this.toDERHex());
        }
        toDERHex() {
            return DER.hexFromSig({ r: this.r, s: this.s });
        }
        // padded bytes of r, then padded bytes of s
        toCompactRawBytes() {
            return hexToBytes$1(this.toCompactHex());
        }
        toCompactHex() {
            return numToNByteStr(this.r) + numToNByteStr(this.s);
        }
    }
    const utils = {
        isValidPrivateKey(privateKey) {
            try {
                normPrivateKeyToScalar(privateKey);
                return true;
            }
            catch (error) {
                return false;
            }
        },
        normPrivateKeyToScalar: normPrivateKeyToScalar,
        /**
         * Produces cryptographically secure private key from random of size (nBitLength+64)
         * as per FIPS 186 B.4.1 with modulo bias being neglible.
         */
        randomPrivateKey: () => {
            const rand = CURVE.randomBytes(Fp.BYTES + 8);
            const num = hashToPrivateScalar(rand, CURVE_ORDER);
            return numberToBytesBE(num, CURVE.nByteLength);
        },
        /**
         * Creates precompute table for an arbitrary EC point. Makes point "cached".
         * Allows to massively speed-up `point.multiply(scalar)`.
         * @returns cached point
         * @example
         * const fast = utils.precompute(8, ProjectivePoint.fromHex(someonesPubKey));
         * fast.multiply(privKey); // much faster ECDH now
         */
        precompute(windowSize = 8, point = Point.BASE) {
            point._setWindowSize(windowSize);
            point.multiply(BigInt(3)); // 3 is arbitrary, just need any number here
            return point;
        },
    };
    /**
     * Computes public key for a private key. Checks for validity of the private key.
     * @param privateKey private key
     * @param isCompressed whether to return compact (default), or full key
     * @returns Public key, full when isCompressed=false; short when isCompressed=true
     */
    function getPublicKey(privateKey, isCompressed = true) {
        return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
    }
    /**
     * Quick and dirty check for item being public key. Does not validate hex, or being on-curve.
     */
    function isProbPub(item) {
        const arr = item instanceof Uint8Array;
        const str = typeof item === 'string';
        const len = (arr || str) && item.length;
        if (arr)
            return len === compressedLen || len === uncompressedLen;
        if (str)
            return len === 2 * compressedLen || len === 2 * uncompressedLen;
        if (item instanceof Point)
            return true;
        return false;
    }
    /**
     * ECDH (Elliptic Curve Diffie Hellman).
     * Computes shared public key from private key and public key.
     * Checks: 1) private key validity 2) shared key is on-curve.
     * Does NOT hash the result.
     * @param privateA private key
     * @param publicB different public key
     * @param isCompressed whether to return compact (default), or full key
     * @returns shared public key
     */
    function getSharedSecret(privateA, publicB, isCompressed = true) {
        if (isProbPub(privateA))
            throw new Error('first arg must be private key');
        if (!isProbPub(publicB))
            throw new Error('second arg must be public key');
        const b = Point.fromHex(publicB); // check for being on-curve
        return b.multiply(normPrivateKeyToScalar(privateA)).toRawBytes(isCompressed);
    }
    // RFC6979: ensure ECDSA msg is X bytes and < N. RFC suggests optional truncating via bits2octets.
    // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which matches bits2int.
    // bits2int can produce res>N, we can do mod(res, N) since the bitLen is the same.
    // int2octets can't be used; pads small msgs with 0: unacceptatble for trunc as per RFC vectors
    const bits2int = CURVE.bits2int ||
        function (bytes) {
            // For curves with nBitLength % 8 !== 0: bits2octets(bits2octets(m)) !== bits2octets(m)
            // for some cases, since bytes.length * 8 is not actual bitLength.
            const num = bytesToNumberBE(bytes); // check for == u8 done here
            const delta = bytes.length * 8 - CURVE.nBitLength; // truncate to nBitLength leftmost bits
            return delta > 0 ? num >> BigInt(delta) : num;
        };
    const bits2int_modN = CURVE.bits2int_modN ||
        function (bytes) {
            return modN(bits2int(bytes)); // can't use bytesToNumberBE here
        };
    // NOTE: pads output with zero as per spec
    const ORDER_MASK = bitMask(CURVE.nBitLength);
    /**
     * Converts to bytes. Checks if num in `[0..ORDER_MASK-1]` e.g.: `[0..2^256-1]`.
     */
    function int2octets(num) {
        if (typeof num !== 'bigint')
            throw new Error('bigint expected');
        if (!(_0n$5 <= num && num < ORDER_MASK))
            throw new Error(`bigint expected < 2^${CURVE.nBitLength}`);
        // works with order, can have different size than numToField!
        return numberToBytesBE(num, CURVE.nByteLength);
    }
    // Steps A, D of RFC6979 3.2
    // Creates RFC6979 seed; converts msg/privKey to numbers.
    // Used only in sign, not in verify.
    // NOTE: we cannot assume here that msgHash has same amount of bytes as curve order, this will be wrong at least for P521.
    // Also it can be bigger for P224 + SHA256
    function prepSig(msgHash, privateKey, opts = defaultSigOpts) {
        if (['recovered', 'canonical'].some((k) => k in opts))
            throw new Error('sign() legacy options not supported');
        const { hash, randomBytes } = CURVE;
        let { lowS, prehash, extraEntropy: ent } = opts; // generates low-s sigs by default
        if (lowS == null)
            lowS = true; // RFC6979 3.2: we skip step A, because we already provide hash
        msgHash = ensureBytes('msgHash', msgHash);
        if (prehash)
            msgHash = ensureBytes('prehashed msgHash', hash(msgHash));
        // We can't later call bits2octets, since nested bits2int is broken for curves
        // with nBitLength % 8 !== 0. Because of that, we unwrap it here as int2octets call.
        // const bits2octets = (bits) => int2octets(bits2int_modN(bits))
        const h1int = bits2int_modN(msgHash);
        const d = normPrivateKeyToScalar(privateKey); // validate private key, convert to bigint
        const seedArgs = [int2octets(d), int2octets(h1int)];
        // extraEntropy. RFC6979 3.6: additional k' (optional).
        if (ent != null) {
            // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1) || k')
            const e = ent === true ? randomBytes(Fp.BYTES) : ent; // generate random bytes OR pass as-is
            seedArgs.push(ensureBytes('extraEntropy', e, Fp.BYTES)); // check for being of size BYTES
        }
        const seed = concatBytes(...seedArgs); // Step D of RFC6979 3.2
        const m = h1int; // NOTE: no need to call bits2int second time here, it is inside truncateHash!
        // Converts signature params into point w r/s, checks result for validity.
        function k2sig(kBytes) {
            // RFC 6979 Section 3.2, step 3: k = bits2int(T)
            const k = bits2int(kBytes); // Cannot use fields methods, since it is group element
            if (!isWithinCurveOrder(k))
                return; // Important: all mod() calls here must be done over N
            const ik = invN(k); // k^-1 mod n
            const q = Point.BASE.multiply(k).toAffine(); // q = Gk
            const r = modN(q.x); // r = q.x mod n
            if (r === _0n$5)
                return;
            // Can use scalar blinding b^-1(bm + bdr) where b ∈ [1,q−1] according to
            // https://tches.iacr.org/index.php/TCHES/article/view/7337/6509. We've decided against it:
            // a) dependency on CSPRNG b) 15% slowdown c) doesn't really help since bigints are not CT
            const s = modN(ik * modN(m + r * d)); // Not using blinding here
            if (s === _0n$5)
                return;
            let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n$2); // recovery bit (2 or 3, when q.x > n)
            let normS = s;
            if (lowS && isBiggerThanHalfOrder(s)) {
                normS = normalizeS(s); // if lowS was passed, ensure s is always
                recovery ^= 1; // // in the bottom half of N
            }
            return new Signature(r, normS, recovery); // use normS, not s
        }
        return { seed, k2sig };
    }
    const defaultSigOpts = { lowS: CURVE.lowS, prehash: false };
    const defaultVerOpts = { lowS: CURVE.lowS, prehash: false };
    /**
     * Signs message hash (not message: you need to hash it by yourself).
     * ```
     * sign(m, d, k) where
     *   (x, y) = G × k
     *   r = x mod n
     *   s = (m + dr)/k mod n
     * ```
     * @param opts `lowS, extraEntropy, prehash`
     */
    function sign(msgHash, privKey, opts = defaultSigOpts) {
        const { seed, k2sig } = prepSig(msgHash, privKey, opts); // Steps A, D of RFC6979 3.2.
        const drbg = createHmacDrbg(CURVE.hash.outputLen, CURVE.nByteLength, CURVE.hmac);
        return drbg(seed, k2sig); // Steps B, C, D, E, F, G
    }
    // Enable precomputes. Slows down first publicKey computation by 20ms.
    Point.BASE._setWindowSize(8);
    // utils.precompute(8, ProjectivePoint.BASE)
    /**
     * Verifies a signature against message hash and public key.
     * Rejects lowS signatures by default: to override,
     * specify option `{lowS: false}`. Implements section 4.1.4 from https://www.secg.org/sec1-v2.pdf:
     *
     * ```
     * verify(r, s, h, P) where
     *   U1 = hs^-1 mod n
     *   U2 = rs^-1 mod n
     *   R = U1⋅G - U2⋅P
     *   mod(R.x, n) == r
     * ```
     */
    function verify(signature, msgHash, publicKey, opts = defaultVerOpts) {
        const sg = signature;
        msgHash = ensureBytes('msgHash', msgHash);
        publicKey = ensureBytes('publicKey', publicKey);
        if ('strict' in opts)
            throw new Error('options.strict was renamed to lowS');
        const { lowS, prehash } = opts;
        let _sig = undefined;
        let P;
        try {
            if (typeof sg === 'string' || sg instanceof Uint8Array) {
                // Signature can be represented in 2 ways: compact (2*nByteLength) & DER (variable-length).
                // Since DER can also be 2*nByteLength bytes, we check for it first.
                try {
                    _sig = Signature.fromDER(sg);
                }
                catch (derError) {
                    if (!(derError instanceof DER.Err))
                        throw derError;
                    _sig = Signature.fromCompact(sg);
                }
            }
            else if (typeof sg === 'object' && typeof sg.r === 'bigint' && typeof sg.s === 'bigint') {
                const { r, s } = sg;
                _sig = new Signature(r, s);
            }
            else {
                throw new Error('PARSE');
            }
            P = Point.fromHex(publicKey);
        }
        catch (error) {
            if (error.message === 'PARSE')
                throw new Error(`signature must be Signature instance, Uint8Array or hex string`);
            return false;
        }
        if (lowS && _sig.hasHighS())
            return false;
        if (prehash)
            msgHash = CURVE.hash(msgHash);
        const { r, s } = _sig;
        const h = bits2int_modN(msgHash); // Cannot use fields methods, since it is group element
        const is = invN(s); // s^-1
        const u1 = modN(h * is); // u1 = hs^-1 mod n
        const u2 = modN(r * is); // u2 = rs^-1 mod n
        const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2)?.toAffine(); // R = u1⋅G + u2⋅P
        if (!R)
            return false;
        const v = modN(R.x);
        return v === r;
    }
    return {
        CURVE,
        getPublicKey,
        getSharedSecret,
        sign,
        verify,
        ProjectivePoint: Point,
        Signature,
        utils,
    };
}
// Implementation of the Shallue and van de Woestijne method for any Weierstrass curve
// TODO: check if there is a way to merge this with uvRatio in Edwards && move to modular?
// b = True and y = sqrt(u / v) if (u / v) is square in F, and
// b = False and y = sqrt(Z * (u / v)) otherwise.
function SWUFpSqrtRatio(Fp, Z) {
    // Generic implementation
    const q = Fp.ORDER;
    let l = _0n$5;
    for (let o = q - _1n$2; o % _2n$2 === _0n$5; o /= _2n$2)
        l += _1n$2;
    const c1 = l; // 1. c1, the largest integer such that 2^c1 divides q - 1.
    const c2 = (q - _1n$2) / _2n$2 ** c1; // 2. c2 = (q - 1) / (2^c1)        # Integer arithmetic
    const c3 = (c2 - _1n$2) / _2n$2; // 3. c3 = (c2 - 1) / 2            # Integer arithmetic
    const c4 = _2n$2 ** c1 - _1n$2; // 4. c4 = 2^c1 - 1                # Integer arithmetic
    const c5 = _2n$2 ** (c1 - _1n$2); // 5. c5 = 2^(c1 - 1)              # Integer arithmetic
    const c6 = Fp.pow(Z, c2); // 6. c6 = Z^c2
    const c7 = Fp.pow(Z, (c2 + _1n$2) / _2n$2); // 7. c7 = Z^((c2 + 1) / 2)
    let sqrtRatio = (u, v) => {
        let tv1 = c6; // 1. tv1 = c6
        let tv2 = Fp.pow(v, c4); // 2. tv2 = v^c4
        let tv3 = Fp.sqr(tv2); // 3. tv3 = tv2^2
        tv3 = Fp.mul(tv3, v); // 4. tv3 = tv3 * v
        let tv5 = Fp.mul(u, tv3); // 5. tv5 = u * tv3
        tv5 = Fp.pow(tv5, c3); // 6. tv5 = tv5^c3
        tv5 = Fp.mul(tv5, tv2); // 7. tv5 = tv5 * tv2
        tv2 = Fp.mul(tv5, v); // 8. tv2 = tv5 * v
        tv3 = Fp.mul(tv5, u); // 9. tv3 = tv5 * u
        let tv4 = Fp.mul(tv3, tv2); // 10. tv4 = tv3 * tv2
        tv5 = Fp.pow(tv4, c5); // 11. tv5 = tv4^c5
        let isQR = Fp.eql(tv5, Fp.ONE); // 12. isQR = tv5 == 1
        tv2 = Fp.mul(tv3, c7); // 13. tv2 = tv3 * c7
        tv5 = Fp.mul(tv4, tv1); // 14. tv5 = tv4 * tv1
        tv3 = Fp.cmov(tv2, tv3, isQR); // 15. tv3 = CMOV(tv2, tv3, isQR)
        tv4 = Fp.cmov(tv5, tv4, isQR); // 16. tv4 = CMOV(tv5, tv4, isQR)
        // 17. for i in (c1, c1 - 1, ..., 2):
        for (let i = c1; i > 1; i--) {
            let tv5 = _2n$2 ** (i - _2n$2); // 18.    tv5 = i - 2;    19.    tv5 = 2^tv5
            let tvv5 = Fp.pow(tv4, tv5); // 20.    tv5 = tv4^tv5
            const e1 = Fp.eql(tvv5, Fp.ONE); // 21.    e1 = tv5 == 1
            tv2 = Fp.mul(tv3, tv1); // 22.    tv2 = tv3 * tv1
            tv1 = Fp.mul(tv1, tv1); // 23.    tv1 = tv1 * tv1
            tvv5 = Fp.mul(tv4, tv1); // 24.    tv5 = tv4 * tv1
            tv3 = Fp.cmov(tv2, tv3, e1); // 25.    tv3 = CMOV(tv2, tv3, e1)
            tv4 = Fp.cmov(tvv5, tv4, e1); // 26.    tv4 = CMOV(tv5, tv4, e1)
        }
        return { isValid: isQR, value: tv3 };
    };
    if (Fp.ORDER % _4n$1 === _3n$1) {
        // sqrt_ratio_3mod4(u, v)
        const c1 = (Fp.ORDER - _3n$1) / _4n$1; // 1. c1 = (q - 3) / 4     # Integer arithmetic
        const c2 = Fp.sqrt(Fp.neg(Z)); // 2. c2 = sqrt(-Z)
        sqrtRatio = (u, v) => {
            let tv1 = Fp.sqr(v); // 1. tv1 = v^2
            const tv2 = Fp.mul(u, v); // 2. tv2 = u * v
            tv1 = Fp.mul(tv1, tv2); // 3. tv1 = tv1 * tv2
            let y1 = Fp.pow(tv1, c1); // 4. y1 = tv1^c1
            y1 = Fp.mul(y1, tv2); // 5. y1 = y1 * tv2
            const y2 = Fp.mul(y1, c2); // 6. y2 = y1 * c2
            const tv3 = Fp.mul(Fp.sqr(y1), v); // 7. tv3 = y1^2; 8. tv3 = tv3 * v
            const isQR = Fp.eql(tv3, u); // 9. isQR = tv3 == u
            let y = Fp.cmov(y2, y1, isQR); // 10. y = CMOV(y2, y1, isQR)
            return { isValid: isQR, value: y }; // 11. return (isQR, y) isQR ? y : y*c2
        };
    }
    // No curves uses that
    // if (Fp.ORDER % _8n === _5n) // sqrt_ratio_5mod8
    return sqrtRatio;
}
// From draft-irtf-cfrg-hash-to-curve-16
function mapToCurveSimpleSWU(Fp, opts) {
    validateField(Fp);
    if (!Fp.isValid(opts.A) || !Fp.isValid(opts.B) || !Fp.isValid(opts.Z))
        throw new Error('mapToCurveSimpleSWU: invalid opts');
    const sqrtRatio = SWUFpSqrtRatio(Fp, opts.Z);
    if (!Fp.isOdd)
        throw new Error('Fp.isOdd is not implemented!');
    // Input: u, an element of F.
    // Output: (x, y), a point on E.
    return (u) => {
        // prettier-ignore
        let tv1, tv2, tv3, tv4, tv5, tv6, x, y;
        tv1 = Fp.sqr(u); // 1.  tv1 = u^2
        tv1 = Fp.mul(tv1, opts.Z); // 2.  tv1 = Z * tv1
        tv2 = Fp.sqr(tv1); // 3.  tv2 = tv1^2
        tv2 = Fp.add(tv2, tv1); // 4.  tv2 = tv2 + tv1
        tv3 = Fp.add(tv2, Fp.ONE); // 5.  tv3 = tv2 + 1
        tv3 = Fp.mul(tv3, opts.B); // 6.  tv3 = B * tv3
        tv4 = Fp.cmov(opts.Z, Fp.neg(tv2), !Fp.eql(tv2, Fp.ZERO)); // 7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
        tv4 = Fp.mul(tv4, opts.A); // 8.  tv4 = A * tv4
        tv2 = Fp.sqr(tv3); // 9.  tv2 = tv3^2
        tv6 = Fp.sqr(tv4); // 10. tv6 = tv4^2
        tv5 = Fp.mul(tv6, opts.A); // 11. tv5 = A * tv6
        tv2 = Fp.add(tv2, tv5); // 12. tv2 = tv2 + tv5
        tv2 = Fp.mul(tv2, tv3); // 13. tv2 = tv2 * tv3
        tv6 = Fp.mul(tv6, tv4); // 14. tv6 = tv6 * tv4
        tv5 = Fp.mul(tv6, opts.B); // 15. tv5 = B * tv6
        tv2 = Fp.add(tv2, tv5); // 16. tv2 = tv2 + tv5
        x = Fp.mul(tv1, tv3); // 17.   x = tv1 * tv3
        const { isValid, value } = sqrtRatio(tv2, tv6); // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
        y = Fp.mul(tv1, u); // 19.   y = tv1 * u  -> Z * u^3 * y1
        y = Fp.mul(y, value); // 20.   y = y * y1
        x = Fp.cmov(x, tv3, isValid); // 21.   x = CMOV(x, tv3, is_gx1_square)
        y = Fp.cmov(y, value, isValid); // 22.   y = CMOV(y, y1, is_gx1_square)
        const e1 = Fp.isOdd(u) === Fp.isOdd(y); // 23.  e1 = sgn0(u) == sgn0(y)
        y = Fp.cmov(Fp.neg(y), y, e1); // 24.   y = CMOV(-y, y, e1)
        x = Fp.div(x, tv4); // 25.   x = x / tv4
        return { x, y };
    };
}

function validateDST(dst) {
    if (dst instanceof Uint8Array)
        return dst;
    if (typeof dst === 'string')
        return utf8ToBytes$2(dst);
    throw new Error('DST must be Uint8Array or string');
}
// Octet Stream to Integer. "spec" implementation of os2ip is 2.5x slower vs bytesToNumberBE.
const os2ip = bytesToNumberBE;
// Integer to Octet Stream (numberToBytesBE)
function i2osp(value, length) {
    if (value < 0 || value >= 1 << (8 * length)) {
        throw new Error(`bad I2OSP call: value=${value} length=${length}`);
    }
    const res = Array.from({ length }).fill(0);
    for (let i = length - 1; i >= 0; i--) {
        res[i] = value & 0xff;
        value >>>= 8;
    }
    return new Uint8Array(res);
}
function strxor(a, b) {
    const arr = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        arr[i] = a[i] ^ b[i];
    }
    return arr;
}
function isBytes(item) {
    if (!(item instanceof Uint8Array))
        throw new Error('Uint8Array expected');
}
function isNum(item) {
    if (!Number.isSafeInteger(item))
        throw new Error('number expected');
}
// Produces a uniformly random byte string using a cryptographic hash function H that outputs b bits
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
function expand_message_xmd(msg, DST, lenInBytes, H) {
    isBytes(msg);
    isBytes(DST);
    isNum(lenInBytes);
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3.3
    if (DST.length > 255)
        DST = H(concatBytes(utf8ToBytes$2('H2C-OVERSIZE-DST-'), DST));
    const { outputLen: b_in_bytes, blockLen: r_in_bytes } = H;
    const ell = Math.ceil(lenInBytes / b_in_bytes);
    if (ell > 255)
        throw new Error('Invalid xmd length');
    const DST_prime = concatBytes(DST, i2osp(DST.length, 1));
    const Z_pad = i2osp(0, r_in_bytes);
    const l_i_b_str = i2osp(lenInBytes, 2); // len_in_bytes_str
    const b = new Array(ell);
    const b_0 = H(concatBytes(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
    b[0] = H(concatBytes(b_0, i2osp(1, 1), DST_prime));
    for (let i = 1; i <= ell; i++) {
        const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
        b[i] = H(concatBytes(...args));
    }
    const pseudo_random_bytes = concatBytes(...b);
    return pseudo_random_bytes.slice(0, lenInBytes);
}
function expand_message_xof(msg, DST, lenInBytes, k, H) {
    isBytes(msg);
    isBytes(DST);
    isNum(lenInBytes);
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3.3
    // DST = H('H2C-OVERSIZE-DST-' || a_very_long_DST, Math.ceil((lenInBytes * k) / 8));
    if (DST.length > 255) {
        const dkLen = Math.ceil((2 * k) / 8);
        DST = H.create({ dkLen }).update(utf8ToBytes$2('H2C-OVERSIZE-DST-')).update(DST).digest();
    }
    if (lenInBytes > 65535 || DST.length > 255)
        throw new Error('expand_message_xof: invalid lenInBytes');
    return (H.create({ dkLen: lenInBytes })
        .update(msg)
        .update(i2osp(lenInBytes, 2))
        // 2. DST_prime = DST || I2OSP(len(DST), 1)
        .update(DST)
        .update(i2osp(DST.length, 1))
        .digest());
}
/**
 * Hashes arbitrary-length byte strings to a list of one or more elements of a finite field F
 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3
 * @param msg a byte string containing the message to hash
 * @param count the number of elements of F to output
 * @param options `{DST: string, p: bigint, m: number, k: number, expand: 'xmd' | 'xof', hash: H}`, see above
 * @returns [u_0, ..., u_(count - 1)], a list of field elements.
 */
function hash_to_field(msg, count, options) {
    validateObject(options, {
        DST: 'string',
        p: 'bigint',
        m: 'isSafeInteger',
        k: 'isSafeInteger',
        hash: 'hash',
    });
    const { p, k, m, hash, expand, DST: _DST } = options;
    isBytes(msg);
    isNum(count);
    const DST = validateDST(_DST);
    const log2p = p.toString(2).length;
    const L = Math.ceil((log2p + k) / 8); // section 5.1 of ietf draft link above
    const len_in_bytes = count * m * L;
    let prb; // pseudo_random_bytes
    if (expand === 'xmd') {
        prb = expand_message_xmd(msg, DST, len_in_bytes, hash);
    }
    else if (expand === 'xof') {
        prb = expand_message_xof(msg, DST, len_in_bytes, k, hash);
    }
    else if (expand === undefined) {
        prb = msg;
    }
    else {
        throw new Error('expand must be "xmd", "xof" or undefined');
    }
    const u = new Array(count);
    for (let i = 0; i < count; i++) {
        const e = new Array(m);
        for (let j = 0; j < m; j++) {
            const elm_offset = L * (j + i * m);
            const tv = prb.subarray(elm_offset, elm_offset + L);
            e[j] = mod(os2ip(tv), p);
        }
        u[i] = e;
    }
    return u;
}
function isogenyMap(field, map) {
    // Make same order as in spec
    const COEFF = map.map((i) => Array.from(i).reverse());
    return (x, y) => {
        const [xNum, xDen, yNum, yDen] = COEFF.map((val) => val.reduce((acc, i) => field.add(field.mul(acc, x), i)));
        x = field.div(xNum, xDen); // xNum / xDen
        y = field.mul(y, field.div(yNum, yDen)); // y * (yNum / yDev)
        return { x, y };
    };
}
function createHasher(Point, mapToCurve, def) {
    if (typeof mapToCurve !== 'function')
        throw new Error('mapToCurve() must be defined');
    return {
        // Encodes byte string to elliptic curve
        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-3
        hashToCurve(msg, options) {
            const u = hash_to_field(msg, 2, { ...def, DST: def.DST, ...options });
            const u0 = Point.fromAffine(mapToCurve(u[0]));
            const u1 = Point.fromAffine(mapToCurve(u[1]));
            const P = u0.add(u1).clearCofactor();
            P.assertValidity();
            return P;
        },
        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-3
        encodeToCurve(msg, options) {
            const u = hash_to_field(msg, 1, { ...def, DST: def.encodeDST, ...options });
            const P = Point.fromAffine(mapToCurve(u[0])).clearCofactor();
            P.assertValidity();
            return P;
        },
    };
}

// HMAC (RFC 2104)
let HMAC$1 = class HMAC extends Hash$2 {
    constructor(hash, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        assert$4.hash(hash);
        const key = toBytes$2(_key);
        this.iHash = hash.create();
        if (typeof this.iHash.update !== 'function')
            throw new TypeError('Expected instance of class which extends utils.Hash');
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        // blockLen can be bigger than outputLen
        pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36;
        this.iHash.update(pad);
        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
        this.oHash = hash.create();
        // Undo internal XOR && apply outer XOR
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36 ^ 0x5c;
        this.oHash.update(pad);
        pad.fill(0);
    }
    update(buf) {
        assert$4.exists(this);
        this.iHash.update(buf);
        return this;
    }
    digestInto(out) {
        assert$4.exists(this);
        assert$4.bytes(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
    }
    _cloneInto(to) {
        // Create new instance without calling constructor since key already in state and we don't know it.
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
    }
    destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
    }
};
/**
 * HMAC: RFC2104 message authentication code.
 * @param hash - function that would be used e.g. sha256
 * @param key - message key
 * @param message - message data
 */
const hmac$2 = (hash, key, message) => new HMAC$1(hash, key).update(message).digest();
hmac$2.create = (hash, key) => new HMAC$1(hash, key);

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// connects noble-curves to noble-hashes
function getHash(hash) {
    return {
        hash,
        hmac: (key, ...msgs) => hmac$2(hash, key, concatBytes$1(...msgs)),
        randomBytes,
    };
}
function createCurve(curveDef, defHash) {
    const create = (hash) => weierstrass({ ...curveDef, ...getHash(hash) });
    return Object.freeze({ ...create(defHash), create });
}

/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
const secp256k1P = BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
const secp256k1N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const _1n$1 = BigInt(1);
const _2n$1 = BigInt(2);
const divNearest = (a, b) => (a + b / _2n$1) / b;
/**
 * √n = n^((p+1)/4) for fields p = 3 mod 4. We unwrap the loop and multiply bit-by-bit.
 * (P+1n/4n).toString(2) would produce bits [223x 1, 0, 22x 1, 4x 0, 11, 00]
 */
function sqrtMod(y) {
    const P = secp256k1P;
    // prettier-ignore
    const _3n = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
    // prettier-ignore
    const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
    const b2 = (y * y * y) % P; // x^3, 11
    const b3 = (b2 * b2 * y) % P; // x^7
    const b6 = (pow2(b3, _3n, P) * b3) % P;
    const b9 = (pow2(b6, _3n, P) * b3) % P;
    const b11 = (pow2(b9, _2n$1, P) * b2) % P;
    const b22 = (pow2(b11, _11n, P) * b11) % P;
    const b44 = (pow2(b22, _22n, P) * b22) % P;
    const b88 = (pow2(b44, _44n, P) * b44) % P;
    const b176 = (pow2(b88, _88n, P) * b88) % P;
    const b220 = (pow2(b176, _44n, P) * b44) % P;
    const b223 = (pow2(b220, _3n, P) * b3) % P;
    const t1 = (pow2(b223, _23n, P) * b22) % P;
    const t2 = (pow2(t1, _6n, P) * b2) % P;
    const root = pow2(t2, _2n$1, P);
    if (!Fp.eql(Fp.sqr(root), y))
        throw new Error('Cannot find square root');
    return root;
}
const Fp = Field$1(secp256k1P, undefined, undefined, { sqrt: sqrtMod });
const secp256k1 = createCurve({
    a: BigInt(0),
    b: BigInt(7),
    Fp,
    n: secp256k1N,
    // Base point (x, y) aka generator point
    Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
    Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
    h: BigInt(1),
    lowS: true,
    /**
     * secp256k1 belongs to Koblitz curves: it has efficiently computable endomorphism.
     * Endomorphism uses 2x less RAM, speeds up precomputation by 2x and ECDH / key recovery by 20%.
     * For precomputed wNAF it trades off 1/2 init time & 1/3 ram for 20% perf hit.
     * Explanation: https://gist.github.com/paulmillr/eb670806793e84df628a7c434a873066
     */
    endo: {
        beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
        splitScalar: (k) => {
            const n = secp256k1N;
            const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
            const b1 = -_1n$1 * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
            const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
            const b2 = a1;
            const POW_2_128 = BigInt('0x100000000000000000000000000000000'); // (2n**128n).toString(16)
            const c1 = divNearest(b2 * k, n);
            const c2 = divNearest(-b1 * k, n);
            let k1 = mod(k - c1 * a1 - c2 * a2, n);
            let k2 = mod(-c1 * b1 - c2 * b2, n);
            const k1neg = k1 > POW_2_128;
            const k2neg = k2 > POW_2_128;
            if (k1neg)
                k1 = n - k1;
            if (k2neg)
                k2 = n - k2;
            if (k1 > POW_2_128 || k2 > POW_2_128) {
                throw new Error('splitScalar: Endomorphism failed, k=' + k);
            }
            return { k1neg, k1, k2neg, k2 };
        },
    },
}, sha256$3);
// Schnorr signatures are superior to ECDSA from above. Below is Schnorr-specific BIP0340 code.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
const _0n$4 = BigInt(0);
const fe = (x) => typeof x === 'bigint' && _0n$4 < x && x < secp256k1P;
const ge = (x) => typeof x === 'bigint' && _0n$4 < x && x < secp256k1N;
/** An object mapping tags to their tagged hash prefix of [SHA256(tag) | SHA256(tag)] */
const TAGGED_HASH_PREFIXES = {};
function taggedHash(tag, ...messages) {
    let tagP = TAGGED_HASH_PREFIXES[tag];
    if (tagP === undefined) {
        const tagH = sha256$3(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
        tagP = concatBytes(tagH, tagH);
        TAGGED_HASH_PREFIXES[tag] = tagP;
    }
    return sha256$3(concatBytes(tagP, ...messages));
}
// ECDSA compact points are 33-byte. Schnorr is 32: we strip first byte 0x02 or 0x03
const pointToBytes = (point) => point.toRawBytes(true).slice(1);
const numTo32b = (n) => numberToBytesBE(n, 32);
const modP$1 = (x) => mod(x, secp256k1P);
const modN$1 = (x) => mod(x, secp256k1N);
const Point$2 = secp256k1.ProjectivePoint;
const GmulAdd = (Q, a, b) => Point$2.BASE.multiplyAndAddUnsafe(Q, a, b);
// Calculate point, scalar and bytes
function schnorrGetExtPubKey(priv) {
    let d_ = secp256k1.utils.normPrivateKeyToScalar(priv); // same method executed in fromPrivateKey
    let p = Point$2.fromPrivateKey(d_); // P = d'⋅G; 0 < d' < n check is done inside
    const scalar = p.hasEvenY() ? d_ : modN$1(-d_);
    return { scalar: scalar, bytes: pointToBytes(p) };
}
/**
 * lift_x from BIP340. Convert 32-byte x coordinate to elliptic curve point.
 * @returns valid point checked for being on-curve
 */
function lift_x(x) {
    if (!fe(x))
        throw new Error('bad x: need 0 < x < p'); // Fail if x ≥ p.
    const xx = modP$1(x * x);
    const c = modP$1(xx * x + BigInt(7)); // Let c = x³ + 7 mod p.
    let y = sqrtMod(c); // Let y = c^(p+1)/4 mod p.
    if (y % _2n$1 !== _0n$4)
        y = modP$1(-y); // Return the unique point P such that x(P) = x and
    const p = new Point$2(x, y, _1n$1); // y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
    p.assertValidity();
    return p;
}
/**
 * Create tagged hash, convert it to bigint, reduce modulo-n.
 */
function challenge(...args) {
    return modN$1(bytesToNumberBE(taggedHash('BIP0340/challenge', ...args)));
}
/**
 * Schnorr public key is just `x` coordinate of Point as per BIP340.
 */
function schnorrGetPublicKey(privateKey) {
    return schnorrGetExtPubKey(privateKey).bytes; // d'=int(sk). Fail if d'=0 or d'≥n. Ret bytes(d'⋅G)
}
/**
 * Creates Schnorr signature as per BIP340. Verifies itself before returning anything.
 * auxRand is optional and is not the sole source of k generation: bad CSPRNG won't be dangerous.
 */
function schnorrSign(message, privateKey, auxRand = randomBytes(32)) {
    const m = ensureBytes('message', message);
    const { bytes: px, scalar: d } = schnorrGetExtPubKey(privateKey); // checks for isWithinCurveOrder
    const a = ensureBytes('auxRand', auxRand, 32); // Auxiliary random data a: a 32-byte array
    const t = numTo32b(d ^ bytesToNumberBE(taggedHash('BIP0340/aux', a))); // Let t be the byte-wise xor of bytes(d) and hash/aux(a)
    const rand = taggedHash('BIP0340/nonce', t, px, m); // Let rand = hash/nonce(t || bytes(P) || m)
    const k_ = modN$1(bytesToNumberBE(rand)); // Let k' = int(rand) mod n
    if (k_ === _0n$4)
        throw new Error('sign failed: k is zero'); // Fail if k' = 0.
    const { bytes: rx, scalar: k } = schnorrGetExtPubKey(k_); // Let R = k'⋅G.
    const e = challenge(rx, px, m); // Let e = int(hash/challenge(bytes(R) || bytes(P) || m)) mod n.
    const sig = new Uint8Array(64); // Let sig = bytes(R) || bytes((k + ed) mod n).
    sig.set(rx, 0);
    sig.set(numTo32b(modN$1(k + e * d)), 32);
    // If Verify(bytes(P), m, sig) (see below) returns failure, abort
    if (!schnorrVerify(sig, m, px))
        throw new Error('sign: Invalid signature produced');
    return sig;
}
/**
 * Verifies Schnorr signature.
 * Will swallow errors & return false except for initial type validation of arguments.
 */
function schnorrVerify(signature, message, publicKey) {
    const sig = ensureBytes('signature', signature, 64);
    const m = ensureBytes('message', message);
    const pub = ensureBytes('publicKey', publicKey, 32);
    try {
        const P = lift_x(bytesToNumberBE(pub)); // P = lift_x(int(pk)); fail if that fails
        const r = bytesToNumberBE(sig.subarray(0, 32)); // Let r = int(sig[0:32]); fail if r ≥ p.
        if (!fe(r))
            return false;
        const s = bytesToNumberBE(sig.subarray(32, 64)); // Let s = int(sig[32:64]); fail if s ≥ n.
        if (!ge(s))
            return false;
        const e = challenge(numTo32b(r), pointToBytes(P), m); // int(challenge(bytes(r)||bytes(P)||m))%n
        const R = GmulAdd(P, s, modN$1(-e)); // R = s⋅G - e⋅P
        if (!R || !R.hasEvenY() || R.toAffine().x !== r)
            return false; // -eP == (n-e)P
        return true; // Fail if is_infinite(R) / not has_even_y(R) / x(R) ≠ r.
    }
    catch (error) {
        return false;
    }
}
const schnorr = {
    getPublicKey: schnorrGetPublicKey,
    sign: schnorrSign,
    verify: schnorrVerify,
    utils: {
        randomPrivateKey: secp256k1.utils.randomPrivateKey,
        lift_x,
        pointToBytes,
        numberToBytesBE,
        bytesToNumberBE,
        taggedHash,
        mod,
    },
};
const isoMap = isogenyMap(Fp, [
    // xNum
    [
        '0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7',
        '0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581',
        '0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262',
        '0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c',
    ],
    // xDen
    [
        '0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b',
        '0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14',
        '0x0000000000000000000000000000000000000000000000000000000000000001', // LAST 1
    ],
    // yNum
    [
        '0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c',
        '0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3',
        '0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931',
        '0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84',
    ],
    // yDen
    [
        '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b',
        '0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573',
        '0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f',
        '0x0000000000000000000000000000000000000000000000000000000000000001', // LAST 1
    ],
].map((i) => i.map((j) => BigInt(j))));
const mapSWU = mapToCurveSimpleSWU(Fp, {
    A: BigInt('0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533'),
    B: BigInt('1771'),
    Z: Fp.create(BigInt('-11')),
});
createHasher(secp256k1.ProjectivePoint, (scalars) => {
    const { x, y } = mapSWU(Fp.create(scalars[0]));
    return isoMap(x, y);
}, {
    DST: 'secp256k1_XMD:SHA-256_SSWU_RO_',
    encodeDST: 'secp256k1_XMD:SHA-256_SSWU_NU_',
    p: Fp.ORDER,
    m: 1,
    k: 128,
    expand: 'xmd',
    hash: sha256$3,
});

function number$1(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`Wrong positive integer: ${n}`);
}
function bool$1(b) {
    if (typeof b !== 'boolean')
        throw new Error(`Expected boolean, not ${b}`);
}
function bytes$1(b, ...lengths) {
    if (!(b instanceof Uint8Array))
        throw new TypeError('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
function hash$2(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number$1(hash.outputLen);
    number$1(hash.blockLen);
}
function exists$1(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
function output$1(out, instance) {
    bytes$1(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
const assert$1$1 = {
    number: number$1,
    bool: bool$1,
    bytes: bytes$1,
    hash: hash$2,
    exists: exists$1,
    output: output$1,
};
var assert$2 = assert$1$1;

/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// Cast array to view
const createView$1 = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
// The rotate right (circular right shift) operation for uint32
const rotr$1 = (word, shift) => (word << (32 - shift)) | (word >>> shift);
// big-endian hardware is rare. Just in case someone still decides to run hashes:
// early-throw an error because we don't support BE yet.
const isLE$1 = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
if (!isLE$1)
    throw new Error('Non little-endian hardware is not supported');
Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function utf8ToBytes$1(str) {
    if (typeof str !== 'string') {
        throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
    }
    return new TextEncoder().encode(str);
}
function toBytes$1(data) {
    if (typeof data === 'string')
        data = utf8ToBytes$1(data);
    if (!(data instanceof Uint8Array))
        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
    return data;
}
// For runtime check if class implements interface
let Hash$1 = class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
};
function wrapConstructor$1(hashConstructor) {
    const hashC = (message) => hashConstructor().update(toBytes$1(message)).digest();
    const tmp = hashConstructor();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashConstructor();
    return hashC;
}

// Polyfill for Safari 14
function setBigUint64$1(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
let SHA2$1 = class SHA2 extends Hash$1 {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView$1(this.buffer);
    }
    update(data) {
        assert$2.exists(this);
        const { view, buffer, blockLen } = this;
        data = toBytes$1(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = createView$1(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        assert$2.exists(this);
        assert$2.output(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64$1(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = createView$1(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
};

// Choice: a ? b : c
const Chi$1 = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj$1 = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K$1 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV$1 = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W$1 = new Uint32Array(64);
let SHA256$1 = class SHA256 extends SHA2$1 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV$1[0] | 0;
        this.B = IV$1[1] | 0;
        this.C = IV$1[2] | 0;
        this.D = IV$1[3] | 0;
        this.E = IV$1[4] | 0;
        this.F = IV$1[5] | 0;
        this.G = IV$1[6] | 0;
        this.H = IV$1[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W$1[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W$1[i - 15];
            const W2 = SHA256_W$1[i - 2];
            const s0 = rotr$1(W15, 7) ^ rotr$1(W15, 18) ^ (W15 >>> 3);
            const s1 = rotr$1(W2, 17) ^ rotr$1(W2, 19) ^ (W2 >>> 10);
            SHA256_W$1[i] = (s1 + SHA256_W$1[i - 7] + s0 + SHA256_W$1[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = rotr$1(E, 6) ^ rotr$1(E, 11) ^ rotr$1(E, 25);
            const T1 = (H + sigma1 + Chi$1(E, F, G) + SHA256_K$1[i] + SHA256_W$1[i]) | 0;
            const sigma0 = rotr$1(A, 2) ^ rotr$1(A, 13) ^ rotr$1(A, 22);
            const T2 = (sigma0 + Maj$1(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W$1.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
};
// Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
let SHA224$1 = class SHA224 extends SHA256$1 {
    constructor() {
        super();
        this.A = 0xc1059ed8 | 0;
        this.B = 0x367cd507 | 0;
        this.C = 0x3070dd17 | 0;
        this.D = 0xf70e5939 | 0;
        this.E = 0xffc00b31 | 0;
        this.F = 0x68581511 | 0;
        this.G = 0x64f98fa7 | 0;
        this.H = 0xbefa4fa4 | 0;
        this.outputLen = 28;
    }
};
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
const sha256$2 = wrapConstructor$1(() => new SHA256$1());
wrapConstructor$1(() => new SHA224$1());

function within_size(data, size) {
    if (data.length > size) {
        throw new TypeError(`Data is larger than array size: ${data.length} > ${size}`);
    }
}
function is_hex(hex) {
    if (hex.match(/[^a-fA-f0-9]/) !== null) {
        throw new TypeError('Invalid characters in hex string: ' + hex);
    }
    if (hex.length % 2 !== 0) {
        throw new Error(`Length of hex string is invalid: ${hex.length}`);
    }
}
function is_safe_num(num) {
    if (num > Number.MAX_SAFE_INTEGER) {
        throw new TypeError('Number exceeds safe bounds!');
    }
}

const { getRandomValues } = crypto ?? globalThis.crypto ?? window.crypto;
function random$1(size = 32) {
    if (typeof getRandomValues === 'function') {
        return crypto.getRandomValues(new Uint8Array(size));
    }
    throw new Error('Crypto module missing getRandomValues!');
}
function set_buffer(data, size, endian = 'be') {
    if (size === undefined)
        size = data.length;
    within_size(data, size);
    const buffer = new Uint8Array(size).fill(0);
    const offset = (endian === 'be') ? 0 : size - data.length;
    buffer.set(data, offset);
    return buffer;
}
function join_array(arr) {
    let i, offset = 0;
    const size = arr.reduce((len, arr) => len + arr.length, 0);
    const buff = new Uint8Array(size);
    for (i = 0; i < arr.length; i++) {
        const a = arr[i];
        buff.set(a, offset);
        offset += a.length;
    }
    return buff;
}

const ec$2 = new TextEncoder();
const ALPHABETS = [
    {
        name: 'base58',
        charset: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    }
];
function getAlphabet(name) {
    for (const alpha of ALPHABETS) {
        if (alpha.name === name) {
            return alpha.charset;
        }
    }
    throw TypeError('Charset does not exist: ' + name);
}
function encode$1$1(data, charset, padding = false) {
    if (typeof data === 'string')
        data = ec$2.encode(data);
    const alphabet = getAlphabet(charset);
    const len = alphabet.length;
    const d = [];
    let s = '', i, j = 0, c, n;
    for (i = 0; i < data.length; i++) {
        j = 0;
        c = data[i];
        s += (c > 0 || (s.length ^ i) > 0) ? '' : '1';
        while (j in d || c > 0) {
            n = d[j];
            n = n > 0 ? n * 256 + c : c;
            c = n / len | 0;
            d[j] = n % len;
            j++;
        }
    }
    while (j-- > 0) {
        s += alphabet[d[j]];
    }
    return (padding && s.length % 4 > 0)
        ? s + '='.repeat(4 - s.length % 4)
        : s;
}
function decode$1$1(encoded, charset) {
    const alphabet = getAlphabet(charset);
    const len = alphabet.length, d = [], b = [];
    encoded = encoded.replace('=', '');
    let i, j = 0, c, n;
    for (i = 0; i < encoded.length; i++) {
        j = 0;
        c = alphabet.indexOf(encoded[i]);
        if (c < 0) {
            throw new Error(`Character range out of bounds: ${c}`);
        }
        if (!(c > 0 || (b.length ^ i) > 0))
            b.push(0);
        while (j in d || c > 0) {
            n = d[j];
            n = n > 0 ? n * len + c : c;
            c = n >> 8;
            d[j] = n % 256;
            j++;
        }
    }
    while (j-- > 0) {
        b.push(d[j]);
    }
    return new Uint8Array(b);
}
function hash256$1(data) {
    return sha256$2(sha256$2(data));
}
function addChecksum(data) {
    const sum = hash256$1(data);
    return join_array([data, sum.slice(0, 4)]);
}
function checkTheSum(data) {
    const ret = data.slice(0, -4);
    const chk = data.slice(-4);
    const sum = hash256$1(ret).slice(0, 4);
    if (sum.toString() !== chk.toString()) {
        throw new Error('Invalid checksum!');
    }
    return ret;
}
const BaseX = {
    encode: encode$1$1,
    decode: decode$1$1
};
const Base58C = {
    encode: (data) => {
        const withSum = addChecksum(data);
        return BaseX.encode(withSum, 'base58');
    },
    decode: (data) => {
        const decoded = BaseX.decode(data, 'base58');
        return checkTheSum(decoded);
    }
};

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const ENCODINGS = [
    { version: 0, name: 'bech32', const: 1 },
    { version: 1, name: 'bech32m', const: 0x2bc830a3 }
];
function polymod(values) {
    let chk = 1;
    for (let p = 0; p < values.length; ++p) {
        const top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ values[p];
        for (let i = 0; i < 5; ++i) {
            if (((top >> i) & 1) !== 0) {
                chk ^= GENERATOR[i];
            }
        }
    }
    return chk;
}
function hrpExpand(hrp) {
    const ret = [];
    let p;
    for (p = 0; p < hrp.length; ++p) {
        ret.push(hrp.charCodeAt(p) >> 5);
    }
    ret.push(0);
    for (p = 0; p < hrp.length; ++p) {
        ret.push(hrp.charCodeAt(p) & 31);
    }
    return ret;
}
function verifyChecksum(hrp, data, enc) {
    const combined = hrpExpand(hrp).concat(data);
    return polymod(combined) === enc.const;
}
function createChecksum(hrp, data, enc) {
    const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    const mod = polymod(values) ^ enc.const;
    const ret = [];
    for (let p = 0; p < 6; ++p) {
        ret.push((mod >> 5 * (5 - p)) & 31);
    }
    return ret;
}
function convertBits(data, fromBits, toBits, pad = true) {
    const ret = [];
    let acc = 0;
    let bits = 0;
    const maxVal = (1 << toBits) - 1;
    const maxAcc = (1 << (fromBits + toBits - 1)) - 1;
    for (const val of data) {
        if (val < 0 || (val >> fromBits) > 0) {
            throw new Error('Failed to perform base conversion. Invalid value: ' + String(val));
        }
        acc = ((acc << fromBits) | val) & maxAcc;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            ret.push((acc >> bits) & maxVal);
        }
    }
    if (pad) {
        if (bits > 0) {
            ret.push((acc << (toBits - bits)) & maxVal);
        }
    }
    else if (bits >= fromBits || ((acc << (toBits - bits)) & maxVal) > 0) {
        throw new Error('Failed to perform base conversion. Invalid Size!');
    }
    return ret;
}
function encode$5(hrp, data, enc) {
    const combined = data.concat(createChecksum(hrp, data, enc));
    let ret = hrp + '1';
    for (let p = 0; p < combined.length; ++p) {
        ret += CHARSET.charAt(combined[p]);
    }
    return ret;
}
function decode$5(bechstr) {
    if (!checkBounds(bechstr)) {
        throw new Error('Encoded string goes out of bounds!');
    }
    bechstr = bechstr.toLowerCase();
    if (!checkSeparatorPos(bechstr)) {
        throw new Error('Encoded string has invalid separator!');
    }
    const data = [];
    const pos = bechstr.lastIndexOf('1');
    const hrp = bechstr.substring(0, pos);
    for (let p = pos + 1; p < bechstr.length; ++p) {
        const d = CHARSET.indexOf(bechstr.charAt(p));
        if (d === -1) {
            throw new Error('Character idx out of bounds: ' + String(p));
        }
        data.push(d);
    }
    const enc = ENCODINGS.find(e => e.version === data[0]) ?? ENCODINGS[0];
    if (!verifyChecksum(hrp, data, enc)) {
        throw new Error('Checksum verification failed!');
    }
    return [hrp, data.slice(0, data.length - 6)];
}
function checkBounds(bechstr) {
    let p;
    let char;
    let hasLower = false;
    let hasUpper = false;
    for (p = 0; p < bechstr.length; ++p) {
        char = bechstr.charCodeAt(p);
        if (char < 33 || char > 126) {
            return false;
        }
        if (char >= 97 && char <= 122) {
            hasLower = true;
        }
        if (char >= 65 && char <= 90) {
            hasUpper = true;
        }
    }
    if (hasLower && hasUpper)
        return false;
    return true;
}
function checkSeparatorPos(bechstr) {
    const pos = bechstr.lastIndexOf('1');
    return !(pos < 1 ||
        pos + 7 > bechstr.length ||
        bechstr.length > 90);
}
function b32encode(data, hrp = 'bc', version = 0) {
    const dat = [version, ...convertBits([...data], 8, 5)];
    const enc = ENCODINGS.find(e => e.version === version) ?? ENCODINGS[0];
    const str = encode$5(hrp, dat, enc);
    b32decode(str);
    return str;
}
function b32decode(str) {
    str = str.toLowerCase();
    const hrp = str.split('1', 1)[0];
    const [hrpgot, data] = decode$5(str);
    const decoded = convertBits(data.slice(1), 5, 8, false);
    const length = decoded.length;
    switch (true) {
        case (hrp !== hrpgot):
            throw new Error('Returned hrp string is invalid.');
        case (decoded === null || length < 2 || length > 40):
            throw new Error('Decoded string is invalid or out of spec.');
        case (data[0] > 16):
            throw new Error('Returned version bit is out of range.');
        default:
            return Uint8Array.from(decoded);
    }
}
function getVersion$1(str) {
    str = str.toLowerCase();
    const [_, data] = decode$5(str);
    return data[0];
}
const Bech32 = {
    encode: b32encode,
    decode: b32decode,
    version: getVersion$1
};

const BASE64_MAP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64URL_MAP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const ec$1 = new TextEncoder();
function b64encode(input, urlSafe = false, padding = true) {
    if (typeof input === 'string')
        input = ec$1.encode(input);
    const map = urlSafe ? B64URL_MAP : BASE64_MAP;
    let output = '';
    let bits = 0;
    let buffer = 0;
    for (let i = 0; i < input.length; i++) {
        buffer = (buffer << 8) | input[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            output += map[(buffer >> bits) & 0x3f];
        }
    }
    if (bits > 0) {
        buffer <<= 6 - bits;
        output += map[buffer & 0x3f];
        while (bits < 6) {
            output += padding ? '=' : '';
            bits += 2;
        }
    }
    return output;
}
function b64decode(input, urlSafe = false) {
    const map = (urlSafe || input.includes('-') || input.includes('_'))
        ? B64URL_MAP.split('')
        : BASE64_MAP.split('');
    input = input.replace(/=+$/, '');
    const chars = input.split('');
    let bits = 0;
    let value = 0;
    const bytes = [];
    for (let i = 0; i < chars.length; i++) {
        const c = chars[i];
        const index = map.indexOf(c);
        if (index === -1) {
            throw new Error('Invalid character: ' + c);
        }
        bits += 6;
        value <<= 6;
        value |= index;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((value >>> bits) & 0xff);
        }
    }
    return new Uint8Array(bytes);
}
const Base64 = {
    encode: b64encode,
    decode: b64decode
};
const B64URL = {
    encode: (data) => b64encode(data, true, false),
    decode: (data) => b64decode(data, true)
};

const _0n$3 = BigInt(0);
const _255n = BigInt(255);
const _256n = BigInt(256);
function big_size(big) {
    if (big <= 0xffn)
        return 1;
    if (big <= 0xffffn)
        return 2;
    if (big <= 0xffffffffn)
        return 4;
    if (big <= 0xffffffffffffffffn)
        return 8;
    if (big <= 0xffffffffffffffffffffffffffffffffn)
        return 16;
    if (big <= 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn) {
        return 32;
    }
    throw new TypeError('Must specify a fixed buffer size for bigints greater than 32 bytes.');
}
function bigToBytes(big, size, endian = 'be') {
    if (size === undefined)
        size = big_size(big);
    const use_le = (endian === 'le');
    const buffer = new ArrayBuffer(size);
    const dataView = new DataView(buffer);
    let offset = (use_le) ? 0 : size - 1;
    while (big > _0n$3) {
        const byte = big & _255n;
        const num = Number(byte);
        if (use_le) {
            dataView.setUint8(offset++, num);
        }
        else {
            dataView.setUint8(offset--, num);
        }
        big = (big - byte) / _256n;
    }
    return new Uint8Array(buffer);
}
function bytesToBig(bytes) {
    let num = BigInt(0);
    for (let i = bytes.length - 1; i >= 0; i--) {
        num = (num * _256n) + BigInt(bytes[i]);
    }
    return BigInt(num);
}

function binToBytes(binary) {
    const bins = binary.split('').map(Number);
    if (bins.length % 8 !== 0) {
        throw new Error(`Binary array is invalid length: ${binary.length}`);
    }
    const bytes = new Uint8Array(bins.length / 8);
    for (let i = 0, ct = 0; i < bins.length; i += 8, ct++) {
        let byte = 0;
        for (let j = 0; j < 8; j++) {
            byte |= (bins[i + j] << (7 - j));
        }
        bytes[ct] = byte;
    }
    return bytes;
}
function bytesToBin(bytes) {
    const bin = new Array(bytes.length * 8);
    let count = 0;
    for (const num of bytes) {
        if (num > 255) {
            throw new Error(`Invalid byte value: ${num}. Byte values must be between 0 and 255.`);
        }
        for (let i = 7; i >= 0; i--, count++) {
            bin[count] = (num >> i) & 1;
        }
    }
    return bin.join('');
}

function num_size(num) {
    if (num <= 0xFF)
        return 1;
    if (num <= 0xFFFF)
        return 2;
    if (num <= 0xFFFFFFFF)
        return 4;
    throw new TypeError('Numbers larger than 4 bytes must specify a fixed size!');
}
function numToBytes(num, size, endian = 'be') {
    if (size === undefined)
        size = num_size(num);
    const use_le = (endian === 'le');
    const buffer = new ArrayBuffer(size);
    const dataView = new DataView(buffer);
    let offset = (use_le) ? 0 : size - 1;
    while (num > 0) {
        const byte = num & 255;
        if (use_le) {
            dataView.setUint8(offset++, num);
        }
        else {
            dataView.setUint8(offset--, num);
        }
        num = (num - byte) / 256;
    }
    return new Uint8Array(buffer);
}
function bytesToNum(bytes) {
    let num = 0;
    for (let i = bytes.length - 1; i >= 0; i--) {
        num = (num * 256) + bytes[i];
        is_safe_num(num);
    }
    return num;
}

const ec = new TextEncoder();
const dc = new TextDecoder();
function strToBytes(str) {
    return ec.encode(str);
}
function bytesToStr(bytes) {
    return dc.decode(bytes);
}
function hex_size(hexstr, size) {
    is_hex(hexstr);
    const len = hexstr.length / 2;
    if (size === undefined)
        size = len;
    if (len > size) {
        throw new TypeError(`Hex string is larger than array size: ${len} > ${size}`);
    }
    return size;
}
function hexToBytes(hexstr, size, endian = 'le') {
    size = hex_size(hexstr, size);
    const use_le = (endian === 'le');
    const buffer = new ArrayBuffer(size);
    const dataView = new DataView(buffer);
    let offset = (use_le) ? 0 : size - 1;
    for (let i = 0; i < hexstr.length; i += 2) {
        const char = hexstr.substring(i, i + 2);
        const num = parseInt(char, 16);
        if (use_le) {
            dataView.setUint8(offset++, num);
        }
        else {
            dataView.setUint8(offset--, num);
        }
    }
    return new Uint8Array(buffer);
}
function bytesToHex(bytes) {
    let chars = '';
    for (let i = 0; i < bytes.length; i++) {
        chars += bytes[i].toString(16).padStart(2, '0');
    }
    return chars;
}
function jsonToBytes(obj) {
    const str = JSON.stringify(obj, (_, v) => {
        return typeof v === 'bigint'
            ? `${v}n`
            : v;
    });
    return strToBytes(str);
}

function buffer(data, size, endian) {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }
    if (data instanceof Uint8Array) {
        return set_buffer(data, size, endian);
    }
    if (typeof data === 'string') {
        return hexToBytes(data, size, endian);
    }
    if (typeof data === 'bigint') {
        return bigToBytes(data, size, endian);
    }
    if (typeof data === 'number') {
        return numToBytes(data, size, endian);
    }
    if (typeof data === 'boolean') {
        return Uint8Array.of(data ? 1 : 0);
    }
    throw TypeError('Unsupported format:' + String(typeof data));
}

class Buff extends Uint8Array {
    static { this.num = numToBuff; }
    static { this.big = bigToBuff; }
    static { this.bin = binToBuff; }
    static { this.raw = rawToBuff; }
    static { this.str = strToBuff; }
    static { this.hex = hexToBuff; }
    static { this.bytes = bytesToBuff; }
    static { this.json = jsonToBuff; }
    static { this.base64 = base64ToBuff; }
    static { this.b64url = b64urlToBuff; }
    static { this.bech32 = bech32ToBuff; }
    static { this.b58chk = b58chkToBuff; }
    static { this.encode = strToBytes; }
    static { this.decode = bytesToStr; }
    static random(size = 32) {
        const rand = random$1(size);
        return new Buff(rand, size);
    }
    constructor(data, size, endian) {
        const buffer$1 = buffer(data, size, endian);
        super(buffer$1);
    }
    get arr() {
        return [...this];
    }
    get num() {
        return this.toNum();
    }
    get big() {
        return this.toBig();
    }
    get str() {
        return this.toStr();
    }
    get hex() {
        return this.toHex();
    }
    get raw() {
        return new Uint8Array(this);
    }
    get bin() {
        return this.toBin();
    }
    get b58chk() {
        return this.tob58chk();
    }
    get base64() {
        return this.toBase64();
    }
    get b64url() {
        return this.toB64url();
    }
    get digest() {
        return this.toHash();
    }
    get id() {
        return this.toHash().hex;
    }
    get stream() {
        return new Stream(this);
    }
    toNum(endian = 'be') {
        const bytes = (endian === 'be')
            ? this.reverse()
            : this;
        return bytesToNum(bytes);
    }
    toBin() {
        return bytesToBin(this);
    }
    toBig(endian = 'be') {
        const bytes = (endian === 'be')
            ? this.reverse()
            : this;
        return bytesToBig(bytes);
    }
    toHash() {
        const digest = sha256$2(this);
        return new Buff(digest);
    }
    toJson() {
        const str = bytesToStr(this);
        return JSON.parse(str);
    }
    toBech32(hrp, version = 0) {
        return Bech32.encode(this, hrp, version);
    }
    toStr() { return bytesToStr(this); }
    toHex() { return bytesToHex(this); }
    toBytes() { return new Uint8Array(this); }
    tob58chk() { return Base58C.encode(this); }
    toBase64() { return Base64.encode(this); }
    toB64url() { return B64URL.encode(this); }
    prepend(data) {
        return Buff.join([Buff.bytes(data), this]);
    }
    append(data) {
        return Buff.join([this, Buff.bytes(data)]);
    }
    slice(start, end) {
        const arr = new Uint8Array(this).slice(start, end);
        return new Buff(arr);
    }
    subarray(begin, end) {
        const arr = new Uint8Array(this).subarray(begin, end);
        return new Buff(arr);
    }
    reverse() {
        const arr = new Uint8Array(this).reverse();
        return new Buff(arr);
    }
    write(bytes, offset) {
        const b = Buff.bytes(bytes);
        this.set(b, offset);
    }
    prefixSize(endian) {
        const size = Buff.varInt(this.length, endian);
        return Buff.join([size, this]);
    }
    static from(data) {
        return new Buff(Uint8Array.from(data));
    }
    static of(...args) {
        return new Buff(Uint8Array.of(...args));
    }
    static join(arr) {
        const bytes = arr.map(e => Buff.bytes(e));
        const joined = join_array(bytes);
        return new Buff(joined);
    }
    static varInt(num, endian) {
        if (num < 0xFD) {
            return Buff.num(num, 1);
        }
        else if (num < 0x10000) {
            return Buff.of(0xFD, ...Buff.num(num, 2, endian));
        }
        else if (num < 0x100000000) {
            return Buff.of(0xFE, ...Buff.num(num, 4, endian));
        }
        else if (BigInt(num) < 0x10000000000000000n) {
            return Buff.of(0xFF, ...Buff.num(num, 8, endian));
        }
        else {
            throw new Error(`Value is too large: ${num}`);
        }
    }
}
function numToBuff(number, size, endian) {
    return new Buff(number, size, endian);
}
function binToBuff(data, size, endian) {
    return new Buff(binToBytes(data), size, endian);
}
function bigToBuff(bigint, size, endian) {
    return new Buff(bigint, size, endian);
}
function rawToBuff(data, size, endian) {
    return new Buff(data, size, endian);
}
function strToBuff(data, size, endian) {
    return new Buff(strToBytes(data), size, endian);
}
function hexToBuff(data, size, endian) {
    return new Buff(data, size, endian);
}
function bytesToBuff(data, size, endian) {
    return new Buff(data, size, endian);
}
function jsonToBuff(data) {
    return new Buff(jsonToBytes(data));
}
function base64ToBuff(data) {
    return new Buff(Base64.decode(data));
}
function b64urlToBuff(data) {
    return new Buff(B64URL.decode(data));
}
function bech32ToBuff(data) {
    return new Buff(Bech32.decode(data));
}
function b58chkToBuff(data) {
    return new Buff(Base58C.decode(data));
}
class Stream {
    constructor(data) {
        this.data = Buff.bytes(data);
        this.size = this.data.length;
    }
    peek(size) {
        if (size > this.size) {
            throw new Error(`Size greater than stream: ${size} > ${this.size}`);
        }
        return new Buff(this.data.slice(0, size));
    }
    read(size) {
        size = size ?? this.readSize();
        const chunk = this.peek(size);
        this.data = this.data.slice(size);
        this.size = this.data.length;
        return chunk;
    }
    readSize(endian) {
        const num = this.read(1).num;
        switch (true) {
            case (num >= 0 && num < 0xFD):
                return num;
            case (num === 0xFD):
                return this.read(2).toNum(endian);
            case (num === 0xFE):
                return this.read(4).toNum(endian);
            case (num === 0xFF):
                return this.read(8).toNum(endian);
            default:
                throw new Error(`Varint is out of range: ${num}`);
        }
    }
}

const curve = secp256k1.CURVE;
const N$1 = curve.n;
const P$1 = curve.p;
const G = { x: curve.Gx, y: curve.Gy };
const _0n$2 = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _4n = BigInt(4);
const CONST = { N: N$1, P: P$1, G, _0n: _0n$2, _1n, _2n, _3n, _4n };
const ecc = Field$1(N$1, 32, true);
const modN = (x) => mod(x, N$1);

function fail(error, throws = false) {
    if (throws) {
        throw new Error(error);
    }
    else {
        return false;
    }
}
function random(size) {
    return Buff.random(size);
}
function mod_bytes(bytes) {
    const b = Buff.bytes(bytes).big;
    return Buff.big(modN(b), 32);
}

var utl = /*#__PURE__*/Object.freeze({
    __proto__: null,
    fail: fail,
    mod_bytes: mod_bytes,
    random: random
});

const { N, P, _0n: _0n$1 } = CONST;
function size(input, size, throws) {
    const bytes = Buff.bytes(input);
    if (bytes.length !== size) {
        return fail(`Invalid byte size: ${bytes.hex} !== ${size}`, throws);
    }
    return true;
}
function in_field(x, throws) {
    if (!(typeof x === 'bigint' && _0n$1 < x && x < N)) {
        fail('x value is not in the field!', throws);
    }
    return true;
}

const NoblePoint = secp256k1.ProjectivePoint;
class Field extends Uint8Array {
    static { this.N = secp256k1.CURVE.n; }
    static mod(x) {
        return new Field(x);
    }
    static is_valid(value, throws) {
        const big = Buff.bytes(value, 32).big;
        return in_field(big, throws);
    }
    constructor(x) {
        let b = normalizeField(x);
        b = modN(b);
        Field.is_valid(b, true);
        super(Buff.big(b, 32), 32);
    }
    get buff() {
        return new Buff(this);
    }
    get raw() {
        return this.buff.raw;
    }
    get big() {
        return this.buff.big;
    }
    get hex() {
        return this.buff.hex;
    }
    get point() {
        return this.generate();
    }
    get hasOddY() {
        return this.point.hasOddY;
    }
    get negated() {
        return (this.hasOddY)
            ? this.negate()
            : this;
    }
    gt(value) {
        const x = new Field(value);
        return x.big > this.big;
    }
    lt(value) {
        const x = new Field(value);
        return x.big < this.big;
    }
    eq(value) {
        const x = new Field(value);
        return x.big === this.big;
    }
    ne(value) {
        const x = new Field(value);
        return x.big !== this.big;
    }
    add(value) {
        const x = Field.mod(value);
        const a = ecc.add(this.big, x.big);
        return new Field(a);
    }
    sub(value) {
        const x = Field.mod(value);
        const a = ecc.sub(this.big, x.big);
        return new Field(a);
    }
    mul(value) {
        const x = Field.mod(value);
        const a = ecc.mul(this.big, x.big);
        return new Field(a);
    }
    pow(value) {
        const x = Field.mod(value);
        const a = ecc.pow(this.big, x.big);
        return new Field(a);
    }
    div(value) {
        const x = Field.mod(value);
        const a = ecc.div(this.big, x.big);
        return new Field(a);
    }
    negate() {
        return new Field(Field.N - this.big);
    }
    generate() {
        const base = secp256k1.ProjectivePoint.BASE;
        const point = base.multiply(this.big);
        return Point.import(point);
    }
}
class Point {
    static { this.P = CONST.P; }
    static { this.G = CONST.G; }
    static { this.base = secp256k1.ProjectivePoint.BASE; }
    static from_x(bytes) {
        let cp = normalizePoint(bytes);
        if (cp.length === 32) {
            cp = cp.prepend(0x02);
        }
        size(cp, 33);
        const point = NoblePoint.fromHex(cp.hex);
        point.assertValidity();
        return new Point(point.x, point.y);
    }
    static generate(value) {
        const field = Field.mod(value);
        const point = Point.base.multiply(field.big);
        return Point.import(point);
    }
    static import(point) {
        const p = (point instanceof Point)
            ? { x: point.x.big, y: point.y.big }
            : { x: point.x, y: point.y };
        return new Point(p.x, p.y);
    }
    constructor(x, y) {
        this._p = new NoblePoint(x, y, 1n);
        this.p.assertValidity();
    }
    get p() {
        return this._p;
    }
    get x() {
        return Buff.big(this.p.x, 32);
    }
    get y() {
        return Buff.big(this.p.y, 32);
    }
    get buff() {
        return Buff.raw(this.p.toRawBytes(true));
    }
    get raw() {
        return this.buff.raw;
    }
    get hex() {
        return this.buff.hex;
    }
    get hasEvenY() {
        return this.p.hasEvenY();
    }
    get hasOddY() {
        return !this.p.hasEvenY();
    }
    eq(value) {
        const p = (value instanceof Point) ? value : Point.from_x(value);
        return this.x.big === p.x.big && this.y.big === p.y.big;
    }
    add(x) {
        return (x instanceof Point)
            ? Point.import(this.p.add(x.p))
            : Point.import(this.p.add(Point.generate(x).p));
    }
    sub(x) {
        return (x instanceof Point)
            ? Point.import(this.p.subtract(x.p))
            : Point.import(this.p.subtract(Point.generate(x).p));
    }
    mul(value) {
        return (value instanceof Point)
            ? Point.import(this.p.multiply(value.x.big))
            : Point.import(this.p.multiply(Field.mod(value).big));
    }
    negate() {
        return Point.import(this.p.negate());
    }
}
function normalizeField(value) {
    if (value instanceof Field) {
        return value.big;
    }
    if (value instanceof Point) {
        return value.x.big;
    }
    if (value instanceof Uint8Array) {
        return Buff.raw(value).big;
    }
    if (typeof value === 'string') {
        return Buff.hex(value).big;
    }
    if (typeof value === 'number') {
        return Buff.num(value).big;
    }
    if (typeof value === 'bigint') {
        return BigInt(value);
    }
    throw TypeError('Invalid input type:' + typeof value);
}
function normalizePoint(value) {
    if (value instanceof Field) {
        return value.point.buff;
    }
    if (value instanceof Point) {
        return value.buff;
    }
    if (value instanceof Uint8Array ||
        typeof value === 'string') {
        return Buff.bytes(value);
    }
    if (typeof value === 'number' ||
        typeof value === 'bigint') {
        return Buff.bytes(value, 32);
    }
    throw new TypeError(`Unknown type: ${typeof value}`);
}

function number(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`Wrong positive integer: ${n}`);
}
function bool(b) {
    if (typeof b !== 'boolean')
        throw new Error(`Expected boolean, not ${b}`);
}
function bytes(b, ...lengths) {
    if (!(b instanceof Uint8Array))
        throw new Error('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
function hash$1(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number(hash.outputLen);
    number(hash.blockLen);
}
function exists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
function output(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
const assert = {
    number,
    bool,
    bytes,
    hash: hash$1,
    exists,
    output,
};
var assert$1 = assert;

/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.json#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated, we can just drop the import.
const u8a = (a) => a instanceof Uint8Array;
// Cast array to view
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
// The rotate right (circular right shift) operation for uint32
const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
// big-endian hardware is rare. Just in case someone still decides to run hashes:
// early-throw an error because we don't support BE yet.
const isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
if (!isLE)
    throw new Error('Non little-endian hardware is not supported');
Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
/**
 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
 */
function utf8ToBytes(str) {
    if (typeof str !== 'string')
        throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
function toBytes$3(data) {
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    if (!u8a(data))
        throw new Error(`expected Uint8Array, got ${typeof data}`);
    return data;
}
// For runtime check if class implements interface
class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
}
function wrapConstructor(hashCons) {
    const hashC = (msg) => hashCons().update(toBytes$3(msg)).digest();
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashCons();
    return hashC;
}

// Polyfill for Safari 14
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
class SHA2 extends Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView(this.buffer);
    }
    update(data) {
        assert$1.exists(this);
        const { view, buffer, blockLen } = this;
        data = toBytes$3(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = createView(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        assert$1.exists(this);
        assert$1.output(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = createView(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
}

// Choice: a ? b : c
const Chi = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W = new Uint32Array(64);
class SHA256 extends SHA2 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV[0] | 0;
        this.B = IV[1] | 0;
        this.C = IV[2] | 0;
        this.D = IV[3] | 0;
        this.E = IV[4] | 0;
        this.F = IV[5] | 0;
        this.G = IV[6] | 0;
        this.H = IV[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = (sigma0 + Maj(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
}
// Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class SHA224 extends SHA256 {
    constructor() {
        super();
        this.A = 0xc1059ed8 | 0;
        this.B = 0x367cd507 | 0;
        this.C = 0x3070dd17 | 0;
        this.D = 0xf70e5939 | 0;
        this.E = 0xffc00b31 | 0;
        this.F = 0x68581511 | 0;
        this.G = 0x64f98fa7 | 0;
        this.H = 0xbefa4fa4 | 0;
        this.outputLen = 28;
    }
}
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
const sha256$1 = wrapConstructor(() => new SHA256());
wrapConstructor(() => new SHA224());

const U32_MASK64 = BigInt(2 ** 32 - 1);
const _32n = BigInt(32);
// We are not using BigUint64Array, because they are extremely slow as per 2022
function fromBig(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
    let Ah = new Uint32Array(lst.length);
    let Al = new Uint32Array(lst.length);
    for (let i = 0; i < lst.length; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
// for Shift in [0, 32)
const shrSH = (h, l, s) => h >>> s;
const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in [1, 32)
const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
// Right rotate for shift===32 (just swaps l&h)
const rotr32H = (h, l) => l;
const rotr32L = (h, l) => h;
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
// JS uses 32-bit signed integers for bitwise operations which means we cannot
// simple take carry out of low bit sum by shift, we need to use division.
// Removing "export" has 5% perf penalty -_-
function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
}
// Addition with more than 2 elements
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
// prettier-ignore
const u64 = {
    fromBig, split, toBig,
    shrSH, shrSL,
    rotrSH, rotrSL, rotrBH, rotrBL,
    rotr32H, rotr32L,
    rotlSH, rotlSL, rotlBH, rotlBL,
    add, add3L, add3H, add4L, add4H, add5H, add5L,
};
var u64$1 = u64;

// Round contants (first 32 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
// prettier-ignore
const [SHA512_Kh, SHA512_Kl] = u64$1.split([
    '0x428a2f98d728ae22', '0x7137449123ef65cd', '0xb5c0fbcfec4d3b2f', '0xe9b5dba58189dbbc',
    '0x3956c25bf348b538', '0x59f111f1b605d019', '0x923f82a4af194f9b', '0xab1c5ed5da6d8118',
    '0xd807aa98a3030242', '0x12835b0145706fbe', '0x243185be4ee4b28c', '0x550c7dc3d5ffb4e2',
    '0x72be5d74f27b896f', '0x80deb1fe3b1696b1', '0x9bdc06a725c71235', '0xc19bf174cf692694',
    '0xe49b69c19ef14ad2', '0xefbe4786384f25e3', '0x0fc19dc68b8cd5b5', '0x240ca1cc77ac9c65',
    '0x2de92c6f592b0275', '0x4a7484aa6ea6e483', '0x5cb0a9dcbd41fbd4', '0x76f988da831153b5',
    '0x983e5152ee66dfab', '0xa831c66d2db43210', '0xb00327c898fb213f', '0xbf597fc7beef0ee4',
    '0xc6e00bf33da88fc2', '0xd5a79147930aa725', '0x06ca6351e003826f', '0x142929670a0e6e70',
    '0x27b70a8546d22ffc', '0x2e1b21385c26c926', '0x4d2c6dfc5ac42aed', '0x53380d139d95b3df',
    '0x650a73548baf63de', '0x766a0abb3c77b2a8', '0x81c2c92e47edaee6', '0x92722c851482353b',
    '0xa2bfe8a14cf10364', '0xa81a664bbc423001', '0xc24b8b70d0f89791', '0xc76c51a30654be30',
    '0xd192e819d6ef5218', '0xd69906245565a910', '0xf40e35855771202a', '0x106aa07032bbd1b8',
    '0x19a4c116b8d2d0c8', '0x1e376c085141ab53', '0x2748774cdf8eeb99', '0x34b0bcb5e19b48a8',
    '0x391c0cb3c5c95a63', '0x4ed8aa4ae3418acb', '0x5b9cca4f7763e373', '0x682e6ff3d6b2b8a3',
    '0x748f82ee5defb2fc', '0x78a5636f43172f60', '0x84c87814a1f0ab72', '0x8cc702081a6439ec',
    '0x90befffa23631e28', '0xa4506cebde82bde9', '0xbef9a3f7b2c67915', '0xc67178f2e372532b',
    '0xca273eceea26619c', '0xd186b8c721c0c207', '0xeada7dd6cde0eb1e', '0xf57d4f7fee6ed178',
    '0x06f067aa72176fba', '0x0a637dc5a2c898a6', '0x113f9804bef90dae', '0x1b710b35131c471b',
    '0x28db77f523047d84', '0x32caab7b40c72493', '0x3c9ebe0a15c9bebc', '0x431d67c49c100d4c',
    '0x4cc5d4becb3e42b6', '0x597f299cfc657e2a', '0x5fcb6fab3ad6faec', '0x6c44198c4a475817'
].map(n => BigInt(n)));
// Temporary buffer, not used to store anything between runs
const SHA512_W_H = new Uint32Array(80);
const SHA512_W_L = new Uint32Array(80);
class SHA512 extends SHA2 {
    constructor() {
        super(128, 64, 16, false);
        // We cannot use array here since array allows indexing by variable which means optimizer/compiler cannot use registers.
        // Also looks cleaner and easier to verify with spec.
        // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0x6a09e667 | 0;
        this.Al = 0xf3bcc908 | 0;
        this.Bh = 0xbb67ae85 | 0;
        this.Bl = 0x84caa73b | 0;
        this.Ch = 0x3c6ef372 | 0;
        this.Cl = 0xfe94f82b | 0;
        this.Dh = 0xa54ff53a | 0;
        this.Dl = 0x5f1d36f1 | 0;
        this.Eh = 0x510e527f | 0;
        this.El = 0xade682d1 | 0;
        this.Fh = 0x9b05688c | 0;
        this.Fl = 0x2b3e6c1f | 0;
        this.Gh = 0x1f83d9ab | 0;
        this.Gl = 0xfb41bd6b | 0;
        this.Hh = 0x5be0cd19 | 0;
        this.Hl = 0x137e2179 | 0;
    }
    // prettier-ignore
    get() {
        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
    }
    // prettier-ignore
    set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
        this.Ah = Ah | 0;
        this.Al = Al | 0;
        this.Bh = Bh | 0;
        this.Bl = Bl | 0;
        this.Ch = Ch | 0;
        this.Cl = Cl | 0;
        this.Dh = Dh | 0;
        this.Dl = Dl | 0;
        this.Eh = Eh | 0;
        this.El = El | 0;
        this.Fh = Fh | 0;
        this.Fl = Fl | 0;
        this.Gh = Gh | 0;
        this.Gl = Gl | 0;
        this.Hh = Hh | 0;
        this.Hl = Hl | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4) {
            SHA512_W_H[i] = view.getUint32(offset);
            SHA512_W_L[i] = view.getUint32((offset += 4));
        }
        for (let i = 16; i < 80; i++) {
            // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
            const W15h = SHA512_W_H[i - 15] | 0;
            const W15l = SHA512_W_L[i - 15] | 0;
            const s0h = u64$1.rotrSH(W15h, W15l, 1) ^ u64$1.rotrSH(W15h, W15l, 8) ^ u64$1.shrSH(W15h, W15l, 7);
            const s0l = u64$1.rotrSL(W15h, W15l, 1) ^ u64$1.rotrSL(W15h, W15l, 8) ^ u64$1.shrSL(W15h, W15l, 7);
            // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
            const W2h = SHA512_W_H[i - 2] | 0;
            const W2l = SHA512_W_L[i - 2] | 0;
            const s1h = u64$1.rotrSH(W2h, W2l, 19) ^ u64$1.rotrBH(W2h, W2l, 61) ^ u64$1.shrSH(W2h, W2l, 6);
            const s1l = u64$1.rotrSL(W2h, W2l, 19) ^ u64$1.rotrBL(W2h, W2l, 61) ^ u64$1.shrSL(W2h, W2l, 6);
            // SHA256_W[i] = s0 + s1 + SHA256_W[i - 7] + SHA256_W[i - 16];
            const SUMl = u64$1.add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
            const SUMh = u64$1.add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
            SHA512_W_H[i] = SUMh | 0;
            SHA512_W_L[i] = SUMl | 0;
        }
        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        // Compression function main loop, 80 rounds
        for (let i = 0; i < 80; i++) {
            // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
            const sigma1h = u64$1.rotrSH(Eh, El, 14) ^ u64$1.rotrSH(Eh, El, 18) ^ u64$1.rotrBH(Eh, El, 41);
            const sigma1l = u64$1.rotrSL(Eh, El, 14) ^ u64$1.rotrSL(Eh, El, 18) ^ u64$1.rotrBL(Eh, El, 41);
            //const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const CHIh = (Eh & Fh) ^ (~Eh & Gh);
            const CHIl = (El & Fl) ^ (~El & Gl);
            // T1 = H + sigma1 + Chi(E, F, G) + SHA512_K[i] + SHA512_W[i]
            // prettier-ignore
            const T1ll = u64$1.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
            const T1h = u64$1.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
            const T1l = T1ll | 0;
            // S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
            const sigma0h = u64$1.rotrSH(Ah, Al, 28) ^ u64$1.rotrBH(Ah, Al, 34) ^ u64$1.rotrBH(Ah, Al, 39);
            const sigma0l = u64$1.rotrSL(Ah, Al, 28) ^ u64$1.rotrBL(Ah, Al, 34) ^ u64$1.rotrBL(Ah, Al, 39);
            const MAJh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch);
            const MAJl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl);
            Hh = Gh | 0;
            Hl = Gl | 0;
            Gh = Fh | 0;
            Gl = Fl | 0;
            Fh = Eh | 0;
            Fl = El | 0;
            ({ h: Eh, l: El } = u64$1.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
            Dh = Ch | 0;
            Dl = Cl | 0;
            Ch = Bh | 0;
            Cl = Bl | 0;
            Bh = Ah | 0;
            Bl = Al | 0;
            const All = u64$1.add3L(T1l, sigma0l, MAJl);
            Ah = u64$1.add3H(All, T1h, sigma0h, MAJh);
            Al = All | 0;
        }
        // Add the compressed chunk to the current hash value
        ({ h: Ah, l: Al } = u64$1.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
        ({ h: Bh, l: Bl } = u64$1.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
        ({ h: Ch, l: Cl } = u64$1.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
        ({ h: Dh, l: Dl } = u64$1.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
        ({ h: Eh, l: El } = u64$1.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
        ({ h: Fh, l: Fl } = u64$1.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
        ({ h: Gh, l: Gl } = u64$1.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
        ({ h: Hh, l: Hl } = u64$1.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
    }
    roundClean() {
        SHA512_W_H.fill(0);
        SHA512_W_L.fill(0);
    }
    destroy() {
        this.buffer.fill(0);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
}
class SHA512_224 extends SHA512 {
    constructor() {
        super();
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0x8c3d37c8 | 0;
        this.Al = 0x19544da2 | 0;
        this.Bh = 0x73e19966 | 0;
        this.Bl = 0x89dcd4d6 | 0;
        this.Ch = 0x1dfab7ae | 0;
        this.Cl = 0x32ff9c82 | 0;
        this.Dh = 0x679dd514 | 0;
        this.Dl = 0x582f9fcf | 0;
        this.Eh = 0x0f6d2b69 | 0;
        this.El = 0x7bd44da8 | 0;
        this.Fh = 0x77e36f73 | 0;
        this.Fl = 0x04c48942 | 0;
        this.Gh = 0x3f9d85a8 | 0;
        this.Gl = 0x6a1d36c8 | 0;
        this.Hh = 0x1112e6ad | 0;
        this.Hl = 0x91d692a1 | 0;
        this.outputLen = 28;
    }
}
class SHA512_256 extends SHA512 {
    constructor() {
        super();
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0x22312194 | 0;
        this.Al = 0xfc2bf72c | 0;
        this.Bh = 0x9f555fa3 | 0;
        this.Bl = 0xc84c64c2 | 0;
        this.Ch = 0x2393b86b | 0;
        this.Cl = 0x6f53b151 | 0;
        this.Dh = 0x96387719 | 0;
        this.Dl = 0x5940eabd | 0;
        this.Eh = 0x96283ee2 | 0;
        this.El = 0xa88effe3 | 0;
        this.Fh = 0xbe5e1e25 | 0;
        this.Fl = 0x53863992 | 0;
        this.Gh = 0x2b0199fc | 0;
        this.Gl = 0x2c85b8aa | 0;
        this.Hh = 0x0eb72ddc | 0;
        this.Hl = 0x81c52ca2 | 0;
        this.outputLen = 32;
    }
}
class SHA384 extends SHA512 {
    constructor() {
        super();
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0xcbbb9d5d | 0;
        this.Al = 0xc1059ed8 | 0;
        this.Bh = 0x629a292a | 0;
        this.Bl = 0x367cd507 | 0;
        this.Ch = 0x9159015a | 0;
        this.Cl = 0x3070dd17 | 0;
        this.Dh = 0x152fecd8 | 0;
        this.Dl = 0xf70e5939 | 0;
        this.Eh = 0x67332667 | 0;
        this.El = 0xffc00b31 | 0;
        this.Fh = 0x8eb44a87 | 0;
        this.Fl = 0x68581511 | 0;
        this.Gh = 0xdb0c2e0d | 0;
        this.Gl = 0x64f98fa7 | 0;
        this.Hh = 0x47b5481d | 0;
        this.Hl = 0xbefa4fa4 | 0;
        this.outputLen = 48;
    }
}
const sha512$1 = wrapConstructor(() => new SHA512());
wrapConstructor(() => new SHA512_224());
wrapConstructor(() => new SHA512_256());
wrapConstructor(() => new SHA384());

// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
// https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
const Rho = new Uint8Array([7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]);
const Id = Uint8Array.from({ length: 16 }, (_, i) => i);
const Pi = Id.map((i) => (9 * i + 5) % 16);
let idxL = [Id];
let idxR = [Pi];
for (let i = 0; i < 4; i++)
    for (let j of [idxL, idxR])
        j.push(j[i].map((k) => Rho[k]));
const shifts = [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
    [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
    [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
    [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5],
].map((i) => new Uint8Array(i));
const shiftsL = idxL.map((idx, i) => idx.map((j) => shifts[i][j]));
const shiftsR = idxR.map((idx, i) => idx.map((j) => shifts[i][j]));
const Kl = new Uint32Array([0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]);
const Kr = new Uint32Array([0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000]);
// The rotate left (circular left shift) operation for uint32
const rotl = (word, shift) => (word << shift) | (word >>> (32 - shift));
// It's called f() in spec.
function f(group, x, y, z) {
    if (group === 0)
        return x ^ y ^ z;
    else if (group === 1)
        return (x & y) | (~x & z);
    else if (group === 2)
        return (x | ~y) ^ z;
    else if (group === 3)
        return (x & z) | (y & ~z);
    else
        return x ^ (y | ~z);
}
// Temporary buffer, not used to store anything between runs
const BUF = new Uint32Array(16);
class RIPEMD160 extends SHA2 {
    constructor() {
        super(64, 20, 8, true);
        this.h0 = 0x67452301 | 0;
        this.h1 = 0xefcdab89 | 0;
        this.h2 = 0x98badcfe | 0;
        this.h3 = 0x10325476 | 0;
        this.h4 = 0xc3d2e1f0 | 0;
    }
    get() {
        const { h0, h1, h2, h3, h4 } = this;
        return [h0, h1, h2, h3, h4];
    }
    set(h0, h1, h2, h3, h4) {
        this.h0 = h0 | 0;
        this.h1 = h1 | 0;
        this.h2 = h2 | 0;
        this.h3 = h3 | 0;
        this.h4 = h4 | 0;
    }
    process(view, offset) {
        for (let i = 0; i < 16; i++, offset += 4)
            BUF[i] = view.getUint32(offset, true);
        // prettier-ignore
        let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
        // Instead of iterating 0 to 80, we split it into 5 groups
        // And use the groups in constants, functions, etc. Much simpler
        for (let group = 0; group < 5; group++) {
            const rGroup = 4 - group;
            const hbl = Kl[group], hbr = Kr[group]; // prettier-ignore
            const rl = idxL[group], rr = idxR[group]; // prettier-ignore
            const sl = shiftsL[group], sr = shiftsR[group]; // prettier-ignore
            for (let i = 0; i < 16; i++) {
                const tl = (rotl(al + f(group, bl, cl, dl) + BUF[rl[i]] + hbl, sl[i]) + el) | 0;
                al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl; // prettier-ignore
            }
            // 2 loops are 10% faster
            for (let i = 0; i < 16; i++) {
                const tr = (rotl(ar + f(rGroup, br, cr, dr) + BUF[rr[i]] + hbr, sr[i]) + er) | 0;
                ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr; // prettier-ignore
            }
        }
        // Add the compressed chunk to the current hash value
        this.set((this.h1 + cl + dr) | 0, (this.h2 + dl + er) | 0, (this.h3 + el + ar) | 0, (this.h4 + al + br) | 0, (this.h0 + bl + cr) | 0);
    }
    roundClean() {
        BUF.fill(0);
    }
    destroy() {
        this.destroyed = true;
        this.buffer.fill(0);
        this.set(0, 0, 0, 0, 0);
    }
}
/**
 * RIPEMD-160 - a hash function from 1990s.
 * @param message - msg that would be hashed
 */
const ripemd160 = wrapConstructor(() => new RIPEMD160());

// HMAC (RFC 2104)
class HMAC extends Hash {
    constructor(hash, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        assert$1.hash(hash);
        const key = toBytes$3(_key);
        this.iHash = hash.create();
        if (typeof this.iHash.update !== 'function')
            throw new Error('Expected instance of class which extends utils.Hash');
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        // blockLen can be bigger than outputLen
        pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36;
        this.iHash.update(pad);
        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
        this.oHash = hash.create();
        // Undo internal XOR && apply outer XOR
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36 ^ 0x5c;
        this.oHash.update(pad);
        pad.fill(0);
    }
    update(buf) {
        assert$1.exists(this);
        this.iHash.update(buf);
        return this;
    }
    digestInto(out) {
        assert$1.exists(this);
        assert$1.bytes(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
    }
    _cloneInto(to) {
        // Create new instance without calling constructor since key already in state and we don't know it.
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
    }
    destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
    }
}
/**
 * HMAC: RFC2104 message authentication code.
 * @param hash - function that would be used e.g. sha256
 * @param key - message key
 * @param message - message data
 */
const hmac$1 = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac$1.create = (hash, key) => new HMAC(hash, key);

function sha256(msg) {
    const b = Buff.bytes(msg);
    return Buff.raw(sha256$1(b));
}
function hash256(msg) {
    const b = Buff.bytes(msg);
    return Buff.raw(sha256$1(sha256$1(b)));
}
function hash160(msg) {
    const b = Buff.bytes(msg);
    return Buff.raw(ripemd160(sha256$1(b)));
}
function hmac512(key, msg) {
    const k = Buff.bytes(key);
    const b = Buff.bytes(msg);
    return Buff.raw(hmac$1(sha512$1, k, b));
}
function hashtag(tag) {
    const hash = Buff.str(tag).digest;
    return Buff.join([hash, hash]);
}

function genSecretKey(size = 32) {
    return getSecretKey(random(size));
}
function getSecretKey(secret) {
    return Field.mod(secret).buff;
}
function getPublicKey(seckey, xonly = false) {
    const p = Field.mod(seckey).point;
    return (xonly) ? p.x : p.buff;
}
function getSharedKey(seckey, pubkey) {
    const P = Point.from_x(pubkey);
    const sp = Field.mod(seckey);
    const sh = P.mul(sp);
    return sh.buff;
}
function getSharedCode(self_sec, peer_pub, tag = 'ecdh/code') {
    const hash = hashtag(tag);
    const sec = getSecretKey(self_sec);
    const pub = getPublicKey(sec);
    const peer = Buff.bytes(peer_pub);
    const link = getSharedKey(sec, peer);
    const keys = [pub.hex, peer.hex];
    keys.sort();
    return hmac512(link, Buff.join([hash, ...keys]));
}
function is_even_pub(pubkey) {
    const pub = Buff.bytes(pubkey);
    switch (true) {
        case (pub.length === 32):
            return true;
        case (pub.length === 33 && pub[0] === 0x02):
            return true;
        case (pub.length === 33 && pub[0] === 0x03):
            return false;
        default:
            throw new TypeError(`Invalid public key: ${pub.hex}`);
    }
}
function xonly_pub(pubkey) {
    const key = Buff.bytes(pubkey);
    switch (key.length) {
        case 32:
            return key;
        case 33:
            return key.slice(1, 33);
        default:
            throw new Error(`Invalid key length: ${key.length}`);
    }
}

var key = /*#__PURE__*/Object.freeze({
    __proto__: null,
    genSecretKey: genSecretKey,
    getPublicKey: getPublicKey,
    getSecretKey: getSecretKey,
    getSharedCode: getSharedCode,
    getSharedKey: getSharedKey,
    is_even_pub: is_even_pub,
    xonly_pub: xonly_pub
});

({
    aux: Buff.random(32),
    throws: false,
    xonly: true
});

const noble = { secp: secp256k1, schnorr };
const util$1 = { ...key, ...utl };

function hash160pkh(pubkey) {
    const bytes = Buff$1.bytes(pubkey);
    checkSize(bytes, 33);
    return hash160(bytes);
}
function hash160sh(script) {
    const bytes = Script.fmt.toBytes(script, false);
    return hash160(bytes);
}
function sha256sh(script) {
    const bytes = Script.fmt.toBytes(script, false);
    return sha256(bytes);
}

function check$4(address, network = 'main') {
    const prefixes = (network === 'main') ? ['1'] : ['m', 'n'];
    for (const prefix of prefixes) {
        if (address.startsWith(prefix)) {
            return true;
        }
    }
    return false;
}
function encode$4(input, network = 'main') {
    const bytes = Buff$1.bytes(input);
    const prefix = (network === 'main') ? Buff$1.num(0x00) : Buff$1.num(0x6F);
    checkSize(input, 20);
    return bytes.prepend(prefix).tob58chk();
}
function decode$4(address, network = 'main') {
    if (!check$4(address, network)) {
        throw new TypeError('Invalid p2pkh address!');
    }
    return Buff$1.b58chk(address).slice(1);
}
function scriptPubKey$4(input) {
    const bytes = Buff$1.bytes(input);
    checkSize(bytes, 20);
    return ['OP_DUP', 'OP_HASH160', bytes.hex, 'OP_EQUALVERIFY', 'OP_CHECKSIG'];
}
function fromPubKey$2(pubkey, network) {
    const pkh = hash160pkh(pubkey);
    return encode$4(pkh, network);
}
const P2PKH = { check: check$4, encode: encode$4, decode: decode$4, hash: hash160pkh, scriptPubKey: scriptPubKey$4, fromPubKey: fromPubKey$2 };

function check$3(address, network = 'main') {
    const prefixes = (network === 'main') ? ['3'] : ['2'];
    for (const prefix of prefixes) {
        if (address.startsWith(prefix)) {
            return true;
        }
    }
    return false;
}
function encode$3(input, network = 'main') {
    const prefix = (network === 'main') ? Buff$1.num(0x05) : Buff$1.num(0xC4);
    const bytes = Buff$1.bytes(input);
    checkSize(bytes, 20);
    return bytes.prepend(prefix).tob58chk();
}
function decode$3(address, network = 'main') {
    if (!check$3(address, network)) {
        throw new TypeError(`Invalid p2sh address for network ${network}:` + address);
    }
    return Buff$1.b58chk(address).slice(1);
}
function scriptPubKey$3(input) {
    const bytes = Buff$1.bytes(input);
    return ['OP_HASH160', bytes.hex, 'OP_EQUAL'];
}
function fromScript$1(script, network) {
    const scriptHash = hash160sh(script);
    return encode$3(scriptHash, network);
}
const P2SH = { check: check$3, encode: encode$3, decode: decode$3, hash: hash160sh, scriptPubKey: scriptPubKey$3, fromScript: fromScript$1 };

const BECH32_PREFIXES = {
    main: 'bc',
    testnet: 'tb',
    signet: 'tb',
    regtest: 'bcrt'
};

const VALID_PREFIXES$2 = ['bc1q', 'tb1q', 'bcrt1q'];
function check$2(address) {
    for (const prefix of VALID_PREFIXES$2) {
        if (address.startsWith(prefix)) {
            return true;
        }
    }
    return false;
}
function encode$2(input, network = 'main') {
    const prefix = BECH32_PREFIXES[network];
    const bytes = Buff$1.bytes(input);
    checkSize(bytes, 20);
    return bytes.toBech32(prefix, 0);
}
function decode$2(address) {
    if (!check$2(address)) {
        throw new TypeError('Invalid segwit address!');
    }
    return Buff$1.bech32(address);
}
function scriptPubKey$2(input) {
    const bytes = Buff$1.bytes(input);
    checkSize(bytes, 20);
    return ['OP_0', bytes.hex];
}
function fromPubKey$1(pubkey, network) {
    const pkh = hash160pkh(pubkey);
    return encode$2(pkh, network);
}
const P2WPKH = { check: check$2, encode: encode$2, decode: decode$2, hash: hash160pkh, scriptPubKey: scriptPubKey$2, fromPubKey: fromPubKey$1 };

const VALID_PREFIXES$1 = ['bc1q', 'tb1q', 'bcrt1q'];
function check$1(address) {
    for (const prefix of VALID_PREFIXES$1) {
        if (address.startsWith(prefix)) {
            return true;
        }
    }
    return false;
}
function encode$1(input, network = 'main') {
    const prefix = BECH32_PREFIXES[network];
    const bytes = Buff$1.bytes(input);
    checkSize(bytes, 32);
    return bytes.toBech32(prefix, 0);
}
function decode$1(address) {
    if (!check$1(address)) {
        throw new TypeError('Invalid segwit address!');
    }
    return Buff$1.bech32(address);
}
function scriptPubKey$1(input) {
    const bytes = Buff$1.bytes(input);
    checkSize(bytes, 32);
    return ['OP_0', bytes.hex];
}
function fromScript(script, network) {
    const sh = sha256sh(script);
    return encode$1(sh, network);
}
const P2WSH = { check: check$1, encode: encode$1, decode: decode$1, hash: sha256sh, scriptPubKey: scriptPubKey$1, fromScript };

function xOnlyPub(key) {
    const bytes = Buff$1.bytes(key);
    return (bytes.length > 32) ? bytes.slice(1, 33) : bytes;
}

const VALID_PREFIXES = ['bc1p', 'tb1p', 'bcrt1p'];
function check(address) {
    for (const prefix of VALID_PREFIXES) {
        if (address.startsWith(prefix)) {
            return true;
        }
    }
    return false;
}
function encode(input, network = 'main') {
    const prefix = BECH32_PREFIXES[network];
    const bytes = Buff$1.bytes(input);
    checkSize(bytes, 32);
    return bytes.toBech32(prefix, 1);
}
function decode(address) {
    if (!check(address)) {
        throw new TypeError('Invalid taproot address!');
    }
    return Buff$1.bech32(address);
}
function scriptPubKey(input) {
    const bytes = Buff$1.bytes(input);
    checkSize(bytes, 32);
    return ['OP_1', bytes.hex];
}
function fromPubKey(pubkey, network) {
    const bytes = xOnlyPub(pubkey);
    return encode(bytes, network);
}
const P2TR = { check, encode, decode, scriptPubKey, fromPubKey };

const DEFAULT_TX = {
    version: 2,
    vin: [],
    vout: [],
    locktime: 0
};
const DEFAULT_VIN = {
    scriptSig: [],
    sequence: 4294967293,
    witness: []
};
const DEFAULT_VOUT = {
    value: 0n,
    scriptPubKey: []
};
function createTx(template) {
    const tx = { ...DEFAULT_TX, ...template };
    tx.vin = tx.vin.map(txin => { return { ...DEFAULT_VIN, ...txin }; });
    tx.vout = tx.vout.map(txout => { return { ...DEFAULT_VOUT, ...txout }; });
    return tx;
}

function encodeTx(txdata, omitWitness) {
    const { version, vin, vout, locktime } = createTx(txdata);
    const useWitness = (omitWitness !== true && checkForWitness(vin));
    const raw = [encodeVersion(version)];
    if (useWitness) {
        raw.push(Buff$1.hex('0001'));
    }
    raw.push(encodeInputs(vin));
    raw.push(encodeOutputs(vout));
    for (const txin of vin) {
        if (useWitness) {
            raw.push(encodeWitness(txin.witness));
        }
    }
    raw.push(encodeLocktime(locktime));
    return Buff$1.join(raw);
}
function checkForWitness(vin) {
    for (const txin of vin) {
        const { witness } = txin;
        if (typeof witness === 'string' ||
            witness instanceof Uint8Array ||
            (Array.isArray(witness) && witness.length > 0)) {
            return true;
        }
    }
    return false;
}
function encodeVersion(num) {
    return Buff$1.num(num, 4).reverse();
}
function encodeTxid(txid) {
    return Buff$1.hex(txid, 32).reverse();
}
function encodePrevOut(vout) {
    return Buff$1.num(vout, 4).reverse();
}
function encodeSequence(sequence) {
    if (typeof sequence === 'string') {
        return Buff$1.hex(sequence, 4).reverse();
    }
    if (typeof sequence === 'number') {
        return Buff$1.num(sequence, 4).reverse();
    }
    throw new Error('Unrecognized format: ' + String(sequence));
}
function encodeInputs(arr) {
    const raw = [Buff$1.varInt(arr.length)];
    for (const vin of arr) {
        const { txid, vout, scriptSig, sequence } = vin;
        raw.push(encodeTxid(txid));
        raw.push(encodePrevOut(vout));
        raw.push(encodeScript(scriptSig, true));
        raw.push(encodeSequence(sequence));
    }
    return Buff$1.join(raw);
}
function encodeValue(value) {
    if (typeof value === 'number') {
        if (value % 1 !== 0) {
            throw new Error('Value must be an integer:' + String(value));
        }
        return Buff$1.num(value, 8).reverse();
    }
    return Buff$1.big(value, 8).reverse();
}
function encodeOutputs(arr) {
    const raw = [Buff$1.varInt(arr.length)];
    for (const vout of arr) {
        raw.push(encodeOutput(vout));
    }
    return Buff$1.join(raw);
}
function encodeOutput(vout) {
    const { value, scriptPubKey } = vout;
    const raw = [];
    raw.push(encodeValue(value));
    raw.push(encodeScript(scriptPubKey, true));
    return Buff$1.join(raw);
}
function encodeWitness(data = []) {
    const buffer = [];
    if (Array.isArray(data)) {
        const count = Buff$1.varInt(data.length);
        buffer.push(count);
        for (const entry of data) {
            buffer.push(encodeData(entry));
        }
        return Buff$1.join(buffer);
    }
    else {
        return Buff$1.bytes(data);
    }
}
function encodeData(data) {
    return (!isEmpty(data))
        ? encodeScript(data, true)
        : new Buff$1(0);
}
function isEmpty(data) {
    if (Array.isArray(data)) {
        return data.length === 0;
    }
    if (typeof data === 'string') {
        if (data === '')
            return true;
    }
    const bytes = Buff$1.bytes(data);
    return bytes.length === 1 && bytes[0] === 0;
}
function encodeLocktime(locktime) {
    if (typeof locktime === 'string') {
        return Buff$1.hex(locktime, 4);
    }
    if (typeof locktime === 'number') {
        return Buff$1.num(locktime, 4).reverse();
    }
    throw new Error('Unrecognized format: ' + String(locktime));
}

function decodeTx(bytes) {
    if (typeof bytes === 'string') {
        bytes = Buff$1.hex(bytes).raw;
    }
    const stream = new Stream$1(bytes);
    const version = readVersion(stream);
    const hasWitness = checkWitnessFlag(stream);
    const vin = readInputs(stream);
    const vout = readOutputs(stream);
    if (hasWitness) {
        for (const txin of vin) {
            txin.witness = readWitness$1(stream);
        }
    }
    const locktime = readLocktime(stream);
    return { version, vin, vout, locktime };
}
function readVersion(stream) {
    return stream.read(4).reverse().toNum();
}
function checkWitnessFlag(stream) {
    const [marker, flag] = [...stream.peek(2)];
    if (marker === 0) {
        stream.read(2);
        if (flag === 1) {
            return true;
        }
        else {
            throw new Error(`Invalid witness flag: ${flag}`);
        }
    }
    return false;
}
function readInputs(stream) {
    const inputs = [];
    const vinCount = stream.readSize();
    for (let i = 0; i < vinCount; i++) {
        inputs.push(readInput(stream));
    }
    return inputs;
}
function readInput(stream) {
    return {
        txid: stream.read(32).reverse().toHex(),
        vout: stream.read(4).reverse().toNum(),
        scriptSig: readScript(stream, true),
        sequence: stream.read(4).reverse().toHex(),
        witness: []
    };
}
function readOutputs(stream) {
    const outputs = [];
    const outcount = stream.readSize();
    for (let i = 0; i < outcount; i++) {
        outputs.push(readOutput(stream));
    }
    return outputs;
}
function readOutput(stream) {
    return {
        value: stream.read(8).reverse().big,
        scriptPubKey: readScript(stream, true)
    };
}
function readWitness$1(stream) {
    const stack = [];
    const count = stream.readSize();
    for (let i = 0; i < count; i++) {
        const word = readData(stream, true);
        stack.push(word ?? '');
    }
    return stack;
}
function readData(stream, varint) {
    const size = (varint === true)
        ? stream.readSize('le')
        : stream.size;
    return size > 0
        ? stream.read(size).hex
        : null;
}
function readScript(stream, varint) {
    const data = readData(stream, varint);
    return (data !== null) ? data : [];
}
function readLocktime(stream) {
    return stream.read(4).reverse().toNum();
}

function toJson(txdata) {
    if (isBytes$1(txdata)) {
        return decodeTx(txdata);
    }
    if (typeof txdata === 'object' &&
        !(txdata instanceof Uint8Array)) {
        encodeTx(txdata);
        return createTx(txdata);
    }
    throw new Error('Invalid format: ' + String(typeof txdata));
}
function toBytes(txdata) {
    if (isBytes$1(txdata)) {
        decodeTx(txdata);
        return Buff$1.bytes(txdata);
    }
    if (typeof txdata === 'object') {
        return encodeTx(txdata);
    }
    throw new Error('Invalid format: ' + String(typeof txdata));
}
const TxFmt = {
    toBytes,
    toJson
};

const OUTPUT_TYPES = [
    ['p2pkh', /^76a914(?<hash>\w{40})88ac$/],
    ['p2sh', /^a914(?<hash>\w{40})87$/],
    ['p2w-pkh', /^0014(?<hash>\w{40})$/],
    ['p2w-sh', /^0020(?<hash>\w{64})$/],
    ['p2tr', /^5120(?<hash>\w{64})$/]
];
const LEAF_VERSIONS = [
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce,
    0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
    0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
    0x66, 0x7e, 0x80, 0x84, 0x96, 0x98, 0xba, 0xbc,
    0xbe
];
function parseAnnex(data) {
    let item = data.at(-1);
    if (isHex(item)) {
        item = Buff$1.hex(item);
    }
    if (data.length > 1 &&
        item instanceof Uint8Array &&
        item[0] === 0x50) {
        data.pop();
        return Buff$1.raw(item);
    }
    return null;
}
function parseBlock(data) {
    let item = data.at(-1);
    if (isHex(item)) {
        item = Buff$1.hex(item);
    }
    if (data.length > 1 &&
        item instanceof Uint8Array &&
        item.length > 32 &&
        LEAF_VERSIONS.includes(item[0] & 0xfe)) {
        data.pop();
        return Buff$1.raw(item);
    }
    return null;
}
function parseWitScript(data) {
    if (data.length > 1) {
        const item = data.at(-1);
        try {
            const script = Script.fmt.toBytes(item);
            data.pop();
            return script;
        }
        catch (err) {
            return null;
        }
    }
    return null;
}
function parseParams(data) {
    const params = [];
    for (const d of data) {
        if (isHex(d) ||
            d instanceof Uint8Array ||
            typeof d === 'number') {
            params.push(Buff$1.bytes(d));
        }
        else {
            throw new Error('unrecognized value: ' + String(d));
        }
    }
    return params;
}
function readWitness(data = []) {
    const items = [...data];
    const annex = parseAnnex(items);
    const cblock = parseBlock(items);
    const script = parseWitScript(items);
    const params = parseParams(items);
    return { annex, cblock, script, params };
}
function readScriptPubKey(script) {
    const hex = Script.fmt.toBytes(script, false).hex;
    for (const [keytype, pattern] of OUTPUT_TYPES) {
        const type = keytype;
        const { groups } = pattern.exec(hex) ?? {};
        const { hash } = groups ?? {};
        if (isHex(hash)) {
            return { type, data: Buff$1.hex(hash) };
        }
    }
    return { type: 'raw', data: Buff$1.hex(hex) };
}
function getTxid(txdata) {
    const json = TxFmt.toJson(txdata);
    const data = encodeTx(json, true);
    return hash256(data).reverse().hex;
}
function getTxSize(txdata) {
    const json = TxFmt.toJson(txdata);
    const bsize = encodeTx(json, true).length;
    const fsize = encodeTx(json, false).length;
    const weight = bsize * 3 + fsize;
    const remain = (weight % 4 > 0) ? 1 : 0;
    const vsize = Math.floor(weight / 4) + remain;
    return { size: fsize, bsize, vsize, weight };
}

const Tx = {
    create: createTx,
    encode: encodeTx,
    decode: decodeTx,
    fmt: TxFmt,
    util: {
        getTxSize,
        getTxid,
        readScriptPubKey,
        readWitness
    }
};

const ADDRESS_TYPES = [
    ['1', 'p2pkh', 'main', 20, 'base58'],
    ['3', 'p2sh', 'main', 20, 'base58'],
    ['m', 'p2pkh', 'testnet', 20, 'base58'],
    ['n', 'p2pkh', 'testnet', 20, 'base58'],
    ['2', 'p2sh', 'testnet', 20, 'base58'],
    ['bc1q', 'p2w-pkh', 'main', 20, 'bech32'],
    ['tb1q', 'p2w-pkh', 'testnet', 20, 'bech32'],
    ['bcrt1q', 'p2w-pkh', 'regtest', 20, 'bech32'],
    ['bc1q', 'p2w-sh', 'main', 32, 'bech32'],
    ['tb1q', 'p2w-sh', 'testnet', 32, 'bech32'],
    ['bcrt1q', 'p2w-sh', 'regtest', 32, 'bech32'],
    ['bc1p', 'p2tr', 'main', 32, 'bech32m'],
    ['tb1p', 'p2tr', 'testnet', 32, 'bech32m'],
    ['bcrt1p', 'p2tr', 'regtest', 32, 'bech32m']
];
function decodeFormat(address, format) {
    switch (format) {
        case 'base58': return Buff$1.b58chk(address).slice(1);
        case 'bech32': return Buff$1.bech32(address);
        case 'bech32m': return Buff$1.bech32(address);
        default: throw new Error('Invalid address format: ' + format);
    }
}
function getData(address) {
    for (const row of ADDRESS_TYPES) {
        const [prefix, _type, _network, size, format] = row;
        if (address.startsWith(prefix)) {
            const bytes = decodeFormat(address, format);
            if (bytes.length === size)
                return row;
        }
    }
    throw new Error('Invalid address: ' + address);
}
function getTool(type) {
    switch (type) {
        case 'p2pkh': return P2PKH;
        case 'p2sh': return P2SH;
        case 'p2w-pkh': return P2WPKH;
        case 'p2w-sh': return P2WSH;
        case 'p2tr': return P2TR;
        default: throw new Error('Invalid address type: ' + type);
    }
}
function decodeAddress(address) {
    const [prefix, type, network] = getData(address);
    const tool = getTool(type);
    const data = tool.decode(address, network);
    const script = tool.scriptPubKey(data);
    return { prefix, type, network, data, script };
}
function fromScriptPubKey(script, network) {
    const { type, data } = Tx.util.readScriptPubKey(script);
    const tool = getTool(type);
    return tool.encode(data, network);
}
function toScriptPubKey(address) {
    const { script } = decodeAddress(address);
    return Script.fmt.toAsm(script, false);
}

const Address = {
    p2pkh: P2PKH,
    p2sh: P2SH,
    p2wpkh: P2WPKH,
    p2wsh: P2WSH,
    p2tr: P2TR,
    decode: decodeAddress,
    fromScriptPubKey,
    toScriptPubKey
};

const VALID_HASH_TYPES$1 = [0x01, 0x02, 0x03];
function hashTx$1(txdata, idx, config = {}) {
    const { sigflag = 0x01 } = config;
    const isAnypay = (sigflag & 0x80) === 0x80;
    const flag = sigflag % 0x80;
    if (!VALID_HASH_TYPES$1.includes(flag)) {
        throw new Error('Invalid hash type: ' + String(sigflag));
    }
    const tx = Tx.fmt.toJson(txdata);
    const { version, vin, vout, locktime } = tx;
    const { txid, vout: prevIdx, prevout, sequence } = vin[idx];
    const { value } = prevout ?? {};
    if (value === undefined) {
        throw new Error('Prevout value is empty!');
    }
    let script = config.script;
    if (script === undefined &&
        config.pubkey !== undefined) {
        const pkhash = hash160(config.pubkey);
        script = `76a914${pkhash.hex}88ac`;
    }
    if (script === undefined) {
        throw new Error('No pubkey / script has been set!');
    }
    if (Script.fmt.toAsm(script).includes('OP_CODESEPARATOR')) {
        throw new Error('This library does not currently support the use of OP_CODESEPARATOR in segwit scripts.');
    }
    const sighash = [
        encodeVersion(version),
        hashPrevouts(vin, isAnypay),
        hashSequence$1(vin, flag, isAnypay),
        encodeTxid(txid),
        encodePrevOut(prevIdx),
        Script.encode(script, true),
        encodeValue(value),
        encodeSequence(sequence),
        hashOutputs$1(vout, idx, flag),
        encodeLocktime(locktime),
        Buff$1.num(sigflag, 4).reverse()
    ];
    return hash256(Buff$1.join(sighash));
}
function hashPrevouts(vin, isAnypay) {
    if (isAnypay === true) {
        return Buff$1.num(0, 32);
    }
    const stack = [];
    for (const { txid, vout } of vin) {
        stack.push(encodeTxid(txid));
        stack.push(encodePrevOut(vout));
    }
    return hash256(Buff$1.join(stack));
}
function hashSequence$1(vin, sigflag, isAnyPay) {
    if (isAnyPay || sigflag !== 0x01) {
        return Buff$1.num(0, 32);
    }
    const stack = [];
    for (const { sequence } of vin) {
        stack.push(encodeSequence(sequence));
    }
    return hash256(Buff$1.join(stack));
}
function hashOutputs$1(vout, idx, sigflag) {
    const stack = [];
    if (sigflag === 0x01) {
        for (const { value, scriptPubKey } of vout) {
            stack.push(encodeValue(value));
            stack.push(Script.encode(scriptPubKey, true));
        }
        return hash256(Buff$1.join(stack));
    }
    if (sigflag === 0x03 && idx < vout.length) {
        const { value, scriptPubKey } = vout[idx];
        stack.push(encodeValue(value));
        stack.push(Script.encode(scriptPubKey, true));
        return hash256(Buff$1.join(stack));
    }
    return Buff$1.num(0, 32);
}

function signTx$1(seckey, txdata, index, config = {}) {
    const { sigflag = 0x01 } = config;
    const hash = hashTx$1(txdata, index, config);
    const sig = noble.secp.sign(hash, seckey).toDERRawBytes(true);
    return Buff$1.join([sig, sigflag]);
}

function verifyTx$1(txdata, index, config = {}) {
    const tx = Tx.fmt.toJson(txdata);
    const { throws = false } = config;
    const { witness = [] } = tx.vin[index];
    const witnessData = Tx.util.readWitness(witness);
    const { script, params } = witnessData;
    let pub = null;
    if (params.length < 1) {
        return safeThrow('Invalid witness data: ' + String(witness), throws);
    }
    if (config.script === undefined &&
        script !== null) {
        config.script = script;
    }
    if (config.pubkey !== undefined) {
        pub = Buff$1.bytes(config.pubkey);
    }
    else if (params.length > 1 &&
        params[1].length === 33) {
        pub = Buff$1.bytes(params[1]);
    }
    else {
        return safeThrow('No pubkey provided!', throws);
    }
    const rawsig = Script.fmt.toParam(params[0]);
    const signature = rawsig.slice(0, -1);
    const sigflag = rawsig.slice(-1)[0];
    const hash = hashTx$1(tx, index, { ...config, sigflag });
    if (!noble.secp.verify(signature, hash, pub)) {
        return safeThrow('Invalid signature!', throws);
    }
    return true;
}

const SWSigner = {
    hash: hashTx$1,
    sign: signTx$1,
    verify: verifyTx$1
};

const VALID_HASH_TYPES = [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83];
function hashTx(template, index, config = {}) {
    const { extension, sigflag = 0x00, extflag = 0x00, key_version = 0x00, separator_pos = 0xFFFFFFFF } = config;
    const txdata = Tx.fmt.toJson(template);
    const { version, vin: input, vout: output, locktime } = txdata;
    if (index >= input.length) {
        throw new Error('Index out of bounds: ' + String(index));
    }
    if (!VALID_HASH_TYPES.includes(sigflag)) {
        throw new Error('Invalid hash type: ' + String(sigflag));
    }
    if (extflag < 0 || extflag > 127) {
        throw new Error('Extention flag out of range: ' + String(extflag));
    }
    const { txid, vout, sequence, witness = [] } = input[index];
    const isAnyPay = (sigflag & 0x80) === 0x80;
    const annex = getAnnexData(witness);
    const annexBit = (annex !== undefined) ? 1 : 0;
    const extendBit = (extension !== undefined) ? 1 : 0;
    const spendType = ((extflag + extendBit) * 2) + annexBit;
    const hashtag = Buff$1.str('TapSighash').digest;
    const preimage = [
        hashtag,
        hashtag,
        Buff$1.num(0x00, 1),
        Buff$1.num(sigflag, 1),
        encodeVersion(version),
        encodeLocktime(locktime)
    ];
    if (!isAnyPay) {
        const prevouts = input.map(e => getPrevout(e));
        preimage.push(hashOutpoints(input), hashAmounts(prevouts), hashScripts(prevouts), hashSequence(input));
    }
    if ((sigflag & 0x03) < 2 || (sigflag & 0x03) > 3) {
        preimage.push(hashOutputs(output));
    }
    preimage.push(Buff$1.num(spendType, 1));
    if (isAnyPay) {
        const { value, scriptPubKey } = getPrevout(input[index]);
        preimage.push(encodeTxid(txid), encodePrevOut(vout), encodeValue(value), Script.encode(scriptPubKey, true), encodeSequence(sequence));
    }
    else {
        preimage.push(Buff$1.num(index, 4).reverse());
    }
    if (annex !== undefined) {
        preimage.push(annex);
    }
    if ((sigflag & 0x03) === 0x03) {
        preimage.push(hashOutput(output[index]));
    }
    if (extension !== undefined) {
        preimage.push(Buff$1.bytes(extension), Buff$1.num(key_version), Buff$1.num(separator_pos, 4));
    }
    return Buff$1.join(preimage).digest;
}
function hashOutpoints(vin) {
    const stack = [];
    for (const { txid, vout } of vin) {
        stack.push(encodeTxid(txid));
        stack.push(encodePrevOut(vout));
    }
    return Buff$1.join(stack).digest;
}
function hashSequence(vin) {
    const stack = [];
    for (const { sequence } of vin) {
        stack.push(encodeSequence(sequence));
    }
    return Buff$1.join(stack).digest;
}
function hashAmounts(prevouts) {
    const stack = [];
    for (const { value } of prevouts) {
        stack.push(encodeValue(value));
    }
    return Buff$1.join(stack).digest;
}
function hashScripts(prevouts) {
    const stack = [];
    for (const { scriptPubKey } of prevouts) {
        stack.push(encodeScript(scriptPubKey, true));
    }
    return Buff$1.join(stack).digest;
}
function hashOutputs(vout) {
    const stack = [];
    for (const { value, scriptPubKey } of vout) {
        stack.push(encodeValue(value));
        stack.push(Script.encode(scriptPubKey, true));
    }
    return Buff$1.join(stack).digest;
}
function hashOutput(vout) {
    return Buff$1.join([
        encodeValue(vout.value),
        Script.encode(vout.scriptPubKey, true)
    ]).digest;
}
function getAnnexData(witness) {
    if (witness === undefined)
        return;
    if (witness.length < 2)
        return;
    let annex = witness.at(-1);
    if (typeof annex === 'string') {
        annex = Buff$1.hex(annex);
    }
    if (annex instanceof Uint8Array &&
        annex[0] === 0x50) {
        return Buff$1.raw(annex).prefixSize('be').digest;
    }
    return undefined;
}
function getPrevout(vin) {
    if (vin.prevout === undefined) {
        throw new Error('Prevout data missing for input: ' + String(vin.txid));
    }
    return vin.prevout;
}

const FIELD_SIZE = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
function signTx(seckey, txdata, index, config = {}) {
    const { sigflag = 0x00 } = config;
    const hash = hashTx(txdata, index, config);
    const sig = sign(seckey, hash);
    return (sigflag === 0x00)
        ? Buff$1.raw(sig)
        : Buff$1.join([sig, sigflag]);
}
function sign(secret, message, rand = Buff$1.random(32)) {
    const m = Buff$1.bytes(message);
    const dp = new Field(secret);
    const P = dp.point;
    const d = (P.hasEvenY) ? dp.big : dp.negated.big;
    const a = hashTag('BIP0340/aux', Buff$1.bytes(rand));
    const t = d ^ a.big;
    const n = hashTag('BIP0340/nonce', t, P.x.raw, m);
    const kp = new Field(n);
    const R = kp.point;
    const k = (R.hasEvenY) ? kp.big : kp.negated.big;
    const e = new Field(hashTag('BIP0340/challenge', R.x.raw, P.x.raw, m));
    const s = new Field(k + (e.big * d));
    return Buff$1.join([R.x.raw, s.raw]);
}
function verify(signature, message, pubkey, shouldThrow = false) {
    const P = Point.from_x(xOnlyPub(pubkey));
    const m = Buff$1.bytes(message);
    const stream = Buff$1.bytes(signature).stream;
    if (stream.size < 64) {
        safeThrow('Signature length is too small: ' + String(stream.size), shouldThrow);
    }
    const r = stream.read(32);
    if (r.big > FIELD_SIZE) {
        safeThrow('Signature r value greater than field size!', shouldThrow);
    }
    const s = stream.read(32);
    if (s.big > CURVE_ORDER) {
        safeThrow('Signature s value greater than curve order!', shouldThrow);
    }
    const e = new Field(hashTag('BIP0340/challenge', r.raw, P.x.raw, m));
    const sG = new Field(s).point;
    const eP = P.mul(e.big);
    const R = sG.sub(eP);
    if (R.hasOddY) {
        safeThrow('Signature R value has odd Y coordinate!', shouldThrow);
    }
    if (R.x.big === 0n) {
        safeThrow('Signature R value is infinite!', shouldThrow);
    }
    return R.x.big === r.big;
}

const DEFAULT_VERSION$1 = 0xc0;
function getTapTag(tag) {
    const htag = Buff$1.str(tag).digest;
    return Buff$1.join([htag, htag]);
}
function getTapLeaf(data, version = DEFAULT_VERSION$1) {
    return Buff$1.join([
        getTapTag('TapLeaf'),
        getVersion(version),
        Buff$1.bytes(data)
    ]).digest.hex;
}
function getTapScript(script, version) {
    return getTapLeaf(Script.fmt.toBytes(script), version);
}
function getTapBranch(leafA, leafB) {
    if (leafB < leafA) {
        [leafA, leafB] = [leafB, leafA];
    }
    return Buff$1.join([
        getTapTag('TapBranch'),
        Buff$1.hex(leafA).raw,
        Buff$1.hex(leafB).raw
    ]).digest.hex;
}
function getTapRoot(leaves) {
    return Buff$1.hex(merkleize(leaves)[0]);
}
function merkleize(taptree, target, path = []) {
    const leaves = [];
    const tree = [];
    if (taptree.length < 1) {
        throw new Error('Tree is empty!');
    }
    for (let i = 0; i < taptree.length; i++) {
        const leaf = taptree[i];
        if (Array.isArray(leaf)) {
            const [r, t, p] = merkleize(leaf, target);
            target = t;
            leaves.push(r);
            for (const e of p) {
                path.push(e);
            }
        }
        else {
            leaves.push(leaf);
        }
    }
    if (leaves.length === 1) {
        return [leaves[0], target, path];
    }
    leaves.sort();
    if (leaves.length % 2 !== 0) {
        leaves.push(leaves[leaves.length - 1]);
    }
    for (let i = 0; i < leaves.length - 1; i += 2) {
        const branch = getTapBranch(leaves[i], leaves[i + 1]);
        tree.push(branch);
        if (typeof target === 'string') {
            if (target === leaves[i]) {
                path.push(leaves[i + 1]);
                target = branch;
            }
            else if (target === leaves[i + 1]) {
                path.push(leaves[i]);
                target = branch;
            }
        }
    }
    return merkleize(tree, target, path);
}
function getVersion(version = 0xc0) {
    return version & 0xfe;
}

function getTapTweak(key, data = new Uint8Array(), isPrivate = false) {
    const pub = (isPrivate)
        ? new Field(key).point.x.raw
        : xOnlyPub(key);
    return Buff$1.join([getTapTag('TapTweak'), pub, Buff$1.bytes(data)]).digest;
}
function getTweakedKey(intkey, data, isPrivate = false) {
    if (data === undefined)
        data = new Uint8Array();
    const k = Buff$1.bytes(intkey);
    const t = getTapTweak(intkey, data, isPrivate);
    if (isPrivate) {
        return tweakSecKey(k, t);
    }
    else {
        return tweakPubKey(k, t);
    }
}
function getTweakedPub(pubkey, data) {
    return getTweakedKey(pubkey, data);
}
function getTweakedSec(seckey, data) {
    return getTweakedKey(seckey, data, true);
}
function tweakSecKey(seckey, tweak) {
    let sec = new Field(seckey);
    if (sec.point.hasOddY) {
        sec = sec.negate();
    }
    return Buff$1.raw(sec.add(tweak).raw);
}
function tweakPubKey(pubkey, tweak) {
    pubkey = xOnlyPub(pubkey);
    const P = Point.from_x(pubkey);
    const Q = P.add(tweak);
    return Buff$1.raw(Q.raw);
}
function getScriptOnlyPubkey() {
    const G = Buff$1.hex('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8');
    return Point.from_x(G.digest).x;
}
const SCRIPT_PUBKEY = getScriptOnlyPubkey();

const DEFAULT_VERSION = 0xc0;
function getTapSecKey(seckey, config = {}) {
    return getTapKey(seckey, { ...config, isPrivate: true });
}
function getTapPubKey(pubkey, config = {}) {
    return getTapKey(pubkey, { ...config, isPrivate: false });
}
function getTapKey(intkey, config = {}) {
    const { isPrivate = false, tree = [], version = DEFAULT_VERSION } = config;
    const pubkey = (isPrivate)
        ? util$1.getPublicKey(intkey, true)
        : xOnlyPub(intkey);
    let { target } = config;
    if (target !== undefined)
        target = Buff$1.bytes(target).hex;
    let tapkey, ctrlpath = [];
    if (tree.length > 0) {
        const [root, _t, path] = merkleize(tree, target);
        ctrlpath = path;
        tapkey = getTweakedKey(intkey, root, isPrivate);
    }
    else {
        if (target !== undefined) {
            tapkey = getTweakedKey(intkey, target, isPrivate);
        }
        else {
            tapkey = getTweakedKey(intkey, undefined, isPrivate);
        }
    }
    const parity = (isPrivate)
        ? util$1.getPublicKey(tapkey)[0]
        : tapkey[0];
    const cbit = Buff$1.num(version + readParityBit(parity));
    const block = [cbit, pubkey];
    if (ctrlpath.length > 0) {
        ctrlpath.forEach(e => block.push(Buff$1.hex(e)));
    }
    const cblock = Buff$1.join(block);
    if (target !== undefined) {
        if (!checkPath(tapkey, target, cblock, config)) {
            throw new Error('Path checking failed! Unable to generate path.');
        }
    }
    return [xOnlyPub(tapkey).hex, cblock.hex];
}
function checkPath(tapkey, target, cblock, config = {}) {
    const { isPrivate = false, throws = false } = config;
    const { parity, paths, intkey } = readCtrlBlock(cblock);
    const pub = (isPrivate)
        ? util$1.getPublicKey(tapkey, true)
        : xOnlyPub(tapkey);
    const extkey = Buff$1.join([parity, pub]);
    if (extkey.length !== 33) {
        return safeThrow('Invalid tapkey: ' + extkey.hex, throws);
    }
    let branch = Buff$1.bytes(target).hex;
    for (const path of paths) {
        branch = getTapBranch(branch, path);
    }
    const k = getTweakedKey(intkey, branch);
    return (Buff$1.raw(k).hex === Buff$1.raw(extkey).hex);
}
function readCtrlBlock(cblock) {
    const buffer = new Stream$1(Buff$1.bytes(cblock));
    const cbyte = buffer.read(1).num;
    const intkey = buffer.read(32);
    const [version, parity] = (cbyte % 2 === 0)
        ? [cbyte, 0x02]
        : [cbyte - 1, 0x03];
    const paths = [];
    while (buffer.size >= 32) {
        paths.push(buffer.read(32).hex);
    }
    if (buffer.size !== 0) {
        throw new Error('Non-empty buffer on control block: ' + String(buffer));
    }
    return { intkey, paths, parity, version };
}
function readParityBit(parity = 0x02) {
    if (parity === 0 || parity === 1)
        return parity;
    if (parity === 0x02 || parity === '02')
        return 0;
    if (parity === 0x03 || parity === '03')
        return 1;
    throw new Error('Invalid parity bit: ' + String(parity));
}

function verifyTx(txdata, index, config = {}) {
    const tx = Tx.fmt.toJson(txdata);
    const { throws = false } = config;
    const { prevout, witness = [] } = tx.vin[index];
    const witnessData = Tx.util.readWitness(witness);
    const { cblock, script, params } = witnessData;
    let pub;
    if (params.length < 1) {
        return safeThrow('Invalid witness data: ' + String(witness), throws);
    }
    const { scriptPubKey } = prevout ?? {};
    if (scriptPubKey === undefined) {
        return safeThrow('Prevout scriptPubKey is empty!', throws);
    }
    const { type, data: tapkey } = Tx.util.readScriptPubKey(scriptPubKey);
    if (type !== 'p2tr') {
        return safeThrow('Prevout script is not a valid taproot output:' + tapkey.hex, throws);
    }
    if (tapkey.length !== 32) {
        return safeThrow('Invalid tapkey length: ' + String(tapkey.length), throws);
    }
    if (cblock !== null &&
        script !== null) {
        const version = cblock[0] & 0xfe;
        const target = getTapLeaf(script, version);
        config.extension = target;
        if (!checkPath(tapkey, target, cblock, { throws })) {
            return safeThrow('cblock verification failed!', throws);
        }
    }
    if (config.pubkey !== undefined) {
        pub = Buff$1.bytes(config.pubkey);
    }
    else if (params.length > 1 && params[1].length === 32) {
        pub = Buff$1.bytes(params[1]);
    }
    else {
        pub = Buff$1.bytes(tapkey);
    }
    const rawsig = Script.fmt.toParam(params[0]);
    const stream = new Stream$1(rawsig);
    const signature = stream.read(64).raw;
    if (stream.size === 1) {
        config.sigflag = stream.read(1).num;
        if (config.sigflag === 0x00) {
            return safeThrow('0x00 is not a valid appended sigflag!', throws);
        }
    }
    const hash = hashTx(tx, index, config);
    if (!verify(signature, hash, pub, throws)) {
        return safeThrow('Invalid signature!', throws);
    }
    return true;
}

const TRSigner = {
    hash: hashTx,
    sign: signTx,
    verify: verifyTx
};

const Signer = {
    segwit: SWSigner,
    taproot: TRSigner
};

const TapTree = {
    getTag: getTapTag,
    getLeaf: getTapLeaf,
    getBranch: getTapBranch,
    getRoot: getTapRoot
};
const TapUtil = {
    readCtrlBlock: readCtrlBlock,
    readParityBit: readParityBit
};
const TapTweak = {
    getPubKey: getTweakedPub,
    getSecKey: getTweakedSec,
    getTweak: getTapTweak,
    tweakSecKey: tweakSecKey,
    tweakPubKey: tweakPubKey
};
const Tap = {
    getPubKey: getTapPubKey,
    getSecKey: getTapSecKey,
    encodeScript: getTapScript,
    checkPath: checkPath,
    tree: TapTree,
    tweak: TapTweak,
    util: TapUtil,
    SCRIPT_PUBKEY: SCRIPT_PUBKEY
};

class TxScript {
    constructor(script) {
        this._buff = Buff$1.raw(encodeScript(script));
    }
    get raw() {
        return this._buff.raw;
    }
    get hex() {
        return this._buff.hex;
    }
    get asm() {
        return decodeScript(this._buff);
    }
    getHash(format, version) {
        switch (format) {
            case 'p2w':
                return hash256(this._buff).hex;
            case 'p2sh':
                return hash160(this._buff).hex;
            case 'p2tr':
                return TapTree.getLeaf(this._buff, version);
            default:
                throw new Error('Unrecognized format: ' + format);
        }
    }
    toJSON() {
        return this.asm ?? [];
    }
}

const MAX_VAL = 0xFFFFFFFF;
const NO_LOCK = (1 << 31);
const TIME_MOD = 512;
const LOCK_TYPE = (1 << 22);
class TxSequence {
    constructor(value) {
        if (typeof value === 'string') {
            this.value = parseInt(value, 16);
        }
        else {
            this.value = value;
        }
    }
    get isReplaceable() {
        return this.value < MAX_VAL;
    }
    get isLocked() {
        return !(this.value !== MAX_VAL || (this.value & NO_LOCK) !== 0);
    }
    get isTimelock() {
        return (this.value & LOCK_TYPE) !== 0;
    }
    get timestamp() {
        return this.isLocked
            ? this.isTimelock
                ? this.value * TIME_MOD
                : this.value * TIME_MOD * 600
            : 0;
    }
    set timestamp(value) {
        this.value = Math.ceil(value / TIME_MOD);
    }
    get blockheight() {
        return this.isLocked
            ? !this.isTimelock
                ? this.value
                : Math.ceil((this.value * TIME_MOD) / 600)
            : 0;
    }
    set blockheight(value) {
        this.value = value;
    }
    get estDate() {
        return this.isTimelock
            ? new Date(Date.now() + (this.value * TIME_MOD * 1000))
            : new Date(Date.now() + (this.value * 600 * 1000));
    }
    set estDate(date) {
        const delta = date.getTime() - Date.now();
        this.value = (delta > (TIME_MOD * 1000))
            ? Math.ceil(delta / 1000 / TIME_MOD)
            : 1;
    }
    toJSON() {
        return this.value;
    }
}

let TxOutput$1 = class TxOutput {
    constructor(txout) {
        this.value = BigInt(txout.value);
        this.scriptPubKey = new TxScript(txout.scriptPubKey);
    }
    get type() {
        const { type } = readScriptPubKey(this.scriptPubKey.raw);
        return type;
    }
};

class TxWitness {
    constructor(data, format) {
        this._data = data;
        this._meta = readWitness(data);
        this.format = format;
    }
    get length() {
        return this._data.length;
    }
    get annex() {
        const annex = this._meta.annex;
        return (annex !== null)
            ? Buff$1.raw(annex).hex
            : undefined;
    }
    get cblock() {
        const cblock = this._meta.cblock;
        return (cblock !== null)
            ? Buff$1.raw(cblock).hex
            : undefined;
    }
    get script() {
        const script = this._meta.script;
        return (script !== null)
            ? Script.decode(script)
            : undefined;
    }
    get params() {
        return this._meta.params;
    }
    toJSON() {
        return this._data;
    }
}

let TxInput$1 = class TxInput {
    constructor(txdata, index) {
        this._tx = txdata;
        this.idx = index;
    }
    get data() {
        return this._tx.vin[this.idx];
    }
    get txid() {
        return this.data.txid;
    }
    get vout() {
        return this.data.vout;
    }
    get prevout() {
        return (this.data.prevout !== undefined)
            ? new TxOutput$1(this.data.prevout)
            : undefined;
    }
    get scriptSig() {
        return new TxScript(this.data.scriptSig);
    }
    get sequence() {
        return new TxSequence(this.data.sequence);
    }
    get witness() {
        return new TxWitness(this.data.witness);
    }
    get type() {
        if (this.prevout !== undefined) {
            const script = this.prevout.scriptPubKey.raw;
            const { type } = readScriptPubKey(script);
            if (type === 'p2sh') {
                const asm = this.scriptSig.asm;
                if (asm[0] === 'OP_0') {
                    if (asm[1].length === 20) {
                        return 'p2w-p2pkh';
                    }
                    if (asm[1].length === 32) {
                        return 'p2w-p2sh';
                    }
                }
                return 'p2sh';
            }
            return type;
        }
        return 'raw';
    }
    sign(seckey, config) {
        if (this.type.startsWith('p2w')) {
            return Signer.segwit.sign(seckey, this._tx, this.idx, config);
        }
        if (this.type.startsWith('p2tr')) {
            return Signer.taproot.sign(seckey, this._tx, this.idx, config);
        }
        if (this.type.startsWith('p2pkh') ||
            this.type.startsWith('p2sh')) {
            throw new Error('This library does not support signing legacy transactions.');
        }
        throw new Error('Unable to sign this input type:' + String(this.type));
    }
};

const LOCKTIME_THRESHOLD = 500000000;
class TxLocktime {
    constructor(value = 0) {
        this.value = Buff$1.bytes(value).num;
    }
    get isTimelock() {
        return this.value > LOCKTIME_THRESHOLD;
    }
    get timestamp() {
        return this.isTimelock
            ? this.value
            : this.value * 600;
    }
    set timestamp(value) {
        this.value = value;
    }
    get blockheight() {
        return !this.isTimelock
            ? this.value
            : Math.floor(this.value / 600);
    }
    set blockheight(value) {
        this.value = value;
    }
    get estDate() {
        return this.isTimelock
            ? new Date(Date.now() + (this.value * 1000))
            : new Date(Date.now() + (this.value * 600 * 1000));
    }
    set estDate(date) {
        this.value = Math.floor((date.getTime() - Date.now()) / 1000);
    }
    toJSON() {
        return this.value;
    }
}

var util;
(function (util) {
    util.assertEqual = (val) => val;
    function assertIs(_arg) { }
    util.assertIs = assertIs;
    function assertNever(_x) {
        throw new Error();
    }
    util.assertNever = assertNever;
    util.arrayToEnum = (items) => {
        const obj = {};
        for (const item of items) {
            obj[item] = item;
        }
        return obj;
    };
    util.getValidEnumValues = (obj) => {
        const validKeys = util.objectKeys(obj).filter((k) => typeof obj[obj[k]] !== "number");
        const filtered = {};
        for (const k of validKeys) {
            filtered[k] = obj[k];
        }
        return util.objectValues(filtered);
    };
    util.objectValues = (obj) => {
        return util.objectKeys(obj).map(function (e) {
            return obj[e];
        });
    };
    util.objectKeys = typeof Object.keys === "function" // eslint-disable-line ban/ban
        ? (obj) => Object.keys(obj) // eslint-disable-line ban/ban
        : (object) => {
            const keys = [];
            for (const key in object) {
                if (Object.prototype.hasOwnProperty.call(object, key)) {
                    keys.push(key);
                }
            }
            return keys;
        };
    util.find = (arr, checker) => {
        for (const item of arr) {
            if (checker(item))
                return item;
        }
        return undefined;
    };
    util.isInteger = typeof Number.isInteger === "function"
        ? (val) => Number.isInteger(val) // eslint-disable-line ban/ban
        : (val) => typeof val === "number" && isFinite(val) && Math.floor(val) === val;
    function joinValues(array, separator = " | ") {
        return array
            .map((val) => (typeof val === "string" ? `'${val}'` : val))
            .join(separator);
    }
    util.joinValues = joinValues;
    util.jsonStringifyReplacer = (_, value) => {
        if (typeof value === "bigint") {
            return value.toString();
        }
        return value;
    };
})(util || (util = {}));
var objectUtil;
(function (objectUtil) {
    objectUtil.mergeShapes = (first, second) => {
        return {
            ...first,
            ...second, // second overwrites first
        };
    };
})(objectUtil || (objectUtil = {}));
const ZodParsedType = util.arrayToEnum([
    "string",
    "nan",
    "number",
    "integer",
    "float",
    "boolean",
    "date",
    "bigint",
    "symbol",
    "function",
    "undefined",
    "null",
    "array",
    "object",
    "unknown",
    "promise",
    "void",
    "never",
    "map",
    "set",
]);
const getParsedType = (data) => {
    const t = typeof data;
    switch (t) {
        case "undefined":
            return ZodParsedType.undefined;
        case "string":
            return ZodParsedType.string;
        case "number":
            return isNaN(data) ? ZodParsedType.nan : ZodParsedType.number;
        case "boolean":
            return ZodParsedType.boolean;
        case "function":
            return ZodParsedType.function;
        case "bigint":
            return ZodParsedType.bigint;
        case "symbol":
            return ZodParsedType.symbol;
        case "object":
            if (Array.isArray(data)) {
                return ZodParsedType.array;
            }
            if (data === null) {
                return ZodParsedType.null;
            }
            if (data.then &&
                typeof data.then === "function" &&
                data.catch &&
                typeof data.catch === "function") {
                return ZodParsedType.promise;
            }
            if (typeof Map !== "undefined" && data instanceof Map) {
                return ZodParsedType.map;
            }
            if (typeof Set !== "undefined" && data instanceof Set) {
                return ZodParsedType.set;
            }
            if (typeof Date !== "undefined" && data instanceof Date) {
                return ZodParsedType.date;
            }
            return ZodParsedType.object;
        default:
            return ZodParsedType.unknown;
    }
};

const ZodIssueCode = util.arrayToEnum([
    "invalid_type",
    "invalid_literal",
    "custom",
    "invalid_union",
    "invalid_union_discriminator",
    "invalid_enum_value",
    "unrecognized_keys",
    "invalid_arguments",
    "invalid_return_type",
    "invalid_date",
    "invalid_string",
    "too_small",
    "too_big",
    "invalid_intersection_types",
    "not_multiple_of",
    "not_finite",
]);
const quotelessJson = (obj) => {
    const json = JSON.stringify(obj, null, 2);
    return json.replace(/"([^"]+)":/g, "$1:");
};
class ZodError extends Error {
    constructor(issues) {
        super();
        this.issues = [];
        this.addIssue = (sub) => {
            this.issues = [...this.issues, sub];
        };
        this.addIssues = (subs = []) => {
            this.issues = [...this.issues, ...subs];
        };
        const actualProto = new.target.prototype;
        if (Object.setPrototypeOf) {
            // eslint-disable-next-line ban/ban
            Object.setPrototypeOf(this, actualProto);
        }
        else {
            this.__proto__ = actualProto;
        }
        this.name = "ZodError";
        this.issues = issues;
    }
    get errors() {
        return this.issues;
    }
    format(_mapper) {
        const mapper = _mapper ||
            function (issue) {
                return issue.message;
            };
        const fieldErrors = { _errors: [] };
        const processError = (error) => {
            for (const issue of error.issues) {
                if (issue.code === "invalid_union") {
                    issue.unionErrors.map(processError);
                }
                else if (issue.code === "invalid_return_type") {
                    processError(issue.returnTypeError);
                }
                else if (issue.code === "invalid_arguments") {
                    processError(issue.argumentsError);
                }
                else if (issue.path.length === 0) {
                    fieldErrors._errors.push(mapper(issue));
                }
                else {
                    let curr = fieldErrors;
                    let i = 0;
                    while (i < issue.path.length) {
                        const el = issue.path[i];
                        const terminal = i === issue.path.length - 1;
                        if (!terminal) {
                            curr[el] = curr[el] || { _errors: [] };
                            // if (typeof el === "string") {
                            //   curr[el] = curr[el] || { _errors: [] };
                            // } else if (typeof el === "number") {
                            //   const errorArray: any = [];
                            //   errorArray._errors = [];
                            //   curr[el] = curr[el] || errorArray;
                            // }
                        }
                        else {
                            curr[el] = curr[el] || { _errors: [] };
                            curr[el]._errors.push(mapper(issue));
                        }
                        curr = curr[el];
                        i++;
                    }
                }
            }
        };
        processError(this);
        return fieldErrors;
    }
    toString() {
        return this.message;
    }
    get message() {
        return JSON.stringify(this.issues, util.jsonStringifyReplacer, 2);
    }
    get isEmpty() {
        return this.issues.length === 0;
    }
    flatten(mapper = (issue) => issue.message) {
        const fieldErrors = {};
        const formErrors = [];
        for (const sub of this.issues) {
            if (sub.path.length > 0) {
                fieldErrors[sub.path[0]] = fieldErrors[sub.path[0]] || [];
                fieldErrors[sub.path[0]].push(mapper(sub));
            }
            else {
                formErrors.push(mapper(sub));
            }
        }
        return { formErrors, fieldErrors };
    }
    get formErrors() {
        return this.flatten();
    }
}
ZodError.create = (issues) => {
    const error = new ZodError(issues);
    return error;
};

const errorMap = (issue, _ctx) => {
    let message;
    switch (issue.code) {
        case ZodIssueCode.invalid_type:
            if (issue.received === ZodParsedType.undefined) {
                message = "Required";
            }
            else {
                message = `Expected ${issue.expected}, received ${issue.received}`;
            }
            break;
        case ZodIssueCode.invalid_literal:
            message = `Invalid literal value, expected ${JSON.stringify(issue.expected, util.jsonStringifyReplacer)}`;
            break;
        case ZodIssueCode.unrecognized_keys:
            message = `Unrecognized key(s) in object: ${util.joinValues(issue.keys, ", ")}`;
            break;
        case ZodIssueCode.invalid_union:
            message = `Invalid input`;
            break;
        case ZodIssueCode.invalid_union_discriminator:
            message = `Invalid discriminator value. Expected ${util.joinValues(issue.options)}`;
            break;
        case ZodIssueCode.invalid_enum_value:
            message = `Invalid enum value. Expected ${util.joinValues(issue.options)}, received '${issue.received}'`;
            break;
        case ZodIssueCode.invalid_arguments:
            message = `Invalid function arguments`;
            break;
        case ZodIssueCode.invalid_return_type:
            message = `Invalid function return type`;
            break;
        case ZodIssueCode.invalid_date:
            message = `Invalid date`;
            break;
        case ZodIssueCode.invalid_string:
            if (typeof issue.validation === "object") {
                if ("includes" in issue.validation) {
                    message = `Invalid input: must include "${issue.validation.includes}"`;
                    if (typeof issue.validation.position === "number") {
                        message = `${message} at one or more positions greater than or equal to ${issue.validation.position}`;
                    }
                }
                else if ("startsWith" in issue.validation) {
                    message = `Invalid input: must start with "${issue.validation.startsWith}"`;
                }
                else if ("endsWith" in issue.validation) {
                    message = `Invalid input: must end with "${issue.validation.endsWith}"`;
                }
                else {
                    util.assertNever(issue.validation);
                }
            }
            else if (issue.validation !== "regex") {
                message = `Invalid ${issue.validation}`;
            }
            else {
                message = "Invalid";
            }
            break;
        case ZodIssueCode.too_small:
            if (issue.type === "array")
                message = `Array must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `more than`} ${issue.minimum} element(s)`;
            else if (issue.type === "string")
                message = `String must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `over`} ${issue.minimum} character(s)`;
            else if (issue.type === "number")
                message = `Number must be ${issue.exact
                    ? `exactly equal to `
                    : issue.inclusive
                        ? `greater than or equal to `
                        : `greater than `}${issue.minimum}`;
            else if (issue.type === "date")
                message = `Date must be ${issue.exact
                    ? `exactly equal to `
                    : issue.inclusive
                        ? `greater than or equal to `
                        : `greater than `}${new Date(Number(issue.minimum))}`;
            else
                message = "Invalid input";
            break;
        case ZodIssueCode.too_big:
            if (issue.type === "array")
                message = `Array must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `less than`} ${issue.maximum} element(s)`;
            else if (issue.type === "string")
                message = `String must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `under`} ${issue.maximum} character(s)`;
            else if (issue.type === "number")
                message = `Number must be ${issue.exact
                    ? `exactly`
                    : issue.inclusive
                        ? `less than or equal to`
                        : `less than`} ${issue.maximum}`;
            else if (issue.type === "bigint")
                message = `BigInt must be ${issue.exact
                    ? `exactly`
                    : issue.inclusive
                        ? `less than or equal to`
                        : `less than`} ${issue.maximum}`;
            else if (issue.type === "date")
                message = `Date must be ${issue.exact
                    ? `exactly`
                    : issue.inclusive
                        ? `smaller than or equal to`
                        : `smaller than`} ${new Date(Number(issue.maximum))}`;
            else
                message = "Invalid input";
            break;
        case ZodIssueCode.custom:
            message = `Invalid input`;
            break;
        case ZodIssueCode.invalid_intersection_types:
            message = `Intersection results could not be merged`;
            break;
        case ZodIssueCode.not_multiple_of:
            message = `Number must be a multiple of ${issue.multipleOf}`;
            break;
        case ZodIssueCode.not_finite:
            message = "Number must be finite";
            break;
        default:
            message = _ctx.defaultError;
            util.assertNever(issue);
    }
    return { message };
};

let overrideErrorMap = errorMap;
function setErrorMap(map) {
    overrideErrorMap = map;
}
function getErrorMap() {
    return overrideErrorMap;
}

const makeIssue = (params) => {
    const { data, path, errorMaps, issueData } = params;
    const fullPath = [...path, ...(issueData.path || [])];
    const fullIssue = {
        ...issueData,
        path: fullPath,
    };
    let errorMessage = "";
    const maps = errorMaps
        .filter((m) => !!m)
        .slice()
        .reverse();
    for (const map of maps) {
        errorMessage = map(fullIssue, { data, defaultError: errorMessage }).message;
    }
    return {
        ...issueData,
        path: fullPath,
        message: issueData.message || errorMessage,
    };
};
const EMPTY_PATH = [];
function addIssueToContext(ctx, issueData) {
    const issue = makeIssue({
        issueData: issueData,
        data: ctx.data,
        path: ctx.path,
        errorMaps: [
            ctx.common.contextualErrorMap,
            ctx.schemaErrorMap,
            getErrorMap(),
            errorMap, // then global default map
        ].filter((x) => !!x),
    });
    ctx.common.issues.push(issue);
}
class ParseStatus {
    constructor() {
        this.value = "valid";
    }
    dirty() {
        if (this.value === "valid")
            this.value = "dirty";
    }
    abort() {
        if (this.value !== "aborted")
            this.value = "aborted";
    }
    static mergeArray(status, results) {
        const arrayValue = [];
        for (const s of results) {
            if (s.status === "aborted")
                return INVALID;
            if (s.status === "dirty")
                status.dirty();
            arrayValue.push(s.value);
        }
        return { status: status.value, value: arrayValue };
    }
    static async mergeObjectAsync(status, pairs) {
        const syncPairs = [];
        for (const pair of pairs) {
            syncPairs.push({
                key: await pair.key,
                value: await pair.value,
            });
        }
        return ParseStatus.mergeObjectSync(status, syncPairs);
    }
    static mergeObjectSync(status, pairs) {
        const finalObject = {};
        for (const pair of pairs) {
            const { key, value } = pair;
            if (key.status === "aborted")
                return INVALID;
            if (value.status === "aborted")
                return INVALID;
            if (key.status === "dirty")
                status.dirty();
            if (value.status === "dirty")
                status.dirty();
            if (typeof value.value !== "undefined" || pair.alwaysSet) {
                finalObject[key.value] = value.value;
            }
        }
        return { status: status.value, value: finalObject };
    }
}
const INVALID = Object.freeze({
    status: "aborted",
});
const DIRTY = (value) => ({ status: "dirty", value });
const OK = (value) => ({ status: "valid", value });
const isAborted = (x) => x.status === "aborted";
const isDirty = (x) => x.status === "dirty";
const isValid = (x) => x.status === "valid";
const isAsync = (x) => typeof Promise !== "undefined" && x instanceof Promise;

var errorUtil;
(function (errorUtil) {
    errorUtil.errToObj = (message) => typeof message === "string" ? { message } : message || {};
    errorUtil.toString = (message) => typeof message === "string" ? message : message === null || message === void 0 ? void 0 : message.message;
})(errorUtil || (errorUtil = {}));

class ParseInputLazyPath {
    constructor(parent, value, path, key) {
        this._cachedPath = [];
        this.parent = parent;
        this.data = value;
        this._path = path;
        this._key = key;
    }
    get path() {
        if (!this._cachedPath.length) {
            if (this._key instanceof Array) {
                this._cachedPath.push(...this._path, ...this._key);
            }
            else {
                this._cachedPath.push(...this._path, this._key);
            }
        }
        return this._cachedPath;
    }
}
const handleResult = (ctx, result) => {
    if (isValid(result)) {
        return { success: true, data: result.value };
    }
    else {
        if (!ctx.common.issues.length) {
            throw new Error("Validation failed but no issues detected.");
        }
        return {
            success: false,
            get error() {
                if (this._error)
                    return this._error;
                const error = new ZodError(ctx.common.issues);
                this._error = error;
                return this._error;
            },
        };
    }
};
function processCreateParams(params) {
    if (!params)
        return {};
    const { errorMap, invalid_type_error, required_error, description } = params;
    if (errorMap && (invalid_type_error || required_error)) {
        throw new Error(`Can't use "invalid_type_error" or "required_error" in conjunction with custom error map.`);
    }
    if (errorMap)
        return { errorMap: errorMap, description };
    const customMap = (iss, ctx) => {
        if (iss.code !== "invalid_type")
            return { message: ctx.defaultError };
        if (typeof ctx.data === "undefined") {
            return { message: required_error !== null && required_error !== void 0 ? required_error : ctx.defaultError };
        }
        return { message: invalid_type_error !== null && invalid_type_error !== void 0 ? invalid_type_error : ctx.defaultError };
    };
    return { errorMap: customMap, description };
}
class ZodType {
    constructor(def) {
        /** Alias of safeParseAsync */
        this.spa = this.safeParseAsync;
        this._def = def;
        this.parse = this.parse.bind(this);
        this.safeParse = this.safeParse.bind(this);
        this.parseAsync = this.parseAsync.bind(this);
        this.safeParseAsync = this.safeParseAsync.bind(this);
        this.spa = this.spa.bind(this);
        this.refine = this.refine.bind(this);
        this.refinement = this.refinement.bind(this);
        this.superRefine = this.superRefine.bind(this);
        this.optional = this.optional.bind(this);
        this.nullable = this.nullable.bind(this);
        this.nullish = this.nullish.bind(this);
        this.array = this.array.bind(this);
        this.promise = this.promise.bind(this);
        this.or = this.or.bind(this);
        this.and = this.and.bind(this);
        this.transform = this.transform.bind(this);
        this.brand = this.brand.bind(this);
        this.default = this.default.bind(this);
        this.catch = this.catch.bind(this);
        this.describe = this.describe.bind(this);
        this.pipe = this.pipe.bind(this);
        this.isNullable = this.isNullable.bind(this);
        this.isOptional = this.isOptional.bind(this);
    }
    get description() {
        return this._def.description;
    }
    _getType(input) {
        return getParsedType(input.data);
    }
    _getOrReturnCtx(input, ctx) {
        return (ctx || {
            common: input.parent.common,
            data: input.data,
            parsedType: getParsedType(input.data),
            schemaErrorMap: this._def.errorMap,
            path: input.path,
            parent: input.parent,
        });
    }
    _processInputParams(input) {
        return {
            status: new ParseStatus(),
            ctx: {
                common: input.parent.common,
                data: input.data,
                parsedType: getParsedType(input.data),
                schemaErrorMap: this._def.errorMap,
                path: input.path,
                parent: input.parent,
            },
        };
    }
    _parseSync(input) {
        const result = this._parse(input);
        if (isAsync(result)) {
            throw new Error("Synchronous parse encountered promise.");
        }
        return result;
    }
    _parseAsync(input) {
        const result = this._parse(input);
        return Promise.resolve(result);
    }
    parse(data, params) {
        const result = this.safeParse(data, params);
        if (result.success)
            return result.data;
        throw result.error;
    }
    safeParse(data, params) {
        var _a;
        const ctx = {
            common: {
                issues: [],
                async: (_a = params === null || params === void 0 ? void 0 : params.async) !== null && _a !== void 0 ? _a : false,
                contextualErrorMap: params === null || params === void 0 ? void 0 : params.errorMap,
            },
            path: (params === null || params === void 0 ? void 0 : params.path) || [],
            schemaErrorMap: this._def.errorMap,
            parent: null,
            data,
            parsedType: getParsedType(data),
        };
        const result = this._parseSync({ data, path: ctx.path, parent: ctx });
        return handleResult(ctx, result);
    }
    async parseAsync(data, params) {
        const result = await this.safeParseAsync(data, params);
        if (result.success)
            return result.data;
        throw result.error;
    }
    async safeParseAsync(data, params) {
        const ctx = {
            common: {
                issues: [],
                contextualErrorMap: params === null || params === void 0 ? void 0 : params.errorMap,
                async: true,
            },
            path: (params === null || params === void 0 ? void 0 : params.path) || [],
            schemaErrorMap: this._def.errorMap,
            parent: null,
            data,
            parsedType: getParsedType(data),
        };
        const maybeAsyncResult = this._parse({ data, path: ctx.path, parent: ctx });
        const result = await (isAsync(maybeAsyncResult)
            ? maybeAsyncResult
            : Promise.resolve(maybeAsyncResult));
        return handleResult(ctx, result);
    }
    refine(check, message) {
        const getIssueProperties = (val) => {
            if (typeof message === "string" || typeof message === "undefined") {
                return { message };
            }
            else if (typeof message === "function") {
                return message(val);
            }
            else {
                return message;
            }
        };
        return this._refinement((val, ctx) => {
            const result = check(val);
            const setError = () => ctx.addIssue({
                code: ZodIssueCode.custom,
                ...getIssueProperties(val),
            });
            if (typeof Promise !== "undefined" && result instanceof Promise) {
                return result.then((data) => {
                    if (!data) {
                        setError();
                        return false;
                    }
                    else {
                        return true;
                    }
                });
            }
            if (!result) {
                setError();
                return false;
            }
            else {
                return true;
            }
        });
    }
    refinement(check, refinementData) {
        return this._refinement((val, ctx) => {
            if (!check(val)) {
                ctx.addIssue(typeof refinementData === "function"
                    ? refinementData(val, ctx)
                    : refinementData);
                return false;
            }
            else {
                return true;
            }
        });
    }
    _refinement(refinement) {
        return new ZodEffects({
            schema: this,
            typeName: ZodFirstPartyTypeKind.ZodEffects,
            effect: { type: "refinement", refinement },
        });
    }
    superRefine(refinement) {
        return this._refinement(refinement);
    }
    optional() {
        return ZodOptional.create(this, this._def);
    }
    nullable() {
        return ZodNullable.create(this, this._def);
    }
    nullish() {
        return this.nullable().optional();
    }
    array() {
        return ZodArray.create(this, this._def);
    }
    promise() {
        return ZodPromise.create(this, this._def);
    }
    or(option) {
        return ZodUnion.create([this, option], this._def);
    }
    and(incoming) {
        return ZodIntersection.create(this, incoming, this._def);
    }
    transform(transform) {
        return new ZodEffects({
            ...processCreateParams(this._def),
            schema: this,
            typeName: ZodFirstPartyTypeKind.ZodEffects,
            effect: { type: "transform", transform },
        });
    }
    default(def) {
        const defaultValueFunc = typeof def === "function" ? def : () => def;
        return new ZodDefault({
            ...processCreateParams(this._def),
            innerType: this,
            defaultValue: defaultValueFunc,
            typeName: ZodFirstPartyTypeKind.ZodDefault,
        });
    }
    brand() {
        return new ZodBranded({
            typeName: ZodFirstPartyTypeKind.ZodBranded,
            type: this,
            ...processCreateParams(this._def),
        });
    }
    catch(def) {
        const catchValueFunc = typeof def === "function" ? def : () => def;
        return new ZodCatch({
            ...processCreateParams(this._def),
            innerType: this,
            catchValue: catchValueFunc,
            typeName: ZodFirstPartyTypeKind.ZodCatch,
        });
    }
    describe(description) {
        const This = this.constructor;
        return new This({
            ...this._def,
            description,
        });
    }
    pipe(target) {
        return ZodPipeline.create(this, target);
    }
    isOptional() {
        return this.safeParse(undefined).success;
    }
    isNullable() {
        return this.safeParse(null).success;
    }
}
const cuidRegex = /^c[^\s-]{8,}$/i;
const cuid2Regex = /^[a-z][a-z0-9]*$/;
const ulidRegex = /[0-9A-HJKMNP-TV-Z]{26}/;
const uuidRegex = /^([a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}|00000000-0000-0000-0000-000000000000)$/i;
// from https://stackoverflow.com/a/46181/1550155
// old version: too slow, didn't support unicode
// const emailRegex = /^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))$/i;
//old email regex
// const emailRegex = /^(([^<>()[\].,;:\s@"]+(\.[^<>()[\].,;:\s@"]+)*)|(".+"))@((?!-)([^<>()[\].,;:\s@"]+\.)+[^<>()[\].,;:\s@"]{1,})[^-<>()[\].,;:\s@"]$/i;
// eslint-disable-next-line
const emailRegex = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[(((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2}))\.){3}((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2}))\])|(\[IPv6:(([a-f0-9]{1,4}:){7}|::([a-f0-9]{1,4}:){0,6}|([a-f0-9]{1,4}:){1}:([a-f0-9]{1,4}:){0,5}|([a-f0-9]{1,4}:){2}:([a-f0-9]{1,4}:){0,4}|([a-f0-9]{1,4}:){3}:([a-f0-9]{1,4}:){0,3}|([a-f0-9]{1,4}:){4}:([a-f0-9]{1,4}:){0,2}|([a-f0-9]{1,4}:){5}:([a-f0-9]{1,4}:){0,1})([a-f0-9]{1,4}|(((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2}))\.){3}((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2})))\])|([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])*(\.[A-Za-z]{2,})+))$/;
// from https://thekevinscott.com/emojis-in-javascript/#writing-a-regular-expression
const emojiRegex = /^(\p{Extended_Pictographic}|\p{Emoji_Component})+$/u;
const ipv4Regex = /^(((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2}))\.){3}((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2}))$/;
const ipv6Regex = /^(([a-f0-9]{1,4}:){7}|::([a-f0-9]{1,4}:){0,6}|([a-f0-9]{1,4}:){1}:([a-f0-9]{1,4}:){0,5}|([a-f0-9]{1,4}:){2}:([a-f0-9]{1,4}:){0,4}|([a-f0-9]{1,4}:){3}:([a-f0-9]{1,4}:){0,3}|([a-f0-9]{1,4}:){4}:([a-f0-9]{1,4}:){0,2}|([a-f0-9]{1,4}:){5}:([a-f0-9]{1,4}:){0,1})([a-f0-9]{1,4}|(((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2}))\.){3}((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2})))$/;
// Adapted from https://stackoverflow.com/a/3143231
const datetimeRegex = (args) => {
    if (args.precision) {
        if (args.offset) {
            return new RegExp(`^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{${args.precision}}(([+-]\\d{2}(:?\\d{2})?)|Z)$`);
        }
        else {
            return new RegExp(`^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{${args.precision}}Z$`);
        }
    }
    else if (args.precision === 0) {
        if (args.offset) {
            return new RegExp(`^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(([+-]\\d{2}(:?\\d{2})?)|Z)$`);
        }
        else {
            return new RegExp(`^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$`);
        }
    }
    else {
        if (args.offset) {
            return new RegExp(`^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(([+-]\\d{2}(:?\\d{2})?)|Z)$`);
        }
        else {
            return new RegExp(`^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z$`);
        }
    }
};
function isValidIP(ip, version) {
    if ((version === "v4" || !version) && ipv4Regex.test(ip)) {
        return true;
    }
    if ((version === "v6" || !version) && ipv6Regex.test(ip)) {
        return true;
    }
    return false;
}
class ZodString extends ZodType {
    constructor() {
        super(...arguments);
        this._regex = (regex, validation, message) => this.refinement((data) => regex.test(data), {
            validation,
            code: ZodIssueCode.invalid_string,
            ...errorUtil.errToObj(message),
        });
        /**
         * @deprecated Use z.string().min(1) instead.
         * @see {@link ZodString.min}
         */
        this.nonempty = (message) => this.min(1, errorUtil.errToObj(message));
        this.trim = () => new ZodString({
            ...this._def,
            checks: [...this._def.checks, { kind: "trim" }],
        });
        this.toLowerCase = () => new ZodString({
            ...this._def,
            checks: [...this._def.checks, { kind: "toLowerCase" }],
        });
        this.toUpperCase = () => new ZodString({
            ...this._def,
            checks: [...this._def.checks, { kind: "toUpperCase" }],
        });
    }
    _parse(input) {
        if (this._def.coerce) {
            input.data = String(input.data);
        }
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.string) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.string,
                received: ctx.parsedType,
            }
            //
            );
            return INVALID;
        }
        const status = new ParseStatus();
        let ctx = undefined;
        for (const check of this._def.checks) {
            if (check.kind === "min") {
                if (input.data.length < check.value) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.too_small,
                        minimum: check.value,
                        type: "string",
                        inclusive: true,
                        exact: false,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "max") {
                if (input.data.length > check.value) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.too_big,
                        maximum: check.value,
                        type: "string",
                        inclusive: true,
                        exact: false,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "length") {
                const tooBig = input.data.length > check.value;
                const tooSmall = input.data.length < check.value;
                if (tooBig || tooSmall) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    if (tooBig) {
                        addIssueToContext(ctx, {
                            code: ZodIssueCode.too_big,
                            maximum: check.value,
                            type: "string",
                            inclusive: true,
                            exact: true,
                            message: check.message,
                        });
                    }
                    else if (tooSmall) {
                        addIssueToContext(ctx, {
                            code: ZodIssueCode.too_small,
                            minimum: check.value,
                            type: "string",
                            inclusive: true,
                            exact: true,
                            message: check.message,
                        });
                    }
                    status.dirty();
                }
            }
            else if (check.kind === "email") {
                if (!emailRegex.test(input.data)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        validation: "email",
                        code: ZodIssueCode.invalid_string,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "emoji") {
                if (!emojiRegex.test(input.data)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        validation: "emoji",
                        code: ZodIssueCode.invalid_string,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "uuid") {
                if (!uuidRegex.test(input.data)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        validation: "uuid",
                        code: ZodIssueCode.invalid_string,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "cuid") {
                if (!cuidRegex.test(input.data)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        validation: "cuid",
                        code: ZodIssueCode.invalid_string,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "cuid2") {
                if (!cuid2Regex.test(input.data)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        validation: "cuid2",
                        code: ZodIssueCode.invalid_string,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "ulid") {
                if (!ulidRegex.test(input.data)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        validation: "ulid",
                        code: ZodIssueCode.invalid_string,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "url") {
                try {
                    new URL(input.data);
                }
                catch (_a) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        validation: "url",
                        code: ZodIssueCode.invalid_string,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "regex") {
                check.regex.lastIndex = 0;
                const testResult = check.regex.test(input.data);
                if (!testResult) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        validation: "regex",
                        code: ZodIssueCode.invalid_string,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "trim") {
                input.data = input.data.trim();
            }
            else if (check.kind === "includes") {
                if (!input.data.includes(check.value, check.position)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.invalid_string,
                        validation: { includes: check.value, position: check.position },
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "toLowerCase") {
                input.data = input.data.toLowerCase();
            }
            else if (check.kind === "toUpperCase") {
                input.data = input.data.toUpperCase();
            }
            else if (check.kind === "startsWith") {
                if (!input.data.startsWith(check.value)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.invalid_string,
                        validation: { startsWith: check.value },
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "endsWith") {
                if (!input.data.endsWith(check.value)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.invalid_string,
                        validation: { endsWith: check.value },
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "datetime") {
                const regex = datetimeRegex(check);
                if (!regex.test(input.data)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.invalid_string,
                        validation: "datetime",
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "ip") {
                if (!isValidIP(input.data, check.version)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        validation: "ip",
                        code: ZodIssueCode.invalid_string,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else {
                util.assertNever(check);
            }
        }
        return { status: status.value, value: input.data };
    }
    _addCheck(check) {
        return new ZodString({
            ...this._def,
            checks: [...this._def.checks, check],
        });
    }
    email(message) {
        return this._addCheck({ kind: "email", ...errorUtil.errToObj(message) });
    }
    url(message) {
        return this._addCheck({ kind: "url", ...errorUtil.errToObj(message) });
    }
    emoji(message) {
        return this._addCheck({ kind: "emoji", ...errorUtil.errToObj(message) });
    }
    uuid(message) {
        return this._addCheck({ kind: "uuid", ...errorUtil.errToObj(message) });
    }
    cuid(message) {
        return this._addCheck({ kind: "cuid", ...errorUtil.errToObj(message) });
    }
    cuid2(message) {
        return this._addCheck({ kind: "cuid2", ...errorUtil.errToObj(message) });
    }
    ulid(message) {
        return this._addCheck({ kind: "ulid", ...errorUtil.errToObj(message) });
    }
    ip(options) {
        return this._addCheck({ kind: "ip", ...errorUtil.errToObj(options) });
    }
    datetime(options) {
        var _a;
        if (typeof options === "string") {
            return this._addCheck({
                kind: "datetime",
                precision: null,
                offset: false,
                message: options,
            });
        }
        return this._addCheck({
            kind: "datetime",
            precision: typeof (options === null || options === void 0 ? void 0 : options.precision) === "undefined" ? null : options === null || options === void 0 ? void 0 : options.precision,
            offset: (_a = options === null || options === void 0 ? void 0 : options.offset) !== null && _a !== void 0 ? _a : false,
            ...errorUtil.errToObj(options === null || options === void 0 ? void 0 : options.message),
        });
    }
    regex(regex, message) {
        return this._addCheck({
            kind: "regex",
            regex: regex,
            ...errorUtil.errToObj(message),
        });
    }
    includes(value, options) {
        return this._addCheck({
            kind: "includes",
            value: value,
            position: options === null || options === void 0 ? void 0 : options.position,
            ...errorUtil.errToObj(options === null || options === void 0 ? void 0 : options.message),
        });
    }
    startsWith(value, message) {
        return this._addCheck({
            kind: "startsWith",
            value: value,
            ...errorUtil.errToObj(message),
        });
    }
    endsWith(value, message) {
        return this._addCheck({
            kind: "endsWith",
            value: value,
            ...errorUtil.errToObj(message),
        });
    }
    min(minLength, message) {
        return this._addCheck({
            kind: "min",
            value: minLength,
            ...errorUtil.errToObj(message),
        });
    }
    max(maxLength, message) {
        return this._addCheck({
            kind: "max",
            value: maxLength,
            ...errorUtil.errToObj(message),
        });
    }
    length(len, message) {
        return this._addCheck({
            kind: "length",
            value: len,
            ...errorUtil.errToObj(message),
        });
    }
    get isDatetime() {
        return !!this._def.checks.find((ch) => ch.kind === "datetime");
    }
    get isEmail() {
        return !!this._def.checks.find((ch) => ch.kind === "email");
    }
    get isURL() {
        return !!this._def.checks.find((ch) => ch.kind === "url");
    }
    get isEmoji() {
        return !!this._def.checks.find((ch) => ch.kind === "emoji");
    }
    get isUUID() {
        return !!this._def.checks.find((ch) => ch.kind === "uuid");
    }
    get isCUID() {
        return !!this._def.checks.find((ch) => ch.kind === "cuid");
    }
    get isCUID2() {
        return !!this._def.checks.find((ch) => ch.kind === "cuid2");
    }
    get isULID() {
        return !!this._def.checks.find((ch) => ch.kind === "ulid");
    }
    get isIP() {
        return !!this._def.checks.find((ch) => ch.kind === "ip");
    }
    get minLength() {
        let min = null;
        for (const ch of this._def.checks) {
            if (ch.kind === "min") {
                if (min === null || ch.value > min)
                    min = ch.value;
            }
        }
        return min;
    }
    get maxLength() {
        let max = null;
        for (const ch of this._def.checks) {
            if (ch.kind === "max") {
                if (max === null || ch.value < max)
                    max = ch.value;
            }
        }
        return max;
    }
}
ZodString.create = (params) => {
    var _a;
    return new ZodString({
        checks: [],
        typeName: ZodFirstPartyTypeKind.ZodString,
        coerce: (_a = params === null || params === void 0 ? void 0 : params.coerce) !== null && _a !== void 0 ? _a : false,
        ...processCreateParams(params),
    });
};
// https://stackoverflow.com/questions/3966484/why-does-modulus-operator-return-fractional-number-in-javascript/31711034#31711034
function floatSafeRemainder(val, step) {
    const valDecCount = (val.toString().split(".")[1] || "").length;
    const stepDecCount = (step.toString().split(".")[1] || "").length;
    const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
    const valInt = parseInt(val.toFixed(decCount).replace(".", ""));
    const stepInt = parseInt(step.toFixed(decCount).replace(".", ""));
    return (valInt % stepInt) / Math.pow(10, decCount);
}
class ZodNumber extends ZodType {
    constructor() {
        super(...arguments);
        this.min = this.gte;
        this.max = this.lte;
        this.step = this.multipleOf;
    }
    _parse(input) {
        if (this._def.coerce) {
            input.data = Number(input.data);
        }
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.number) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.number,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        let ctx = undefined;
        const status = new ParseStatus();
        for (const check of this._def.checks) {
            if (check.kind === "int") {
                if (!util.isInteger(input.data)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.invalid_type,
                        expected: "integer",
                        received: "float",
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "min") {
                const tooSmall = check.inclusive
                    ? input.data < check.value
                    : input.data <= check.value;
                if (tooSmall) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.too_small,
                        minimum: check.value,
                        type: "number",
                        inclusive: check.inclusive,
                        exact: false,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "max") {
                const tooBig = check.inclusive
                    ? input.data > check.value
                    : input.data >= check.value;
                if (tooBig) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.too_big,
                        maximum: check.value,
                        type: "number",
                        inclusive: check.inclusive,
                        exact: false,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "multipleOf") {
                if (floatSafeRemainder(input.data, check.value) !== 0) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.not_multiple_of,
                        multipleOf: check.value,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "finite") {
                if (!Number.isFinite(input.data)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.not_finite,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else {
                util.assertNever(check);
            }
        }
        return { status: status.value, value: input.data };
    }
    gte(value, message) {
        return this.setLimit("min", value, true, errorUtil.toString(message));
    }
    gt(value, message) {
        return this.setLimit("min", value, false, errorUtil.toString(message));
    }
    lte(value, message) {
        return this.setLimit("max", value, true, errorUtil.toString(message));
    }
    lt(value, message) {
        return this.setLimit("max", value, false, errorUtil.toString(message));
    }
    setLimit(kind, value, inclusive, message) {
        return new ZodNumber({
            ...this._def,
            checks: [
                ...this._def.checks,
                {
                    kind,
                    value,
                    inclusive,
                    message: errorUtil.toString(message),
                },
            ],
        });
    }
    _addCheck(check) {
        return new ZodNumber({
            ...this._def,
            checks: [...this._def.checks, check],
        });
    }
    int(message) {
        return this._addCheck({
            kind: "int",
            message: errorUtil.toString(message),
        });
    }
    positive(message) {
        return this._addCheck({
            kind: "min",
            value: 0,
            inclusive: false,
            message: errorUtil.toString(message),
        });
    }
    negative(message) {
        return this._addCheck({
            kind: "max",
            value: 0,
            inclusive: false,
            message: errorUtil.toString(message),
        });
    }
    nonpositive(message) {
        return this._addCheck({
            kind: "max",
            value: 0,
            inclusive: true,
            message: errorUtil.toString(message),
        });
    }
    nonnegative(message) {
        return this._addCheck({
            kind: "min",
            value: 0,
            inclusive: true,
            message: errorUtil.toString(message),
        });
    }
    multipleOf(value, message) {
        return this._addCheck({
            kind: "multipleOf",
            value: value,
            message: errorUtil.toString(message),
        });
    }
    finite(message) {
        return this._addCheck({
            kind: "finite",
            message: errorUtil.toString(message),
        });
    }
    safe(message) {
        return this._addCheck({
            kind: "min",
            inclusive: true,
            value: Number.MIN_SAFE_INTEGER,
            message: errorUtil.toString(message),
        })._addCheck({
            kind: "max",
            inclusive: true,
            value: Number.MAX_SAFE_INTEGER,
            message: errorUtil.toString(message),
        });
    }
    get minValue() {
        let min = null;
        for (const ch of this._def.checks) {
            if (ch.kind === "min") {
                if (min === null || ch.value > min)
                    min = ch.value;
            }
        }
        return min;
    }
    get maxValue() {
        let max = null;
        for (const ch of this._def.checks) {
            if (ch.kind === "max") {
                if (max === null || ch.value < max)
                    max = ch.value;
            }
        }
        return max;
    }
    get isInt() {
        return !!this._def.checks.find((ch) => ch.kind === "int" ||
            (ch.kind === "multipleOf" && util.isInteger(ch.value)));
    }
    get isFinite() {
        let max = null, min = null;
        for (const ch of this._def.checks) {
            if (ch.kind === "finite" ||
                ch.kind === "int" ||
                ch.kind === "multipleOf") {
                return true;
            }
            else if (ch.kind === "min") {
                if (min === null || ch.value > min)
                    min = ch.value;
            }
            else if (ch.kind === "max") {
                if (max === null || ch.value < max)
                    max = ch.value;
            }
        }
        return Number.isFinite(min) && Number.isFinite(max);
    }
}
ZodNumber.create = (params) => {
    return new ZodNumber({
        checks: [],
        typeName: ZodFirstPartyTypeKind.ZodNumber,
        coerce: (params === null || params === void 0 ? void 0 : params.coerce) || false,
        ...processCreateParams(params),
    });
};
class ZodBigInt extends ZodType {
    constructor() {
        super(...arguments);
        this.min = this.gte;
        this.max = this.lte;
    }
    _parse(input) {
        if (this._def.coerce) {
            input.data = BigInt(input.data);
        }
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.bigint) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.bigint,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        let ctx = undefined;
        const status = new ParseStatus();
        for (const check of this._def.checks) {
            if (check.kind === "min") {
                const tooSmall = check.inclusive
                    ? input.data < check.value
                    : input.data <= check.value;
                if (tooSmall) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.too_small,
                        type: "bigint",
                        minimum: check.value,
                        inclusive: check.inclusive,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "max") {
                const tooBig = check.inclusive
                    ? input.data > check.value
                    : input.data >= check.value;
                if (tooBig) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.too_big,
                        type: "bigint",
                        maximum: check.value,
                        inclusive: check.inclusive,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "multipleOf") {
                if (input.data % check.value !== BigInt(0)) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.not_multiple_of,
                        multipleOf: check.value,
                        message: check.message,
                    });
                    status.dirty();
                }
            }
            else {
                util.assertNever(check);
            }
        }
        return { status: status.value, value: input.data };
    }
    gte(value, message) {
        return this.setLimit("min", value, true, errorUtil.toString(message));
    }
    gt(value, message) {
        return this.setLimit("min", value, false, errorUtil.toString(message));
    }
    lte(value, message) {
        return this.setLimit("max", value, true, errorUtil.toString(message));
    }
    lt(value, message) {
        return this.setLimit("max", value, false, errorUtil.toString(message));
    }
    setLimit(kind, value, inclusive, message) {
        return new ZodBigInt({
            ...this._def,
            checks: [
                ...this._def.checks,
                {
                    kind,
                    value,
                    inclusive,
                    message: errorUtil.toString(message),
                },
            ],
        });
    }
    _addCheck(check) {
        return new ZodBigInt({
            ...this._def,
            checks: [...this._def.checks, check],
        });
    }
    positive(message) {
        return this._addCheck({
            kind: "min",
            value: BigInt(0),
            inclusive: false,
            message: errorUtil.toString(message),
        });
    }
    negative(message) {
        return this._addCheck({
            kind: "max",
            value: BigInt(0),
            inclusive: false,
            message: errorUtil.toString(message),
        });
    }
    nonpositive(message) {
        return this._addCheck({
            kind: "max",
            value: BigInt(0),
            inclusive: true,
            message: errorUtil.toString(message),
        });
    }
    nonnegative(message) {
        return this._addCheck({
            kind: "min",
            value: BigInt(0),
            inclusive: true,
            message: errorUtil.toString(message),
        });
    }
    multipleOf(value, message) {
        return this._addCheck({
            kind: "multipleOf",
            value,
            message: errorUtil.toString(message),
        });
    }
    get minValue() {
        let min = null;
        for (const ch of this._def.checks) {
            if (ch.kind === "min") {
                if (min === null || ch.value > min)
                    min = ch.value;
            }
        }
        return min;
    }
    get maxValue() {
        let max = null;
        for (const ch of this._def.checks) {
            if (ch.kind === "max") {
                if (max === null || ch.value < max)
                    max = ch.value;
            }
        }
        return max;
    }
}
ZodBigInt.create = (params) => {
    var _a;
    return new ZodBigInt({
        checks: [],
        typeName: ZodFirstPartyTypeKind.ZodBigInt,
        coerce: (_a = params === null || params === void 0 ? void 0 : params.coerce) !== null && _a !== void 0 ? _a : false,
        ...processCreateParams(params),
    });
};
class ZodBoolean extends ZodType {
    _parse(input) {
        if (this._def.coerce) {
            input.data = Boolean(input.data);
        }
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.boolean) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.boolean,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        return OK(input.data);
    }
}
ZodBoolean.create = (params) => {
    return new ZodBoolean({
        typeName: ZodFirstPartyTypeKind.ZodBoolean,
        coerce: (params === null || params === void 0 ? void 0 : params.coerce) || false,
        ...processCreateParams(params),
    });
};
class ZodDate extends ZodType {
    _parse(input) {
        if (this._def.coerce) {
            input.data = new Date(input.data);
        }
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.date) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.date,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        if (isNaN(input.data.getTime())) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_date,
            });
            return INVALID;
        }
        const status = new ParseStatus();
        let ctx = undefined;
        for (const check of this._def.checks) {
            if (check.kind === "min") {
                if (input.data.getTime() < check.value) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.too_small,
                        message: check.message,
                        inclusive: true,
                        exact: false,
                        minimum: check.value,
                        type: "date",
                    });
                    status.dirty();
                }
            }
            else if (check.kind === "max") {
                if (input.data.getTime() > check.value) {
                    ctx = this._getOrReturnCtx(input, ctx);
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.too_big,
                        message: check.message,
                        inclusive: true,
                        exact: false,
                        maximum: check.value,
                        type: "date",
                    });
                    status.dirty();
                }
            }
            else {
                util.assertNever(check);
            }
        }
        return {
            status: status.value,
            value: new Date(input.data.getTime()),
        };
    }
    _addCheck(check) {
        return new ZodDate({
            ...this._def,
            checks: [...this._def.checks, check],
        });
    }
    min(minDate, message) {
        return this._addCheck({
            kind: "min",
            value: minDate.getTime(),
            message: errorUtil.toString(message),
        });
    }
    max(maxDate, message) {
        return this._addCheck({
            kind: "max",
            value: maxDate.getTime(),
            message: errorUtil.toString(message),
        });
    }
    get minDate() {
        let min = null;
        for (const ch of this._def.checks) {
            if (ch.kind === "min") {
                if (min === null || ch.value > min)
                    min = ch.value;
            }
        }
        return min != null ? new Date(min) : null;
    }
    get maxDate() {
        let max = null;
        for (const ch of this._def.checks) {
            if (ch.kind === "max") {
                if (max === null || ch.value < max)
                    max = ch.value;
            }
        }
        return max != null ? new Date(max) : null;
    }
}
ZodDate.create = (params) => {
    return new ZodDate({
        checks: [],
        coerce: (params === null || params === void 0 ? void 0 : params.coerce) || false,
        typeName: ZodFirstPartyTypeKind.ZodDate,
        ...processCreateParams(params),
    });
};
class ZodSymbol extends ZodType {
    _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.symbol) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.symbol,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        return OK(input.data);
    }
}
ZodSymbol.create = (params) => {
    return new ZodSymbol({
        typeName: ZodFirstPartyTypeKind.ZodSymbol,
        ...processCreateParams(params),
    });
};
class ZodUndefined extends ZodType {
    _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.undefined) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.undefined,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        return OK(input.data);
    }
}
ZodUndefined.create = (params) => {
    return new ZodUndefined({
        typeName: ZodFirstPartyTypeKind.ZodUndefined,
        ...processCreateParams(params),
    });
};
class ZodNull extends ZodType {
    _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.null) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.null,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        return OK(input.data);
    }
}
ZodNull.create = (params) => {
    return new ZodNull({
        typeName: ZodFirstPartyTypeKind.ZodNull,
        ...processCreateParams(params),
    });
};
class ZodAny extends ZodType {
    constructor() {
        super(...arguments);
        // to prevent instances of other classes from extending ZodAny. this causes issues with catchall in ZodObject.
        this._any = true;
    }
    _parse(input) {
        return OK(input.data);
    }
}
ZodAny.create = (params) => {
    return new ZodAny({
        typeName: ZodFirstPartyTypeKind.ZodAny,
        ...processCreateParams(params),
    });
};
class ZodUnknown extends ZodType {
    constructor() {
        super(...arguments);
        // required
        this._unknown = true;
    }
    _parse(input) {
        return OK(input.data);
    }
}
ZodUnknown.create = (params) => {
    return new ZodUnknown({
        typeName: ZodFirstPartyTypeKind.ZodUnknown,
        ...processCreateParams(params),
    });
};
class ZodNever extends ZodType {
    _parse(input) {
        const ctx = this._getOrReturnCtx(input);
        addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: ZodParsedType.never,
            received: ctx.parsedType,
        });
        return INVALID;
    }
}
ZodNever.create = (params) => {
    return new ZodNever({
        typeName: ZodFirstPartyTypeKind.ZodNever,
        ...processCreateParams(params),
    });
};
class ZodVoid extends ZodType {
    _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.undefined) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.void,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        return OK(input.data);
    }
}
ZodVoid.create = (params) => {
    return new ZodVoid({
        typeName: ZodFirstPartyTypeKind.ZodVoid,
        ...processCreateParams(params),
    });
};
class ZodArray extends ZodType {
    _parse(input) {
        const { ctx, status } = this._processInputParams(input);
        const def = this._def;
        if (ctx.parsedType !== ZodParsedType.array) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.array,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        if (def.exactLength !== null) {
            const tooBig = ctx.data.length > def.exactLength.value;
            const tooSmall = ctx.data.length < def.exactLength.value;
            if (tooBig || tooSmall) {
                addIssueToContext(ctx, {
                    code: tooBig ? ZodIssueCode.too_big : ZodIssueCode.too_small,
                    minimum: (tooSmall ? def.exactLength.value : undefined),
                    maximum: (tooBig ? def.exactLength.value : undefined),
                    type: "array",
                    inclusive: true,
                    exact: true,
                    message: def.exactLength.message,
                });
                status.dirty();
            }
        }
        if (def.minLength !== null) {
            if (ctx.data.length < def.minLength.value) {
                addIssueToContext(ctx, {
                    code: ZodIssueCode.too_small,
                    minimum: def.minLength.value,
                    type: "array",
                    inclusive: true,
                    exact: false,
                    message: def.minLength.message,
                });
                status.dirty();
            }
        }
        if (def.maxLength !== null) {
            if (ctx.data.length > def.maxLength.value) {
                addIssueToContext(ctx, {
                    code: ZodIssueCode.too_big,
                    maximum: def.maxLength.value,
                    type: "array",
                    inclusive: true,
                    exact: false,
                    message: def.maxLength.message,
                });
                status.dirty();
            }
        }
        if (ctx.common.async) {
            return Promise.all([...ctx.data].map((item, i) => {
                return def.type._parseAsync(new ParseInputLazyPath(ctx, item, ctx.path, i));
            })).then((result) => {
                return ParseStatus.mergeArray(status, result);
            });
        }
        const result = [...ctx.data].map((item, i) => {
            return def.type._parseSync(new ParseInputLazyPath(ctx, item, ctx.path, i));
        });
        return ParseStatus.mergeArray(status, result);
    }
    get element() {
        return this._def.type;
    }
    min(minLength, message) {
        return new ZodArray({
            ...this._def,
            minLength: { value: minLength, message: errorUtil.toString(message) },
        });
    }
    max(maxLength, message) {
        return new ZodArray({
            ...this._def,
            maxLength: { value: maxLength, message: errorUtil.toString(message) },
        });
    }
    length(len, message) {
        return new ZodArray({
            ...this._def,
            exactLength: { value: len, message: errorUtil.toString(message) },
        });
    }
    nonempty(message) {
        return this.min(1, message);
    }
}
ZodArray.create = (schema, params) => {
    return new ZodArray({
        type: schema,
        minLength: null,
        maxLength: null,
        exactLength: null,
        typeName: ZodFirstPartyTypeKind.ZodArray,
        ...processCreateParams(params),
    });
};
function deepPartialify(schema) {
    if (schema instanceof ZodObject) {
        const newShape = {};
        for (const key in schema.shape) {
            const fieldSchema = schema.shape[key];
            newShape[key] = ZodOptional.create(deepPartialify(fieldSchema));
        }
        return new ZodObject({
            ...schema._def,
            shape: () => newShape,
        });
    }
    else if (schema instanceof ZodArray) {
        return new ZodArray({
            ...schema._def,
            type: deepPartialify(schema.element),
        });
    }
    else if (schema instanceof ZodOptional) {
        return ZodOptional.create(deepPartialify(schema.unwrap()));
    }
    else if (schema instanceof ZodNullable) {
        return ZodNullable.create(deepPartialify(schema.unwrap()));
    }
    else if (schema instanceof ZodTuple) {
        return ZodTuple.create(schema.items.map((item) => deepPartialify(item)));
    }
    else {
        return schema;
    }
}
class ZodObject extends ZodType {
    constructor() {
        super(...arguments);
        this._cached = null;
        /**
         * @deprecated In most cases, this is no longer needed - unknown properties are now silently stripped.
         * If you want to pass through unknown properties, use `.passthrough()` instead.
         */
        this.nonstrict = this.passthrough;
        // extend<
        //   Augmentation extends ZodRawShape,
        //   NewOutput extends util.flatten<{
        //     [k in keyof Augmentation | keyof Output]: k extends keyof Augmentation
        //       ? Augmentation[k]["_output"]
        //       : k extends keyof Output
        //       ? Output[k]
        //       : never;
        //   }>,
        //   NewInput extends util.flatten<{
        //     [k in keyof Augmentation | keyof Input]: k extends keyof Augmentation
        //       ? Augmentation[k]["_input"]
        //       : k extends keyof Input
        //       ? Input[k]
        //       : never;
        //   }>
        // >(
        //   augmentation: Augmentation
        // ): ZodObject<
        //   extendShape<T, Augmentation>,
        //   UnknownKeys,
        //   Catchall,
        //   NewOutput,
        //   NewInput
        // > {
        //   return new ZodObject({
        //     ...this._def,
        //     shape: () => ({
        //       ...this._def.shape(),
        //       ...augmentation,
        //     }),
        //   }) as any;
        // }
        /**
         * @deprecated Use `.extend` instead
         *  */
        this.augment = this.extend;
    }
    _getCached() {
        if (this._cached !== null)
            return this._cached;
        const shape = this._def.shape();
        const keys = util.objectKeys(shape);
        return (this._cached = { shape, keys });
    }
    _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.object) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.object,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        const { status, ctx } = this._processInputParams(input);
        const { shape, keys: shapeKeys } = this._getCached();
        const extraKeys = [];
        if (!(this._def.catchall instanceof ZodNever &&
            this._def.unknownKeys === "strip")) {
            for (const key in ctx.data) {
                if (!shapeKeys.includes(key)) {
                    extraKeys.push(key);
                }
            }
        }
        const pairs = [];
        for (const key of shapeKeys) {
            const keyValidator = shape[key];
            const value = ctx.data[key];
            pairs.push({
                key: { status: "valid", value: key },
                value: keyValidator._parse(new ParseInputLazyPath(ctx, value, ctx.path, key)),
                alwaysSet: key in ctx.data,
            });
        }
        if (this._def.catchall instanceof ZodNever) {
            const unknownKeys = this._def.unknownKeys;
            if (unknownKeys === "passthrough") {
                for (const key of extraKeys) {
                    pairs.push({
                        key: { status: "valid", value: key },
                        value: { status: "valid", value: ctx.data[key] },
                    });
                }
            }
            else if (unknownKeys === "strict") {
                if (extraKeys.length > 0) {
                    addIssueToContext(ctx, {
                        code: ZodIssueCode.unrecognized_keys,
                        keys: extraKeys,
                    });
                    status.dirty();
                }
            }
            else if (unknownKeys === "strip") ;
            else {
                throw new Error(`Internal ZodObject error: invalid unknownKeys value.`);
            }
        }
        else {
            // run catchall validation
            const catchall = this._def.catchall;
            for (const key of extraKeys) {
                const value = ctx.data[key];
                pairs.push({
                    key: { status: "valid", value: key },
                    value: catchall._parse(new ParseInputLazyPath(ctx, value, ctx.path, key) //, ctx.child(key), value, getParsedType(value)
                    ),
                    alwaysSet: key in ctx.data,
                });
            }
        }
        if (ctx.common.async) {
            return Promise.resolve()
                .then(async () => {
                const syncPairs = [];
                for (const pair of pairs) {
                    const key = await pair.key;
                    syncPairs.push({
                        key,
                        value: await pair.value,
                        alwaysSet: pair.alwaysSet,
                    });
                }
                return syncPairs;
            })
                .then((syncPairs) => {
                return ParseStatus.mergeObjectSync(status, syncPairs);
            });
        }
        else {
            return ParseStatus.mergeObjectSync(status, pairs);
        }
    }
    get shape() {
        return this._def.shape();
    }
    strict(message) {
        return new ZodObject({
            ...this._def,
            unknownKeys: "strict",
            ...(message !== undefined
                ? {
                    errorMap: (issue, ctx) => {
                        var _a, _b, _c, _d;
                        const defaultError = (_c = (_b = (_a = this._def).errorMap) === null || _b === void 0 ? void 0 : _b.call(_a, issue, ctx).message) !== null && _c !== void 0 ? _c : ctx.defaultError;
                        if (issue.code === "unrecognized_keys")
                            return {
                                message: (_d = errorUtil.errToObj(message).message) !== null && _d !== void 0 ? _d : defaultError,
                            };
                        return {
                            message: defaultError,
                        };
                    },
                }
                : {}),
        });
    }
    strip() {
        return new ZodObject({
            ...this._def,
            unknownKeys: "strip",
        });
    }
    passthrough() {
        return new ZodObject({
            ...this._def,
            unknownKeys: "passthrough",
        });
    }
    // const AugmentFactory =
    //   <Def extends ZodObjectDef>(def: Def) =>
    //   <Augmentation extends ZodRawShape>(
    //     augmentation: Augmentation
    //   ): ZodObject<
    //     extendShape<ReturnType<Def["shape"]>, Augmentation>,
    //     Def["unknownKeys"],
    //     Def["catchall"]
    //   > => {
    //     return new ZodObject({
    //       ...def,
    //       shape: () => ({
    //         ...def.shape(),
    //         ...augmentation,
    //       }),
    //     }) as any;
    //   };
    extend(augmentation) {
        return new ZodObject({
            ...this._def,
            shape: () => ({
                ...this._def.shape(),
                ...augmentation,
            }),
        });
    }
    /**
     * Prior to zod@1.0.12 there was a bug in the
     * inferred type of merged objects. Please
     * upgrade if you are experiencing issues.
     */
    merge(merging) {
        const merged = new ZodObject({
            unknownKeys: merging._def.unknownKeys,
            catchall: merging._def.catchall,
            shape: () => ({
                ...this._def.shape(),
                ...merging._def.shape(),
            }),
            typeName: ZodFirstPartyTypeKind.ZodObject,
        });
        return merged;
    }
    // merge<
    //   Incoming extends AnyZodObject,
    //   Augmentation extends Incoming["shape"],
    //   NewOutput extends {
    //     [k in keyof Augmentation | keyof Output]: k extends keyof Augmentation
    //       ? Augmentation[k]["_output"]
    //       : k extends keyof Output
    //       ? Output[k]
    //       : never;
    //   },
    //   NewInput extends {
    //     [k in keyof Augmentation | keyof Input]: k extends keyof Augmentation
    //       ? Augmentation[k]["_input"]
    //       : k extends keyof Input
    //       ? Input[k]
    //       : never;
    //   }
    // >(
    //   merging: Incoming
    // ): ZodObject<
    //   extendShape<T, ReturnType<Incoming["_def"]["shape"]>>,
    //   Incoming["_def"]["unknownKeys"],
    //   Incoming["_def"]["catchall"],
    //   NewOutput,
    //   NewInput
    // > {
    //   const merged: any = new ZodObject({
    //     unknownKeys: merging._def.unknownKeys,
    //     catchall: merging._def.catchall,
    //     shape: () =>
    //       objectUtil.mergeShapes(this._def.shape(), merging._def.shape()),
    //     typeName: ZodFirstPartyTypeKind.ZodObject,
    //   }) as any;
    //   return merged;
    // }
    setKey(key, schema) {
        return this.augment({ [key]: schema });
    }
    // merge<Incoming extends AnyZodObject>(
    //   merging: Incoming
    // ): //ZodObject<T & Incoming["_shape"], UnknownKeys, Catchall> = (merging) => {
    // ZodObject<
    //   extendShape<T, ReturnType<Incoming["_def"]["shape"]>>,
    //   Incoming["_def"]["unknownKeys"],
    //   Incoming["_def"]["catchall"]
    // > {
    //   // const mergedShape = objectUtil.mergeShapes(
    //   //   this._def.shape(),
    //   //   merging._def.shape()
    //   // );
    //   const merged: any = new ZodObject({
    //     unknownKeys: merging._def.unknownKeys,
    //     catchall: merging._def.catchall,
    //     shape: () =>
    //       objectUtil.mergeShapes(this._def.shape(), merging._def.shape()),
    //     typeName: ZodFirstPartyTypeKind.ZodObject,
    //   }) as any;
    //   return merged;
    // }
    catchall(index) {
        return new ZodObject({
            ...this._def,
            catchall: index,
        });
    }
    pick(mask) {
        const shape = {};
        util.objectKeys(mask).forEach((key) => {
            if (mask[key] && this.shape[key]) {
                shape[key] = this.shape[key];
            }
        });
        return new ZodObject({
            ...this._def,
            shape: () => shape,
        });
    }
    omit(mask) {
        const shape = {};
        util.objectKeys(this.shape).forEach((key) => {
            if (!mask[key]) {
                shape[key] = this.shape[key];
            }
        });
        return new ZodObject({
            ...this._def,
            shape: () => shape,
        });
    }
    /**
     * @deprecated
     */
    deepPartial() {
        return deepPartialify(this);
    }
    partial(mask) {
        const newShape = {};
        util.objectKeys(this.shape).forEach((key) => {
            const fieldSchema = this.shape[key];
            if (mask && !mask[key]) {
                newShape[key] = fieldSchema;
            }
            else {
                newShape[key] = fieldSchema.optional();
            }
        });
        return new ZodObject({
            ...this._def,
            shape: () => newShape,
        });
    }
    required(mask) {
        const newShape = {};
        util.objectKeys(this.shape).forEach((key) => {
            if (mask && !mask[key]) {
                newShape[key] = this.shape[key];
            }
            else {
                const fieldSchema = this.shape[key];
                let newField = fieldSchema;
                while (newField instanceof ZodOptional) {
                    newField = newField._def.innerType;
                }
                newShape[key] = newField;
            }
        });
        return new ZodObject({
            ...this._def,
            shape: () => newShape,
        });
    }
    keyof() {
        return createZodEnum(util.objectKeys(this.shape));
    }
}
ZodObject.create = (shape, params) => {
    return new ZodObject({
        shape: () => shape,
        unknownKeys: "strip",
        catchall: ZodNever.create(),
        typeName: ZodFirstPartyTypeKind.ZodObject,
        ...processCreateParams(params),
    });
};
ZodObject.strictCreate = (shape, params) => {
    return new ZodObject({
        shape: () => shape,
        unknownKeys: "strict",
        catchall: ZodNever.create(),
        typeName: ZodFirstPartyTypeKind.ZodObject,
        ...processCreateParams(params),
    });
};
ZodObject.lazycreate = (shape, params) => {
    return new ZodObject({
        shape,
        unknownKeys: "strip",
        catchall: ZodNever.create(),
        typeName: ZodFirstPartyTypeKind.ZodObject,
        ...processCreateParams(params),
    });
};
class ZodUnion extends ZodType {
    _parse(input) {
        const { ctx } = this._processInputParams(input);
        const options = this._def.options;
        function handleResults(results) {
            // return first issue-free validation if it exists
            for (const result of results) {
                if (result.result.status === "valid") {
                    return result.result;
                }
            }
            for (const result of results) {
                if (result.result.status === "dirty") {
                    // add issues from dirty option
                    ctx.common.issues.push(...result.ctx.common.issues);
                    return result.result;
                }
            }
            // return invalid
            const unionErrors = results.map((result) => new ZodError(result.ctx.common.issues));
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_union,
                unionErrors,
            });
            return INVALID;
        }
        if (ctx.common.async) {
            return Promise.all(options.map(async (option) => {
                const childCtx = {
                    ...ctx,
                    common: {
                        ...ctx.common,
                        issues: [],
                    },
                    parent: null,
                };
                return {
                    result: await option._parseAsync({
                        data: ctx.data,
                        path: ctx.path,
                        parent: childCtx,
                    }),
                    ctx: childCtx,
                };
            })).then(handleResults);
        }
        else {
            let dirty = undefined;
            const issues = [];
            for (const option of options) {
                const childCtx = {
                    ...ctx,
                    common: {
                        ...ctx.common,
                        issues: [],
                    },
                    parent: null,
                };
                const result = option._parseSync({
                    data: ctx.data,
                    path: ctx.path,
                    parent: childCtx,
                });
                if (result.status === "valid") {
                    return result;
                }
                else if (result.status === "dirty" && !dirty) {
                    dirty = { result, ctx: childCtx };
                }
                if (childCtx.common.issues.length) {
                    issues.push(childCtx.common.issues);
                }
            }
            if (dirty) {
                ctx.common.issues.push(...dirty.ctx.common.issues);
                return dirty.result;
            }
            const unionErrors = issues.map((issues) => new ZodError(issues));
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_union,
                unionErrors,
            });
            return INVALID;
        }
    }
    get options() {
        return this._def.options;
    }
}
ZodUnion.create = (types, params) => {
    return new ZodUnion({
        options: types,
        typeName: ZodFirstPartyTypeKind.ZodUnion,
        ...processCreateParams(params),
    });
};
/////////////////////////////////////////////////////
/////////////////////////////////////////////////////
//////////                                 //////////
//////////      ZodDiscriminatedUnion      //////////
//////////                                 //////////
/////////////////////////////////////////////////////
/////////////////////////////////////////////////////
const getDiscriminator = (type) => {
    if (type instanceof ZodLazy) {
        return getDiscriminator(type.schema);
    }
    else if (type instanceof ZodEffects) {
        return getDiscriminator(type.innerType());
    }
    else if (type instanceof ZodLiteral) {
        return [type.value];
    }
    else if (type instanceof ZodEnum) {
        return type.options;
    }
    else if (type instanceof ZodNativeEnum) {
        // eslint-disable-next-line ban/ban
        return Object.keys(type.enum);
    }
    else if (type instanceof ZodDefault) {
        return getDiscriminator(type._def.innerType);
    }
    else if (type instanceof ZodUndefined) {
        return [undefined];
    }
    else if (type instanceof ZodNull) {
        return [null];
    }
    else {
        return null;
    }
};
class ZodDiscriminatedUnion extends ZodType {
    _parse(input) {
        const { ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.object) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.object,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        const discriminator = this.discriminator;
        const discriminatorValue = ctx.data[discriminator];
        const option = this.optionsMap.get(discriminatorValue);
        if (!option) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_union_discriminator,
                options: Array.from(this.optionsMap.keys()),
                path: [discriminator],
            });
            return INVALID;
        }
        if (ctx.common.async) {
            return option._parseAsync({
                data: ctx.data,
                path: ctx.path,
                parent: ctx,
            });
        }
        else {
            return option._parseSync({
                data: ctx.data,
                path: ctx.path,
                parent: ctx,
            });
        }
    }
    get discriminator() {
        return this._def.discriminator;
    }
    get options() {
        return this._def.options;
    }
    get optionsMap() {
        return this._def.optionsMap;
    }
    /**
     * The constructor of the discriminated union schema. Its behaviour is very similar to that of the normal z.union() constructor.
     * However, it only allows a union of objects, all of which need to share a discriminator property. This property must
     * have a different value for each object in the union.
     * @param discriminator the name of the discriminator property
     * @param types an array of object schemas
     * @param params
     */
    static create(discriminator, options, params) {
        // Get all the valid discriminator values
        const optionsMap = new Map();
        // try {
        for (const type of options) {
            const discriminatorValues = getDiscriminator(type.shape[discriminator]);
            if (!discriminatorValues) {
                throw new Error(`A discriminator value for key \`${discriminator}\` could not be extracted from all schema options`);
            }
            for (const value of discriminatorValues) {
                if (optionsMap.has(value)) {
                    throw new Error(`Discriminator property ${String(discriminator)} has duplicate value ${String(value)}`);
                }
                optionsMap.set(value, type);
            }
        }
        return new ZodDiscriminatedUnion({
            typeName: ZodFirstPartyTypeKind.ZodDiscriminatedUnion,
            discriminator,
            options,
            optionsMap,
            ...processCreateParams(params),
        });
    }
}
function mergeValues(a, b) {
    const aType = getParsedType(a);
    const bType = getParsedType(b);
    if (a === b) {
        return { valid: true, data: a };
    }
    else if (aType === ZodParsedType.object && bType === ZodParsedType.object) {
        const bKeys = util.objectKeys(b);
        const sharedKeys = util
            .objectKeys(a)
            .filter((key) => bKeys.indexOf(key) !== -1);
        const newObj = { ...a, ...b };
        for (const key of sharedKeys) {
            const sharedValue = mergeValues(a[key], b[key]);
            if (!sharedValue.valid) {
                return { valid: false };
            }
            newObj[key] = sharedValue.data;
        }
        return { valid: true, data: newObj };
    }
    else if (aType === ZodParsedType.array && bType === ZodParsedType.array) {
        if (a.length !== b.length) {
            return { valid: false };
        }
        const newArray = [];
        for (let index = 0; index < a.length; index++) {
            const itemA = a[index];
            const itemB = b[index];
            const sharedValue = mergeValues(itemA, itemB);
            if (!sharedValue.valid) {
                return { valid: false };
            }
            newArray.push(sharedValue.data);
        }
        return { valid: true, data: newArray };
    }
    else if (aType === ZodParsedType.date &&
        bType === ZodParsedType.date &&
        +a === +b) {
        return { valid: true, data: a };
    }
    else {
        return { valid: false };
    }
}
class ZodIntersection extends ZodType {
    _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        const handleParsed = (parsedLeft, parsedRight) => {
            if (isAborted(parsedLeft) || isAborted(parsedRight)) {
                return INVALID;
            }
            const merged = mergeValues(parsedLeft.value, parsedRight.value);
            if (!merged.valid) {
                addIssueToContext(ctx, {
                    code: ZodIssueCode.invalid_intersection_types,
                });
                return INVALID;
            }
            if (isDirty(parsedLeft) || isDirty(parsedRight)) {
                status.dirty();
            }
            return { status: status.value, value: merged.data };
        };
        if (ctx.common.async) {
            return Promise.all([
                this._def.left._parseAsync({
                    data: ctx.data,
                    path: ctx.path,
                    parent: ctx,
                }),
                this._def.right._parseAsync({
                    data: ctx.data,
                    path: ctx.path,
                    parent: ctx,
                }),
            ]).then(([left, right]) => handleParsed(left, right));
        }
        else {
            return handleParsed(this._def.left._parseSync({
                data: ctx.data,
                path: ctx.path,
                parent: ctx,
            }), this._def.right._parseSync({
                data: ctx.data,
                path: ctx.path,
                parent: ctx,
            }));
        }
    }
}
ZodIntersection.create = (left, right, params) => {
    return new ZodIntersection({
        left: left,
        right: right,
        typeName: ZodFirstPartyTypeKind.ZodIntersection,
        ...processCreateParams(params),
    });
};
class ZodTuple extends ZodType {
    _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.array) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.array,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        if (ctx.data.length < this._def.items.length) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.too_small,
                minimum: this._def.items.length,
                inclusive: true,
                exact: false,
                type: "array",
            });
            return INVALID;
        }
        const rest = this._def.rest;
        if (!rest && ctx.data.length > this._def.items.length) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.too_big,
                maximum: this._def.items.length,
                inclusive: true,
                exact: false,
                type: "array",
            });
            status.dirty();
        }
        const items = [...ctx.data]
            .map((item, itemIndex) => {
            const schema = this._def.items[itemIndex] || this._def.rest;
            if (!schema)
                return null;
            return schema._parse(new ParseInputLazyPath(ctx, item, ctx.path, itemIndex));
        })
            .filter((x) => !!x); // filter nulls
        if (ctx.common.async) {
            return Promise.all(items).then((results) => {
                return ParseStatus.mergeArray(status, results);
            });
        }
        else {
            return ParseStatus.mergeArray(status, items);
        }
    }
    get items() {
        return this._def.items;
    }
    rest(rest) {
        return new ZodTuple({
            ...this._def,
            rest,
        });
    }
}
ZodTuple.create = (schemas, params) => {
    if (!Array.isArray(schemas)) {
        throw new Error("You must pass an array of schemas to z.tuple([ ... ])");
    }
    return new ZodTuple({
        items: schemas,
        typeName: ZodFirstPartyTypeKind.ZodTuple,
        rest: null,
        ...processCreateParams(params),
    });
};
class ZodRecord extends ZodType {
    get keySchema() {
        return this._def.keyType;
    }
    get valueSchema() {
        return this._def.valueType;
    }
    _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.object) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.object,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        const pairs = [];
        const keyType = this._def.keyType;
        const valueType = this._def.valueType;
        for (const key in ctx.data) {
            pairs.push({
                key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, key)),
                value: valueType._parse(new ParseInputLazyPath(ctx, ctx.data[key], ctx.path, key)),
            });
        }
        if (ctx.common.async) {
            return ParseStatus.mergeObjectAsync(status, pairs);
        }
        else {
            return ParseStatus.mergeObjectSync(status, pairs);
        }
    }
    get element() {
        return this._def.valueType;
    }
    static create(first, second, third) {
        if (second instanceof ZodType) {
            return new ZodRecord({
                keyType: first,
                valueType: second,
                typeName: ZodFirstPartyTypeKind.ZodRecord,
                ...processCreateParams(third),
            });
        }
        return new ZodRecord({
            keyType: ZodString.create(),
            valueType: first,
            typeName: ZodFirstPartyTypeKind.ZodRecord,
            ...processCreateParams(second),
        });
    }
}
class ZodMap extends ZodType {
    _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.map) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.map,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        const keyType = this._def.keyType;
        const valueType = this._def.valueType;
        const pairs = [...ctx.data.entries()].map(([key, value], index) => {
            return {
                key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, [index, "key"])),
                value: valueType._parse(new ParseInputLazyPath(ctx, value, ctx.path, [index, "value"])),
            };
        });
        if (ctx.common.async) {
            const finalMap = new Map();
            return Promise.resolve().then(async () => {
                for (const pair of pairs) {
                    const key = await pair.key;
                    const value = await pair.value;
                    if (key.status === "aborted" || value.status === "aborted") {
                        return INVALID;
                    }
                    if (key.status === "dirty" || value.status === "dirty") {
                        status.dirty();
                    }
                    finalMap.set(key.value, value.value);
                }
                return { status: status.value, value: finalMap };
            });
        }
        else {
            const finalMap = new Map();
            for (const pair of pairs) {
                const key = pair.key;
                const value = pair.value;
                if (key.status === "aborted" || value.status === "aborted") {
                    return INVALID;
                }
                if (key.status === "dirty" || value.status === "dirty") {
                    status.dirty();
                }
                finalMap.set(key.value, value.value);
            }
            return { status: status.value, value: finalMap };
        }
    }
}
ZodMap.create = (keyType, valueType, params) => {
    return new ZodMap({
        valueType,
        keyType,
        typeName: ZodFirstPartyTypeKind.ZodMap,
        ...processCreateParams(params),
    });
};
class ZodSet extends ZodType {
    _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.set) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.set,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        const def = this._def;
        if (def.minSize !== null) {
            if (ctx.data.size < def.minSize.value) {
                addIssueToContext(ctx, {
                    code: ZodIssueCode.too_small,
                    minimum: def.minSize.value,
                    type: "set",
                    inclusive: true,
                    exact: false,
                    message: def.minSize.message,
                });
                status.dirty();
            }
        }
        if (def.maxSize !== null) {
            if (ctx.data.size > def.maxSize.value) {
                addIssueToContext(ctx, {
                    code: ZodIssueCode.too_big,
                    maximum: def.maxSize.value,
                    type: "set",
                    inclusive: true,
                    exact: false,
                    message: def.maxSize.message,
                });
                status.dirty();
            }
        }
        const valueType = this._def.valueType;
        function finalizeSet(elements) {
            const parsedSet = new Set();
            for (const element of elements) {
                if (element.status === "aborted")
                    return INVALID;
                if (element.status === "dirty")
                    status.dirty();
                parsedSet.add(element.value);
            }
            return { status: status.value, value: parsedSet };
        }
        const elements = [...ctx.data.values()].map((item, i) => valueType._parse(new ParseInputLazyPath(ctx, item, ctx.path, i)));
        if (ctx.common.async) {
            return Promise.all(elements).then((elements) => finalizeSet(elements));
        }
        else {
            return finalizeSet(elements);
        }
    }
    min(minSize, message) {
        return new ZodSet({
            ...this._def,
            minSize: { value: minSize, message: errorUtil.toString(message) },
        });
    }
    max(maxSize, message) {
        return new ZodSet({
            ...this._def,
            maxSize: { value: maxSize, message: errorUtil.toString(message) },
        });
    }
    size(size, message) {
        return this.min(size, message).max(size, message);
    }
    nonempty(message) {
        return this.min(1, message);
    }
}
ZodSet.create = (valueType, params) => {
    return new ZodSet({
        valueType,
        minSize: null,
        maxSize: null,
        typeName: ZodFirstPartyTypeKind.ZodSet,
        ...processCreateParams(params),
    });
};
class ZodFunction extends ZodType {
    constructor() {
        super(...arguments);
        this.validate = this.implement;
    }
    _parse(input) {
        const { ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.function) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.function,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        function makeArgsIssue(args, error) {
            return makeIssue({
                data: args,
                path: ctx.path,
                errorMaps: [
                    ctx.common.contextualErrorMap,
                    ctx.schemaErrorMap,
                    getErrorMap(),
                    errorMap,
                ].filter((x) => !!x),
                issueData: {
                    code: ZodIssueCode.invalid_arguments,
                    argumentsError: error,
                },
            });
        }
        function makeReturnsIssue(returns, error) {
            return makeIssue({
                data: returns,
                path: ctx.path,
                errorMaps: [
                    ctx.common.contextualErrorMap,
                    ctx.schemaErrorMap,
                    getErrorMap(),
                    errorMap,
                ].filter((x) => !!x),
                issueData: {
                    code: ZodIssueCode.invalid_return_type,
                    returnTypeError: error,
                },
            });
        }
        const params = { errorMap: ctx.common.contextualErrorMap };
        const fn = ctx.data;
        if (this._def.returns instanceof ZodPromise) {
            return OK(async (...args) => {
                const error = new ZodError([]);
                const parsedArgs = await this._def.args
                    .parseAsync(args, params)
                    .catch((e) => {
                    error.addIssue(makeArgsIssue(args, e));
                    throw error;
                });
                const result = await fn(...parsedArgs);
                const parsedReturns = await this._def.returns._def.type
                    .parseAsync(result, params)
                    .catch((e) => {
                    error.addIssue(makeReturnsIssue(result, e));
                    throw error;
                });
                return parsedReturns;
            });
        }
        else {
            return OK((...args) => {
                const parsedArgs = this._def.args.safeParse(args, params);
                if (!parsedArgs.success) {
                    throw new ZodError([makeArgsIssue(args, parsedArgs.error)]);
                }
                const result = fn(...parsedArgs.data);
                const parsedReturns = this._def.returns.safeParse(result, params);
                if (!parsedReturns.success) {
                    throw new ZodError([makeReturnsIssue(result, parsedReturns.error)]);
                }
                return parsedReturns.data;
            });
        }
    }
    parameters() {
        return this._def.args;
    }
    returnType() {
        return this._def.returns;
    }
    args(...items) {
        return new ZodFunction({
            ...this._def,
            args: ZodTuple.create(items).rest(ZodUnknown.create()),
        });
    }
    returns(returnType) {
        return new ZodFunction({
            ...this._def,
            returns: returnType,
        });
    }
    implement(func) {
        const validatedFunc = this.parse(func);
        return validatedFunc;
    }
    strictImplement(func) {
        const validatedFunc = this.parse(func);
        return validatedFunc;
    }
    static create(args, returns, params) {
        return new ZodFunction({
            args: (args
                ? args
                : ZodTuple.create([]).rest(ZodUnknown.create())),
            returns: returns || ZodUnknown.create(),
            typeName: ZodFirstPartyTypeKind.ZodFunction,
            ...processCreateParams(params),
        });
    }
}
class ZodLazy extends ZodType {
    get schema() {
        return this._def.getter();
    }
    _parse(input) {
        const { ctx } = this._processInputParams(input);
        const lazySchema = this._def.getter();
        return lazySchema._parse({ data: ctx.data, path: ctx.path, parent: ctx });
    }
}
ZodLazy.create = (getter, params) => {
    return new ZodLazy({
        getter: getter,
        typeName: ZodFirstPartyTypeKind.ZodLazy,
        ...processCreateParams(params),
    });
};
class ZodLiteral extends ZodType {
    _parse(input) {
        if (input.data !== this._def.value) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                received: ctx.data,
                code: ZodIssueCode.invalid_literal,
                expected: this._def.value,
            });
            return INVALID;
        }
        return { status: "valid", value: input.data };
    }
    get value() {
        return this._def.value;
    }
}
ZodLiteral.create = (value, params) => {
    return new ZodLiteral({
        value: value,
        typeName: ZodFirstPartyTypeKind.ZodLiteral,
        ...processCreateParams(params),
    });
};
function createZodEnum(values, params) {
    return new ZodEnum({
        values: values,
        typeName: ZodFirstPartyTypeKind.ZodEnum,
        ...processCreateParams(params),
    });
}
class ZodEnum extends ZodType {
    _parse(input) {
        if (typeof input.data !== "string") {
            const ctx = this._getOrReturnCtx(input);
            const expectedValues = this._def.values;
            addIssueToContext(ctx, {
                expected: util.joinValues(expectedValues),
                received: ctx.parsedType,
                code: ZodIssueCode.invalid_type,
            });
            return INVALID;
        }
        if (this._def.values.indexOf(input.data) === -1) {
            const ctx = this._getOrReturnCtx(input);
            const expectedValues = this._def.values;
            addIssueToContext(ctx, {
                received: ctx.data,
                code: ZodIssueCode.invalid_enum_value,
                options: expectedValues,
            });
            return INVALID;
        }
        return OK(input.data);
    }
    get options() {
        return this._def.values;
    }
    get enum() {
        const enumValues = {};
        for (const val of this._def.values) {
            enumValues[val] = val;
        }
        return enumValues;
    }
    get Values() {
        const enumValues = {};
        for (const val of this._def.values) {
            enumValues[val] = val;
        }
        return enumValues;
    }
    get Enum() {
        const enumValues = {};
        for (const val of this._def.values) {
            enumValues[val] = val;
        }
        return enumValues;
    }
    extract(values) {
        return ZodEnum.create(values);
    }
    exclude(values) {
        return ZodEnum.create(this.options.filter((opt) => !values.includes(opt)));
    }
}
ZodEnum.create = createZodEnum;
class ZodNativeEnum extends ZodType {
    _parse(input) {
        const nativeEnumValues = util.getValidEnumValues(this._def.values);
        const ctx = this._getOrReturnCtx(input);
        if (ctx.parsedType !== ZodParsedType.string &&
            ctx.parsedType !== ZodParsedType.number) {
            const expectedValues = util.objectValues(nativeEnumValues);
            addIssueToContext(ctx, {
                expected: util.joinValues(expectedValues),
                received: ctx.parsedType,
                code: ZodIssueCode.invalid_type,
            });
            return INVALID;
        }
        if (nativeEnumValues.indexOf(input.data) === -1) {
            const expectedValues = util.objectValues(nativeEnumValues);
            addIssueToContext(ctx, {
                received: ctx.data,
                code: ZodIssueCode.invalid_enum_value,
                options: expectedValues,
            });
            return INVALID;
        }
        return OK(input.data);
    }
    get enum() {
        return this._def.values;
    }
}
ZodNativeEnum.create = (values, params) => {
    return new ZodNativeEnum({
        values: values,
        typeName: ZodFirstPartyTypeKind.ZodNativeEnum,
        ...processCreateParams(params),
    });
};
class ZodPromise extends ZodType {
    unwrap() {
        return this._def.type;
    }
    _parse(input) {
        const { ctx } = this._processInputParams(input);
        if (ctx.parsedType !== ZodParsedType.promise &&
            ctx.common.async === false) {
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.promise,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        const promisified = ctx.parsedType === ZodParsedType.promise
            ? ctx.data
            : Promise.resolve(ctx.data);
        return OK(promisified.then((data) => {
            return this._def.type.parseAsync(data, {
                path: ctx.path,
                errorMap: ctx.common.contextualErrorMap,
            });
        }));
    }
}
ZodPromise.create = (schema, params) => {
    return new ZodPromise({
        type: schema,
        typeName: ZodFirstPartyTypeKind.ZodPromise,
        ...processCreateParams(params),
    });
};
class ZodEffects extends ZodType {
    innerType() {
        return this._def.schema;
    }
    sourceType() {
        return this._def.schema._def.typeName === ZodFirstPartyTypeKind.ZodEffects
            ? this._def.schema.sourceType()
            : this._def.schema;
    }
    _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        const effect = this._def.effect || null;
        if (effect.type === "preprocess") {
            const processed = effect.transform(ctx.data);
            if (ctx.common.async) {
                return Promise.resolve(processed).then((processed) => {
                    return this._def.schema._parseAsync({
                        data: processed,
                        path: ctx.path,
                        parent: ctx,
                    });
                });
            }
            else {
                return this._def.schema._parseSync({
                    data: processed,
                    path: ctx.path,
                    parent: ctx,
                });
            }
        }
        const checkCtx = {
            addIssue: (arg) => {
                addIssueToContext(ctx, arg);
                if (arg.fatal) {
                    status.abort();
                }
                else {
                    status.dirty();
                }
            },
            get path() {
                return ctx.path;
            },
        };
        checkCtx.addIssue = checkCtx.addIssue.bind(checkCtx);
        if (effect.type === "refinement") {
            const executeRefinement = (acc
            // effect: RefinementEffect<any>
            ) => {
                const result = effect.refinement(acc, checkCtx);
                if (ctx.common.async) {
                    return Promise.resolve(result);
                }
                if (result instanceof Promise) {
                    throw new Error("Async refinement encountered during synchronous parse operation. Use .parseAsync instead.");
                }
                return acc;
            };
            if (ctx.common.async === false) {
                const inner = this._def.schema._parseSync({
                    data: ctx.data,
                    path: ctx.path,
                    parent: ctx,
                });
                if (inner.status === "aborted")
                    return INVALID;
                if (inner.status === "dirty")
                    status.dirty();
                // return value is ignored
                executeRefinement(inner.value);
                return { status: status.value, value: inner.value };
            }
            else {
                return this._def.schema
                    ._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx })
                    .then((inner) => {
                    if (inner.status === "aborted")
                        return INVALID;
                    if (inner.status === "dirty")
                        status.dirty();
                    return executeRefinement(inner.value).then(() => {
                        return { status: status.value, value: inner.value };
                    });
                });
            }
        }
        if (effect.type === "transform") {
            if (ctx.common.async === false) {
                const base = this._def.schema._parseSync({
                    data: ctx.data,
                    path: ctx.path,
                    parent: ctx,
                });
                if (!isValid(base))
                    return base;
                const result = effect.transform(base.value, checkCtx);
                if (result instanceof Promise) {
                    throw new Error(`Asynchronous transform encountered during synchronous parse operation. Use .parseAsync instead.`);
                }
                return { status: status.value, value: result };
            }
            else {
                return this._def.schema
                    ._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx })
                    .then((base) => {
                    if (!isValid(base))
                        return base;
                    return Promise.resolve(effect.transform(base.value, checkCtx)).then((result) => ({ status: status.value, value: result }));
                });
            }
        }
        util.assertNever(effect);
    }
}
ZodEffects.create = (schema, effect, params) => {
    return new ZodEffects({
        schema,
        typeName: ZodFirstPartyTypeKind.ZodEffects,
        effect,
        ...processCreateParams(params),
    });
};
ZodEffects.createWithPreprocess = (preprocess, schema, params) => {
    return new ZodEffects({
        schema,
        effect: { type: "preprocess", transform: preprocess },
        typeName: ZodFirstPartyTypeKind.ZodEffects,
        ...processCreateParams(params),
    });
};
class ZodOptional extends ZodType {
    _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType === ZodParsedType.undefined) {
            return OK(undefined);
        }
        return this._def.innerType._parse(input);
    }
    unwrap() {
        return this._def.innerType;
    }
}
ZodOptional.create = (type, params) => {
    return new ZodOptional({
        innerType: type,
        typeName: ZodFirstPartyTypeKind.ZodOptional,
        ...processCreateParams(params),
    });
};
class ZodNullable extends ZodType {
    _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType === ZodParsedType.null) {
            return OK(null);
        }
        return this._def.innerType._parse(input);
    }
    unwrap() {
        return this._def.innerType;
    }
}
ZodNullable.create = (type, params) => {
    return new ZodNullable({
        innerType: type,
        typeName: ZodFirstPartyTypeKind.ZodNullable,
        ...processCreateParams(params),
    });
};
class ZodDefault extends ZodType {
    _parse(input) {
        const { ctx } = this._processInputParams(input);
        let data = ctx.data;
        if (ctx.parsedType === ZodParsedType.undefined) {
            data = this._def.defaultValue();
        }
        return this._def.innerType._parse({
            data,
            path: ctx.path,
            parent: ctx,
        });
    }
    removeDefault() {
        return this._def.innerType;
    }
}
ZodDefault.create = (type, params) => {
    return new ZodDefault({
        innerType: type,
        typeName: ZodFirstPartyTypeKind.ZodDefault,
        defaultValue: typeof params.default === "function"
            ? params.default
            : () => params.default,
        ...processCreateParams(params),
    });
};
class ZodCatch extends ZodType {
    _parse(input) {
        const { ctx } = this._processInputParams(input);
        // newCtx is used to not collect issues from inner types in ctx
        const newCtx = {
            ...ctx,
            common: {
                ...ctx.common,
                issues: [],
            },
        };
        const result = this._def.innerType._parse({
            data: newCtx.data,
            path: newCtx.path,
            parent: {
                ...newCtx,
            },
        });
        if (isAsync(result)) {
            return result.then((result) => {
                return {
                    status: "valid",
                    value: result.status === "valid"
                        ? result.value
                        : this._def.catchValue({
                            get error() {
                                return new ZodError(newCtx.common.issues);
                            },
                            input: newCtx.data,
                        }),
                };
            });
        }
        else {
            return {
                status: "valid",
                value: result.status === "valid"
                    ? result.value
                    : this._def.catchValue({
                        get error() {
                            return new ZodError(newCtx.common.issues);
                        },
                        input: newCtx.data,
                    }),
            };
        }
    }
    removeCatch() {
        return this._def.innerType;
    }
}
ZodCatch.create = (type, params) => {
    return new ZodCatch({
        innerType: type,
        typeName: ZodFirstPartyTypeKind.ZodCatch,
        catchValue: typeof params.catch === "function" ? params.catch : () => params.catch,
        ...processCreateParams(params),
    });
};
class ZodNaN extends ZodType {
    _parse(input) {
        const parsedType = this._getType(input);
        if (parsedType !== ZodParsedType.nan) {
            const ctx = this._getOrReturnCtx(input);
            addIssueToContext(ctx, {
                code: ZodIssueCode.invalid_type,
                expected: ZodParsedType.nan,
                received: ctx.parsedType,
            });
            return INVALID;
        }
        return { status: "valid", value: input.data };
    }
}
ZodNaN.create = (params) => {
    return new ZodNaN({
        typeName: ZodFirstPartyTypeKind.ZodNaN,
        ...processCreateParams(params),
    });
};
const BRAND = Symbol("zod_brand");
class ZodBranded extends ZodType {
    _parse(input) {
        const { ctx } = this._processInputParams(input);
        const data = ctx.data;
        return this._def.type._parse({
            data,
            path: ctx.path,
            parent: ctx,
        });
    }
    unwrap() {
        return this._def.type;
    }
}
class ZodPipeline extends ZodType {
    _parse(input) {
        const { status, ctx } = this._processInputParams(input);
        if (ctx.common.async) {
            const handleAsync = async () => {
                const inResult = await this._def.in._parseAsync({
                    data: ctx.data,
                    path: ctx.path,
                    parent: ctx,
                });
                if (inResult.status === "aborted")
                    return INVALID;
                if (inResult.status === "dirty") {
                    status.dirty();
                    return DIRTY(inResult.value);
                }
                else {
                    return this._def.out._parseAsync({
                        data: inResult.value,
                        path: ctx.path,
                        parent: ctx,
                    });
                }
            };
            return handleAsync();
        }
        else {
            const inResult = this._def.in._parseSync({
                data: ctx.data,
                path: ctx.path,
                parent: ctx,
            });
            if (inResult.status === "aborted")
                return INVALID;
            if (inResult.status === "dirty") {
                status.dirty();
                return {
                    status: "dirty",
                    value: inResult.value,
                };
            }
            else {
                return this._def.out._parseSync({
                    data: inResult.value,
                    path: ctx.path,
                    parent: ctx,
                });
            }
        }
    }
    static create(a, b) {
        return new ZodPipeline({
            in: a,
            out: b,
            typeName: ZodFirstPartyTypeKind.ZodPipeline,
        });
    }
}
const custom = (check, params = {}, 
/*
 * @deprecated
 *
 * Pass `fatal` into the params object instead:
 *
 * ```ts
 * z.string().custom((val) => val.length > 5, { fatal: false })
 * ```
 *
 */
fatal) => {
    if (check)
        return ZodAny.create().superRefine((data, ctx) => {
            var _a, _b;
            if (!check(data)) {
                const p = typeof params === "function"
                    ? params(data)
                    : typeof params === "string"
                        ? { message: params }
                        : params;
                const _fatal = (_b = (_a = p.fatal) !== null && _a !== void 0 ? _a : fatal) !== null && _b !== void 0 ? _b : true;
                const p2 = typeof p === "string" ? { message: p } : p;
                ctx.addIssue({ code: "custom", ...p2, fatal: _fatal });
            }
        });
    return ZodAny.create();
};
const late = {
    object: ZodObject.lazycreate,
};
var ZodFirstPartyTypeKind;
(function (ZodFirstPartyTypeKind) {
    ZodFirstPartyTypeKind["ZodString"] = "ZodString";
    ZodFirstPartyTypeKind["ZodNumber"] = "ZodNumber";
    ZodFirstPartyTypeKind["ZodNaN"] = "ZodNaN";
    ZodFirstPartyTypeKind["ZodBigInt"] = "ZodBigInt";
    ZodFirstPartyTypeKind["ZodBoolean"] = "ZodBoolean";
    ZodFirstPartyTypeKind["ZodDate"] = "ZodDate";
    ZodFirstPartyTypeKind["ZodSymbol"] = "ZodSymbol";
    ZodFirstPartyTypeKind["ZodUndefined"] = "ZodUndefined";
    ZodFirstPartyTypeKind["ZodNull"] = "ZodNull";
    ZodFirstPartyTypeKind["ZodAny"] = "ZodAny";
    ZodFirstPartyTypeKind["ZodUnknown"] = "ZodUnknown";
    ZodFirstPartyTypeKind["ZodNever"] = "ZodNever";
    ZodFirstPartyTypeKind["ZodVoid"] = "ZodVoid";
    ZodFirstPartyTypeKind["ZodArray"] = "ZodArray";
    ZodFirstPartyTypeKind["ZodObject"] = "ZodObject";
    ZodFirstPartyTypeKind["ZodUnion"] = "ZodUnion";
    ZodFirstPartyTypeKind["ZodDiscriminatedUnion"] = "ZodDiscriminatedUnion";
    ZodFirstPartyTypeKind["ZodIntersection"] = "ZodIntersection";
    ZodFirstPartyTypeKind["ZodTuple"] = "ZodTuple";
    ZodFirstPartyTypeKind["ZodRecord"] = "ZodRecord";
    ZodFirstPartyTypeKind["ZodMap"] = "ZodMap";
    ZodFirstPartyTypeKind["ZodSet"] = "ZodSet";
    ZodFirstPartyTypeKind["ZodFunction"] = "ZodFunction";
    ZodFirstPartyTypeKind["ZodLazy"] = "ZodLazy";
    ZodFirstPartyTypeKind["ZodLiteral"] = "ZodLiteral";
    ZodFirstPartyTypeKind["ZodEnum"] = "ZodEnum";
    ZodFirstPartyTypeKind["ZodEffects"] = "ZodEffects";
    ZodFirstPartyTypeKind["ZodNativeEnum"] = "ZodNativeEnum";
    ZodFirstPartyTypeKind["ZodOptional"] = "ZodOptional";
    ZodFirstPartyTypeKind["ZodNullable"] = "ZodNullable";
    ZodFirstPartyTypeKind["ZodDefault"] = "ZodDefault";
    ZodFirstPartyTypeKind["ZodCatch"] = "ZodCatch";
    ZodFirstPartyTypeKind["ZodPromise"] = "ZodPromise";
    ZodFirstPartyTypeKind["ZodBranded"] = "ZodBranded";
    ZodFirstPartyTypeKind["ZodPipeline"] = "ZodPipeline";
})(ZodFirstPartyTypeKind || (ZodFirstPartyTypeKind = {}));
const instanceOfType = (
// const instanceOfType = <T extends new (...args: any[]) => any>(
cls, params = {
    message: `Input not instance of ${cls.name}`,
}) => custom((data) => data instanceof cls, params);
const stringType = ZodString.create;
const numberType = ZodNumber.create;
const nanType = ZodNaN.create;
const bigIntType = ZodBigInt.create;
const booleanType = ZodBoolean.create;
const dateType = ZodDate.create;
const symbolType = ZodSymbol.create;
const undefinedType = ZodUndefined.create;
const nullType = ZodNull.create;
const anyType = ZodAny.create;
const unknownType = ZodUnknown.create;
const neverType = ZodNever.create;
const voidType = ZodVoid.create;
const arrayType = ZodArray.create;
const objectType = ZodObject.create;
const strictObjectType = ZodObject.strictCreate;
const unionType = ZodUnion.create;
const discriminatedUnionType = ZodDiscriminatedUnion.create;
const intersectionType = ZodIntersection.create;
const tupleType = ZodTuple.create;
const recordType = ZodRecord.create;
const mapType = ZodMap.create;
const setType = ZodSet.create;
const functionType = ZodFunction.create;
const lazyType = ZodLazy.create;
const literalType = ZodLiteral.create;
const enumType = ZodEnum.create;
const nativeEnumType = ZodNativeEnum.create;
const promiseType = ZodPromise.create;
const effectsType = ZodEffects.create;
const optionalType = ZodOptional.create;
const nullableType = ZodNullable.create;
const preprocessType = ZodEffects.createWithPreprocess;
const pipelineType = ZodPipeline.create;
const ostring = () => stringType().optional();
const onumber = () => numberType().optional();
const oboolean = () => booleanType().optional();
const coerce = {
    string: ((arg) => ZodString.create({ ...arg, coerce: true })),
    number: ((arg) => ZodNumber.create({ ...arg, coerce: true })),
    boolean: ((arg) => ZodBoolean.create({
        ...arg,
        coerce: true,
    })),
    bigint: ((arg) => ZodBigInt.create({ ...arg, coerce: true })),
    date: ((arg) => ZodDate.create({ ...arg, coerce: true })),
};
const NEVER = INVALID;

var z = /*#__PURE__*/Object.freeze({
    __proto__: null,
    defaultErrorMap: errorMap,
    setErrorMap: setErrorMap,
    getErrorMap: getErrorMap,
    makeIssue: makeIssue,
    EMPTY_PATH: EMPTY_PATH,
    addIssueToContext: addIssueToContext,
    ParseStatus: ParseStatus,
    INVALID: INVALID,
    DIRTY: DIRTY,
    OK: OK,
    isAborted: isAborted,
    isDirty: isDirty,
    isValid: isValid,
    isAsync: isAsync,
    get util () { return util; },
    get objectUtil () { return objectUtil; },
    ZodParsedType: ZodParsedType,
    getParsedType: getParsedType,
    ZodType: ZodType,
    ZodString: ZodString,
    ZodNumber: ZodNumber,
    ZodBigInt: ZodBigInt,
    ZodBoolean: ZodBoolean,
    ZodDate: ZodDate,
    ZodSymbol: ZodSymbol,
    ZodUndefined: ZodUndefined,
    ZodNull: ZodNull,
    ZodAny: ZodAny,
    ZodUnknown: ZodUnknown,
    ZodNever: ZodNever,
    ZodVoid: ZodVoid,
    ZodArray: ZodArray,
    ZodObject: ZodObject,
    ZodUnion: ZodUnion,
    ZodDiscriminatedUnion: ZodDiscriminatedUnion,
    ZodIntersection: ZodIntersection,
    ZodTuple: ZodTuple,
    ZodRecord: ZodRecord,
    ZodMap: ZodMap,
    ZodSet: ZodSet,
    ZodFunction: ZodFunction,
    ZodLazy: ZodLazy,
    ZodLiteral: ZodLiteral,
    ZodEnum: ZodEnum,
    ZodNativeEnum: ZodNativeEnum,
    ZodPromise: ZodPromise,
    ZodEffects: ZodEffects,
    ZodTransformer: ZodEffects,
    ZodOptional: ZodOptional,
    ZodNullable: ZodNullable,
    ZodDefault: ZodDefault,
    ZodCatch: ZodCatch,
    ZodNaN: ZodNaN,
    BRAND: BRAND,
    ZodBranded: ZodBranded,
    ZodPipeline: ZodPipeline,
    custom: custom,
    Schema: ZodType,
    ZodSchema: ZodType,
    late: late,
    get ZodFirstPartyTypeKind () { return ZodFirstPartyTypeKind; },
    coerce: coerce,
    any: anyType,
    array: arrayType,
    bigint: bigIntType,
    boolean: booleanType,
    date: dateType,
    discriminatedUnion: discriminatedUnionType,
    effect: effectsType,
    'enum': enumType,
    'function': functionType,
    'instanceof': instanceOfType,
    intersection: intersectionType,
    lazy: lazyType,
    literal: literalType,
    map: mapType,
    nan: nanType,
    nativeEnum: nativeEnumType,
    never: neverType,
    'null': nullType,
    nullable: nullableType,
    number: numberType,
    object: objectType,
    oboolean: oboolean,
    onumber: onumber,
    optional: optionalType,
    ostring: ostring,
    pipeline: pipelineType,
    preprocess: preprocessType,
    promise: promiseType,
    record: recordType,
    set: setType,
    strictObject: strictObjectType,
    string: stringType,
    symbol: symbolType,
    transformer: effectsType,
    tuple: tupleType,
    'undefined': undefinedType,
    union: unionType,
    unknown: unknownType,
    'void': voidType,
    NEVER: NEVER,
    ZodIssueCode: ZodIssueCode,
    quotelessJson: quotelessJson,
    ZodError: ZodError
});

const hexstr = z.string().regex(/^[a-fA-F0-9]$/);
const hash = z.string().regex(/^[a-fA-F0-9]{64}$/);
const uint32 = z.number().min(0).max(0xFFFFFFFF);
const uint64 = z.bigint();
const byteArr = z.instanceof(Uint8Array);
const asmcode = z.union([hexstr, uint32, z.string(), byteArr]).array();
const script = z.union([asmcode, hexstr, byteArr]);
const witness = z.array(script);
const TxOutput = z.object({
    value: z.union([uint32, uint64]),
    scriptPubKey: script
});
const TxInput = z.object({
    txid: hash,
    vout: uint32,
    scriptSig: script,
    sequence: uint32,
    prevout: TxOutput.optional(),
    witness
});
const TxData = z.object({
    version: uint32,
    vin: z.array(TxInput),
    vout: z.array(TxOutput),
    locktime: uint32
});
const Schema = {
    TxData,
    TxInput,
    TxOutput,
    witness,
    script,
    hexstr,
    hash,
    uint32,
    uint64
};

class Transaction {
    constructor(txdata) {
        if (typeof txdata === 'string') {
            txdata = Buff$1.hex(txdata);
        }
        if (txdata instanceof Uint8Array) {
            txdata = Tx.decode(txdata);
        }
        const schema = Schema.TxData;
        this._data = schema.parse(Tx.create(txdata));
    }
    get data() {
        return this._data;
    }
    get version() {
        return this.data.version;
    }
    get vin() {
        return this.data.vin.map((_e, i) => new TxInput$1(this.data, i));
    }
    get vout() {
        return this.data.vout.map((e) => new TxOutput$1(e));
    }
    get locktime() {
        return new TxLocktime(this.data.locktime);
    }
    get base() {
        return Tx.encode(this.data, true);
    }
    get buff() {
        return Tx.encode(this.data);
    }
    get raw() {
        return this.buff.raw;
    }
    get hex() {
        return this.buff.hex;
    }
    get size() {
        return this.raw.length;
    }
    get bsize() {
        return this.base.length;
    }
    get weight() {
        return this.bsize * 3 + this.size;
    }
    get vsize() {
        const remainder = (this.weight % 4 > 0) ? 1 : 0;
        return Math.floor(this.weight / 4) + remainder;
    }
    get hash() {
        const hash = hash256(this.buff);
        return hash.reverse().hex;
    }
    get txid() {
        const hash = hash256(this.base);
        return hash.reverse().hex;
    }
    async export() {
        const { size, weight, vsize, hex } = this;
        const txid = this.txid;
        const hash = this.hash;
        return { txid, hash, ...this.data, size, weight, vsize, hex };
    }
}

export { Address, TxInput$1 as Input, TxOutput$1 as Output, Script, TxSequence as Sequence, Signer, Tap, Transaction, Tx, TxWitness as Witness };
