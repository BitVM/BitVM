import '../libs/blake3.js'
import {toHex} from '../libs/bytes.js'

export const BLAKE3 = buffer => {
    let hash = blake3.newRegular().update(buffer).finalize(20).padStart(40, 0)
    return Array.from(Uint8Array.from(hash.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))))
}

export const hashData = data => {
    let buffer = new TextEncoder().encode(data.toString())
    return BLAKE3(buffer)
}

export const buildTree = data => {
    let hashes = data.map(item => hashData(item))
    while (hashes.length > 1) {
        if (hashes.length % 2 !== 0) {
            hashes.push(hashes[hashes.length - 1])
        }
        let newHashes = []
        for (let i = 0; i < hashes.length; i += 2) {
            let concatenated = hashes[i].concat(hashes[i + 1])
            newHashes.push(BLAKE3(new Uint8Array(concatenated)))
        }
        hashes = newHashes
    }
    return hashes[0]
}

export const buildPath = (data, index) => {
    let hashes = data.map(item => hashData(item))
    let path = []
    while (hashes.length > 1) {
        if (hashes.length % 2 !== 0) {
            hashes.push(hashes[hashes.length - 1])
        }
        path.push(hashes[index ^ 1])
        let newHashes = []
        for (let i = 0; i < hashes.length; i += 2) {
            let concatenated = hashes[i].concat(hashes[i + 1])
            newHashes.push(BLAKE3(new Uint8Array(concatenated)))
        }
        hashes = newHashes
        index = index >>> 1
    }
    return path
}

export const verifyPath = (path, leaf, index) => {
    let node = hashData(leaf)
    return path.reduce((node, hint) => {
        let concatenated = (index & 1) == 0 ? node.concat(hint) : hint.concat(node)
        index = index >>> 1
        return BLAKE3(new Uint8Array(concatenated))
    }, node)
}