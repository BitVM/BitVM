import { compile, compileUnlock, toPublicKey, generateP2trAddressInfo, DUST_LIMIT } from './utils.js'
import { pushHex, pushHexEndian } from '../opcodes/utils.js'
import { hashLock, preimageHex, bit_state, bit_state_commit, bit_state_unlock } from '../opcodes/u32/u32_state.js'
import { u160_state_commit, u160_state_commit_unlock, u160_state_unlock, u160_state, u160_equalverify, u160_push, u160_swap_endian, u160_toaltstack, u160_fromaltstack } from '../opcodes/u160/u160_std.js'
import { Tap, Tx, Address, Signer } from '../libs/tapscript.js'
import { broadcastTransaction } from '../libs/esplora.js'
import { blake3_160 } from '../opcodes/blake3/blake3.js'


const IDENTIFIER_MERKLE = 'MERKLE_CHALLENGE'

// Depth of the Merkle tree 
const N = 32
// Number of queries we need
const H = 5 // = log2(N)


export function selectorLeaf(verifierSecret, length, isAbove = 0) {
    if (length >= H) throw `length >= ${H}`

    return [

        OP_RIPEMD160,
        hashLock(verifierSecret, IDENTIFIER_MERKLE, length, isAbove),
        OP_EQUALVERIFY,

        // sibelIndex = i0 i1 i2 ... i_{length-1} 1 0 0 ... 0 0
        0,
        loop(length, i => [
            OP_SWAP,
            bit_state(verifierSecret, `challenge_${i}`),
            OP_IF,
            2 ** (H - i - 1),
            OP_ADD,
            OP_ENDIF
        ]),
        2 ** (H - 1 - length),
        OP_ADD,
        OP_TOALTSTACK,
        // Now sibelIndex is on the stack


        // endIndex
        0,
        OP_SWAP,
        bit_state(verifierSecret, `challenge_0`),
        OP_IF, 2 ** (H - 1), OP_ADD, OP_ENDIF,

        OP_SWAP,
        bit_state(verifierSecret, `challenge_1`),
        OP_IF, 2 ** (H - 2), OP_ADD, OP_ENDIF,

        OP_SWAP,
        bit_state(verifierSecret, `challenge_2`),
        OP_IF, 2 ** (H - 3), OP_ADD, OP_ENDIF,

        OP_SWAP,
        bit_state(verifierSecret, `challenge_3`),
        OP_IF, 2 ** (H - 4), OP_ADD, OP_ENDIF,

        OP_SWAP,
        bit_state(verifierSecret, `challenge_4`),
        OP_IF, 2 ** (H - 5), OP_ADD, OP_ENDIF,

        // Now indexB is on the stack

        // check  |sibelIndex - endIndex| == 1
        // 
        OP_FROMALTSTACK,
        OP_SUB,
        isAbove ? OP_NEGATE : '',
        OP_1,
        OP_NUMEQUALVERIFY,
        OP_TRUE
    ]
}


function trailingZeros(n) {
    let count = 0;
    while ((n & 1) === 0 && n !== 0) count++, n >>= 1;
    return count;
}


export function selectorLeafUnlock(
    verifierSecret,
    endIndex,
    sibelIndex,
    isAbove
) {
    const length = H - trailingZeros(sibelIndex) - 1
    return [

        // endIndex
        loop(H, i => bit_state_unlock(verifierSecret, `challenge_${H - 1 - i}`, endIndex >>> i & 1)),

        // sibelIndex
        loop(length, i => bit_state_unlock(verifierSecret, `challenge_${length - i - 1}`, sibelIndex >>> (H - length + i) & 1)),

        // unlock the corresponding challenge
        preimageHex(verifierSecret, IDENTIFIER_MERKLE, length, isAbove),
    ]
}


export function computeSelectorRoot(verifierSecret) {
    return [
        selectorLeaf(verifierSecret, 0, 0),
        selectorLeaf(verifierSecret, 1, 0),
        selectorLeaf(verifierSecret, 2, 0),
        selectorLeaf(verifierSecret, 3, 0),

        selectorLeaf(verifierSecret, 0, 1),
        selectorLeaf(verifierSecret, 1, 1),
        selectorLeaf(verifierSecret, 2, 1),
        selectorLeaf(verifierSecret, 3, 1),
    ].map(compile)
}


export function challengeLeaf(
    proverSecret,
    verifierSecret,
    index,
    isAbove = 0
) {
    return [
        // loop( 20 + 1, _ => OP_DROP),
        OP_RIPEMD160,
        hashLock(verifierSecret, IDENTIFIER_MERKLE, index, isAbove),
        OP_EQUALVERIFY,
        u160_state(proverSecret, `identifier${ isAbove ? index : H }`),
        blake3_160,
        // loop(20, _ => OP_DROP),
        u160_toaltstack,
        u160_state(proverSecret, `identifier${ isAbove ? H : index }`),
        u160_fromaltstack,
        u160_swap_endian,
        u160_equalverify,
        OP_TRUE,
    ]
}

export function challengeLeafUnlock(
    proverSecret,
    verifierSecret,
    index,
    sibling,
    childHash,
    parentHash,
    merkleIndex,
    isAbove
) {
    return [
        u160_state_unlock(proverSecret, `identifier${H}`, parentHash),
        pushHexEndian(sibling),
        u160_state_unlock(proverSecret, `identifier${index}`, childHash),
        preimageHex(verifierSecret, IDENTIFIER_MERKLE, index, isAbove),
    ]
}


export function computeChallengeRoot(proverSecret, verifierSecret) {
    return [
        challengeLeaf(proverSecret, verifierSecret, 0, 0),
        challengeLeaf(proverSecret, verifierSecret, 1, 0),
        challengeLeaf(proverSecret, verifierSecret, 2, 0),
        challengeLeaf(proverSecret, verifierSecret, 3, 0),

        challengeLeaf(proverSecret, verifierSecret, 0, 1),
        challengeLeaf(proverSecret, verifierSecret, 1, 1),
        challengeLeaf(proverSecret, verifierSecret, 2, 1),
        challengeLeaf(proverSecret, verifierSecret, 3, 1)
    ].map(compile)
}

function computeTree(user, scripts){
    const tree = scripts.map(s => Tap.encodeScript(s))

    const [tseckey] = Tap.getSecKey(user.seckey, { tree })
    const [tpubkey, _] = Tap.getPubKey(user.pubkey, { tree })

    // A taproot address is simply the tweaked public key, encoded in bech32 format.
    const address = Address.p2tr.fromPubKey(tpubkey, 'signet')

    return { address, tree, scripts }
}

function computeCblock(user, tree, index){
    const target = tree[index]
    const [_, cblock] = Tap.getPubKey(user.pubkey, { tree, target })
    return cblock
}







// Sample secret / public key pair.

const vicky = {
    seckey : '730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6',
    pubkey : '07b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3'    
}

const paul = {
    seckey : '730fff80e1413068a05b57d6a58261f07551163369787f349438ea38ca80fac6',
    pubkey : '07b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3'    
}

const selectRoot = computeTree(vicky, computeSelectorRoot( vicky.seckey ))
const challengeRoot = computeTree(paul, computeChallengeRoot( paul.seckey, vicky.seckey ))
console.log(selectRoot.address)


const selectUnlockScript = compileUnlock(selectorLeafUnlock(vicky.seckey, 0b01001, 0b01000, 0))
const selectIndex = 1
const selectCblock = computeCblock(vicky, selectRoot.tree, selectIndex)
const selectScript = selectRoot.scripts[selectIndex]
const selectTx = Tx.create({
    vin: [{
        // The txid of your funding transaction.
        txid: '0677fbabfd7efa10d18385caf9989a94fd032cf005008acde0f6cfab28afa802',
        // The index of the output you are spending.
        vout: 1,
        // For Taproot, we need to specify this data when signing.
        prevout: {
            // The value of the output we are spending.
            value: 100_000,
            // This is the script that our taproot address decodes into.
            scriptPubKey: Address.toScriptPubKey(selectRoot.address)
        },
    }],
    vout: [{
        // We are locking up 99_000 sats (minus 1000 sats for fees.)
        value: 99_000,
        // We are locking up funds to this address.
        scriptPubKey: Address.toScriptPubKey(challengeRoot.address)
    }]
})
selectTx.vin[0].witness = [...selectUnlockScript, selectScript, selectCblock]
const selectTxhex = Tx.encode( selectTx ).hex
const selectTxid = Tx.util.getTxid( selectTxhex )
console.log('TXID', selectTxid)



const challengeTx = Tx.create({
    vin: [{
        // The txid of your funding transaction.
        txid: selectTxid, //selectTxid,
        // The index of the output you are spending.
        vout: 0,
        // For Taproot, we need to specify this data when signing.
        prevout: {
            // The value of the output we are spending.
            value: 99_000,
            // This is the script that our taproot address decodes into.
            scriptPubKey: Address.toScriptPubKey(challengeRoot.address)
        },
    }],
    vout: [{
        value: 1_000,
        // We are locking up funds to this address.
        scriptPubKey: Address.toScriptPubKey('tb1pq7u2ujdvjzsy36d4xdt6yd2txv6wnj97aqf7ewvwnxn7ql5v8w3sg98j36')
    }]
})


const challengeUnlockScript = compileUnlock( challengeLeafUnlock(
    paul.seckey, 
    vicky.seckey, 
    0, 
    'cea7db5e66bd5868387a438d8512a72cde5f973e',
    '79db24d391abb5c560e26454d29ff3ceb938681e',
    'ebd2c3f8b23391c56c7a5b1725d9466825626a58',
    0,
    1
))

const challengeIndex = 4
const challengeCblock = computeCblock(paul, challengeRoot.tree, challengeIndex)
const challengeScript = challengeRoot.scripts[challengeIndex]
challengeTx.vin[0].witness = [...challengeUnlockScript, challengeScript, challengeCblock]
const challengeTxhex = Tx.encode( challengeTx ).hex
const challengeTxid = Tx.util.getTxid( challengeTxhex )
console.log('TXID', challengeTxid)


await broadcastTransaction(selectTxhex)
await broadcastTransaction(challengeTxhex)

console.log('success')