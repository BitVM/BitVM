import { compile, compileUnlock, toPublicKey, generateP2trAddressInfo, DUST_LIMIT } from './utils.js'
import { hashLock, preimageHex, bit_state_commit, bit_state_unlock } from '../opcodes/u32/u32_state.js';
import { u160_state_commit, u160_state_unlock } from '../opcodes/u160/u160_std.js';
import { Tap, Tx, Address, Signer } from '../libs/tapscript.js'
import { broadcastTransaction } from '../libs/esplora.js';
import { keys } from '../libs/crypto_tools.js'


const CHALLENGE_FEE = 1000
const RESPONSE_FEE = 3000
  

export function challengeScript(vicky, paul, identifier) {
    return compile([
        bit_state_commit(vicky.secret, identifier),
        vicky.pubkey,
        OP_CHECKSIGVERIFY,
        paul.pubkey,
        OP_CHECKSIG
    ])
}

export function responseScript(vicky, paul, identifier) {
    return compile([
        u160_state_commit(paul.secret, identifier),
        paul.pubkey,
        OP_CHECKSIGVERIFY,
        vicky.pubkey,
        OP_CHECKSIG
    ])
}

export function createChallengeResponseChain(vicky, paul, outpoint, length, connect_address) {
    // Generate all required addresses, tapleafs and scripts.
    const tx_chain = []
    for (let i = 0; i < length; i++) {
        const script = challengeScript(vicky, paul, `challenge_${i}`)
        const [address, tapleaf, cblock] = generateP2trAddressInfo(script, paul.pubkey)
        tx_chain[2 * i] = {address, tapleaf, script, cblock, signatures: []} 
    }

    for (let i = 0; i < length; i++) {
        const script = responseScript(vicky, paul, `response_${i}`)
        const [address, tapleaf, cblock] = generateP2trAddressInfo(script, vicky.pubkey)
        tx_chain[2 * i + 1] =  {address, tapleaf, script, cblock, signatures: []}
    }

    for (let i = 0; i < length; i++) {
        const challenge_tx = Tx.create({
            vin: [{
                txid: outpoint.txid,
                vout: outpoint.vout,
                prevout: {
                    value: outpoint.value,
                    // This is the script that our taproot address decodes into.
                    scriptPubKey: Address.toScriptPubKey(tx_chain[2 * i].address)
                },
            }],
            vout: [{
                value: outpoint.value - CHALLENGE_FEE,
                // We are locking up funds to this address.
                scriptPubKey: Address.toScriptPubKey(tx_chain[2 * i + 1].address)
            }]
        })
        tx_chain[2 * i].tx = challenge_tx

        let next_address = connect_address
        if (i != length - 1) next_address = tx_chain[2 * (i+1)].address
        
        const response_tx = Tx.create({
            vin: [{
                txid: Tx.util.getTxid(Tx.encode(challenge_tx).hex),
                vout: 0,
                prevout: {
                    value: challenge_tx.vout[0].value,
                    // This is the script that our taproot address decodes into.
                    scriptPubKey: Address.toScriptPubKey(tx_chain[2 * i + 1].address)
                },
            }],
            vout: [{
                value: challenge_tx.vout[0].value - RESPONSE_FEE,
                // We are locking up funds to this address.
                scriptPubKey: Address.toScriptPubKey(next_address)
            }]
        })
        tx_chain[2 * i + 1].tx = response_tx

        outpoint = {
            vout : 0,
            txid : Tx.util.getTxid(Tx.encode(response_tx).hex),
            value : challenge_tx.vout[0].value - RESPONSE_FEE
        }
    }
    return { tx_chain, outpoint }
}

export function presignChallengeResponseChain(vicky, paul, unsigned_tx_chain) {
    const sign = Signer.taproot.sign
    for (let i = 0; i < unsigned_tx_chain.length / 2; i++) {
        // Sign challenge tx - first Paul then Vicky
        const challenge = unsigned_tx_chain[2 * i]
        challenge.signatures.push(sign(paul.seckey, challenge.tx, 0, {extension: challenge.tapleaf}).hex)
        challenge.signatures.push(sign(vicky.seckey, challenge.tx, 0, {extension: challenge.tapleaf}).hex)
        
        // Sign response tx - first Vicky then Paul
        const response = unsigned_tx_chain[2 * i + 1]
        response.signatures.push(sign(vicky.seckey, response.tx, 0, {extension: response.tapleaf}).hex)
        response.signatures.push(sign(paul.seckey, response.tx, 0, {extension: response.tapleaf}).hex)
    }
}

export async function executeReveal1bit(vicky, tx_chain, id, value) {
    // We send a challenge Tx
    const round = tx_chain[id]
    const unlockScript = bit_state_unlock(vicky.secret, `challenge_${id / 2}`, value)
    round.tx.vin[0].witness = [...round.signatures, unlockScript, round.script, round.cblock]
    const txhex = Tx.encode(round.tx).hex
    await broadcastTransaction(txhex)
    console.log(`Challenge tx ${id / 2} broadcasted`, Tx.util.getTxid(txhex))
}

export async function executeReveal160bit(paul, tx_chain, id, value) {
    // We send a response Tx
    const round = tx_chain[id]
    const unlockScript = compileUnlock(u160_state_unlock(paul.secret, `response_${(id - 1) / 2}`, value))
    round.tx.vin[0].witness = [...round.signatures, ...unlockScript, round.script, round.cblock]
    const txhex = Tx.encode(round.tx).hex
    await broadcastTransaction(txhex)
    console.log(`Response tx ${(id - 1) / 2} broadcasted`, Tx.util.getTxid(txhex))
}
