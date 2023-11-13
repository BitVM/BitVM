import { compile, compileUnlock, toPublicKey, generateP2trAddressInfo, DUST_LIMIT } from './utils.js'
import { hashLock, preimageHex, bit_state_commit, bit_state_unlock } from '../opcodes/u32/u32_state.js';
import { u160_state_commit, u160_state_commit_unlock } from '../opcodes/u160/u160_std.js';
import { Tap, Tx, Address, Signer } from '../libs/tapscript.js'
import { broadcastTransaction } from '../libs/esplora.js';

const CHALLENGE_FEE = 1000
const RESPONSE_FEE = 3000
  

export function challengeScript(secret, identifier, pubkey_paul, pubkey_vicky) {
    return compile([
        bit_state_commit(secret, identifier),
        pubkey_vicky,
        OP_CHECKSIGVERIFY,
        pubkey_paul,
        OP_CHECKSIG
    ])
}

export function responseScript(secret, identifier, pubkey_paul, pubkey_vicky) {
    return compile([
        u160_state_commit(secret, identifier),
        pubkey_paul,
        OP_CHECKSIGVERIFY,
        pubkey_vicky,
        OP_CHECKSIG
    ])
}


export function createChallengeResponseChain(funding_txid, funding_vout, paul, vicky, length, identifier = 'id') {
    // Generate all required addresses, tapleafs and scripts.
    const tx_chain = []
    for (let i = 0; i < length; i++) {
        {
            const script = challengeScript(vicky.secret, `challenge_${i}`, paul.pubkey, vicky.pubkey)
            const [address, tapleaf, cblock] = generateP2trAddressInfo(script, paul.pubkey)
            tx_chain.push({address, tapleaf, script, cblock, signatures: []})
        }

        {
            const script = responseScript(paul.secret, `response_${i}`, paul.pubkey, vicky.pubkey)
            const [address, tapleaf, cblock] = generateP2trAddressInfo(script, vicky.pubkey)
            tx_chain.push({address, tapleaf, script, cblock, signatures: []})
        }
    }

    let vin_txid = funding_txid
    let vin_vout = funding_vout
    for (let i = 0; i < length; i++) {
        const challenge_tx = Tx.create({
            vin: [{
                txid: vin_txid,
                vout: vin_vout,
                prevout: {
                    value: (length - i) * (CHALLENGE_FEE + RESPONSE_FEE) + DUST_LIMIT,
                    // This is the script that our taproot address decodes into.
                    scriptPubKey: Address.toScriptPubKey(tx_chain[2 * i].address)
                },
            }],
            vout: [{
                value: (length - i) * (CHALLENGE_FEE + RESPONSE_FEE) - CHALLENGE_FEE + DUST_LIMIT,
                // We are locking up funds to this address.
                scriptPubKey: Address.toScriptPubKey(tx_chain[2 * i + 1].address)
            }]
        })
        tx_chain[2 * i].tx = challenge_tx
        let next_address = 'tb1pmk48eaj54487f96z6ktgu75zaekxs793cpm6yvgvqy90mlekn0ss7u3737'
        if (2 * i + 2 < length) {
            next_address = tx_chain[2 * i + 2].address
        }
        const response_tx = Tx.create({
            vin: [{
                txid: Tx.util.getTxid(Tx.encode(challenge_tx).hex),
                vout: 0,
                prevout: {
                    value: (length - i) * (CHALLENGE_FEE + RESPONSE_FEE) - CHALLENGE_FEE + DUST_LIMIT,
                    // This is the script that our taproot address decodes into.
                    scriptPubKey: Address.toScriptPubKey(tx_chain[2 * i + 1].address)
                },
            }],
            vout: [{
                value: (length - i - 1) * (CHALLENGE_FEE + RESPONSE_FEE) + DUST_LIMIT,
                // We are locking up funds to this address.
                scriptPubKey: Address.toScriptPubKey(next_address)
            }]
        })
        tx_chain[2 * i + 1].tx = response_tx
        vin_vout = 0
        vin_txid = Tx.util.getTxid(Tx.encode(response_tx).hex)
    }
    return tx_chain
}

export function presignChallengeResponseChain(unsigned_tx_chain, seckey_paul, seckey_vicky) {
    const sign = Signer.taproot.sign
    for (let i = 0; i < unsigned_tx_chain.length / 2; i++) {
        // Sign challenge tx - first Paul then Vicky
        const challenge = unsigned_tx_chain[2 * i]
        challenge.signatures.push(sign(seckey_paul, challenge.tx, 0, {extension: challenge.tapleaf}).hex)
        challenge.signatures.push(sign(seckey_vicky, challenge.tx, 0, {extension: challenge.tapleaf}).hex)
        
        // Sign response tx - first Vicky then Paul
        const response = unsigned_tx_chain[2 * i + 1]
        response.signatures.push(sign(seckey_vicky, response.tx, 0, {extension: response.tapleaf}).hex)
        response.signatures.push(sign(seckey_paul, response.tx, 0, {extension: response.tapleaf}).hex)
    }
}

export async function revealTxChain(tx_chain, id, secret, value) {
    if (id % 2 == 0) {
        // We send a challenge Tx
        const unlockScript = bit_state_unlock(secret, `challenge_${id / 2}`, value)
        tx_chain[id].tx.vin[0].witness = [...tx_chain[id].signatures, unlockScript, tx_chain[id].script, tx_chain[id].cblock]
        const txhex = Tx.encode(tx_chain[id].tx).hex
        await broadcastTransaction(txhex)
        console.log(`Challenge tx ${id / 2} broadcasted`, Tx.util.getTxid(txhex))
    } else {
        // We send a response Tx
        const unlockScript = compileUnlock(u160_state_commit_unlock(secret, `response_${(id - 1) / 2}`, value))
        tx_chain[id].tx.vin[0].witness = [...tx_chain[id].signatures, ...unlockScript, tx_chain[id].script, tx_chain[id].cblock]
        const txhex = Tx.encode(tx_chain[id].tx).hex
        await broadcastTransaction(txhex)
        console.log(`Response tx ${(id - 1) / 2} broadcasted`, Tx.util.getTxid(txhex))
    }
}