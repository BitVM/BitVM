import { compileScript, compileUnlockScript } from '../scripts/compile.js'
import { Script, Tap, Tx, Address, Signer } from '../libs/tapscript.js'
import { broadcastTransaction }  from '../libs/esplora.js'


const NETWORK = 'signet'
const MIN_FEES = 32000

// TODO set to smallest sendable amount
export const DUST_LIMIT = 500

// This is an unspendable pubkey 
// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
const UNSPENDABLE_PUBKEY = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'


class Transaction {
    #leaves = []
    #prevOutpoint
    #nextScriptPubKey
    #successorTx
    
    constructor(leaves){
        for(const leaf of leaves){
            this.addLeaf(...leaf)
        }
    }

    addLeaf(type, ...args){
        const leaf = new type(this, ...args)
        this.#leaves.push( leaf )
    }

    getLeaf(index){
        return this.#leaves[index]
    }

    tx(){
        if(!this.#nextScriptPubKey || !this.#prevOutpoint) 
            throw 'Transaction not finalized yet'
        
        // TODO: cache this

        return Tx.create({
            vin: [{
                txid: this.#prevOutpoint.txid,
                vout: this.#prevOutpoint.vout,
                prevout: {
                    value: this.#prevOutpoint.value,
                    scriptPubKey: this.scriptPubKey()
                },
            }],
            vout: [{
                value: this.#prevOutpoint.value - MIN_FEES, // TODO: Set fees here
                scriptPubKey: this.#nextScriptPubKey
            }]
        })
    }

    txid(){
        return Tx.util.getTxid(Tx.encode(this.tx()).hex)
    }


    setPrevOutpoint(outpoint){
        this.#prevOutpoint = outpoint
    }

    nextOutpoint(){
        return {
            txid : this.txid(),
            vout : 0,
            value : this.tx().vout[0].value
        }
    }

    tree(){
        return this.#leaves.map(leaf => leaf.encodedLockingScript)
    }

    address(){
        // TODO: cache this
        const tree = this.tree()
        const [tpubkey, _] = Tap.getPubKey(UNSPENDABLE_PUBKEY, { tree })
        return Address.p2tr.fromPubKey(tpubkey, NETWORK)
    }

    scriptPubKey(){
        return Address.toScriptPubKey(this.address())
    }

    setOutputAddress(address){
        this.#nextScriptPubKey = Address.toScriptPubKey(address)
    }
}


export class Leaf {

    #lockArgs

    constructor(tx, ...args){
        this.tx = tx
        this.lockingScript = compileScript( this.lock(...args) )
        this.encodedLockingScript = Tap.encodeScript(this.lockingScript)
        this.#lockArgs = args
    }

    async execute(...args){
        const tree = this.tx.tree()
        const target = this.encodedLockingScript
        const [_, cblock] = Tap.getPubKey(UNSPENDABLE_PUBKEY, { tree, target })

        const tx = this.tx.tx() // TODO: cleanup this code smell `tx.tx()`
        const unlockScript = compileUnlockScript(this.unlock(...this.#lockArgs, ...args))
        tx.vin[0].witness = [...unlockScript, this.lockingScript, cblock]
        const txhex = Tx.encode(tx).hex
        console.log(`Executing ${this.constructor.name}...`)
        const txid = await broadcastTransaction(txhex)
        console.log(`broadcasted Tx: ${txid}`)
    }
}

export function compileSequence(sequence, outpoint, finalAddress) {
    const result = sequence.map(root => new Transaction(root))

    for (let i = 0; i < result.length - 1; i++){
        const tx = result[i]
        tx.setPrevOutpoint(outpoint)
        tx.setOutputAddress(result[i+1].address())
        outpoint = tx.nextOutpoint()
    }

    const tx = result[result.length-1]
    tx.setPrevOutpoint(outpoint)
    tx.setOutputAddress(finalAddress)

    return result
}


const mergeRoots = (rootA, rootB) => [...rootA, ...rootB]

const mergeSequences = (sequenceA, sequenceB) => {
    const length = Math.max(sequenceA.length, sequenceB.length)
    const result = []
    for (let i = 0; i < length; i++) {
        const a = sequenceA[i] || []
        const b = sequenceB[i] || []
        result[i] = [...a, ...b]
    }
    return result
}
