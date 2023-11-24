import { compile } from './utils.js'
import { Tap, Tx, Address, Signer } from '../libs/tapscript.js'
import { broadcastTransaction }  from '../libs/esplora.js'

const NETWORK = 'signet'
const MIN_FEES = 2000

// This is an unspendable pubkey 
// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
const UNSPENDABLE_PUBKEY = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'

class Transaction {
    #leafs = [];
    #prevOutpoint;
    #nextScriptPubKey;
    
    constructor(txParams){
        for(const leafParams of txParams){
            this.addLeaf(...leafParams)
        }
    }

    addLeaf(type, ...args){
        const leaf = new type(this, ...args)
        this.#leafs.push( leaf )
    }

    getLeaf(index){
        return this.#leafs[index]
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
        return this.#leafs.map(leaf => leaf.encodedLockingScript)
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

    constructor(tx, ...args){
        this.tx = tx
        this.lockingScript = compile( this.lock(...args) )
        this.encodedLockingScript = Tap.encodeScript(this.lockingScript)
    }

    async execute(...args){
        const tree = this.tx.tree()
        const target = this.encodedLockingScript
        const [_, cblock] = Tap.getPubKey(UNSPENDABLE_PUBKEY, { tree, target })

        const tx = this.tx.tx()
        tx.vin[0].witness = [...this.unlock(...args), this.lockingScript, cblock]
        const txhex = Tx.encode(tx).hex
        await broadcastTransaction(txhex)
    }

    sign(player){
        return player.sign(this.tx.tx(), this.encodedLockingScript)
    }
    
}

export function compileSequence(sequence, outpoint, finalAddress) {
    const result = []
    for (let txParams of sequence){
        const tx = new Transaction(txParams)
        result.push(tx)
    }

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






