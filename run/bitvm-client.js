import * as Esplora  from '../libs/esplora.js'
import { fetchJson }  from '../libs/common.js'
import { 
	PaulPlayer, VickyOpponent, PAUL,
	VickyPlayer, PaulOpponent, VICKY  
} from '../transactions/bitvm-player.js'
import { BITVM_GRAPH, compileGraph } from '../transactions/graph.js'
import { Tx } from '../libs/tapscript.js'
import { VM } from './vm.js'


class BitVMClient {
	vicky
	paul
	actorId

	constructor(outpoint, vicky, paul, program, actorId) {
		this.vicky = vicky
		this.paul = paul
		// TODO: the first step of the sequence should be a joined funding TXs taking an input from Paul and an input from Vicky and outputs the joined funding output, which will be used as the start of the sequence. They sign this transaction last, only after they have signed and validated all the rest of the sequence.
	    this.graph = compileGraph(BITVM_GRAPH, outpoint, {vicky, paul, program})
	    this.utxoSet = new Set()
	    this.actorId = actorId
	}

	listen() {
		const opponent = this.actorId == PAUL ? this.vicky : this.paul

	    startListening(async block => {

			for(const txid of block.txids){
				// Check if this transaction belongs to our graph
				const tx = this.graph[txid]
				if(!tx) 
					continue
				console.log(`observed Tx: ${txid}`)
				
				// Read commited values from transaction
				const txHex = await Esplora.fetchTransaction(txid, 'hex')
				opponent.witnessTx(txHex)

				// Update our UTXO set
				this.updateUtxoSet(txid, txHex)
			}

		    // Iterate through our UTXO set and execute the first executable TX
	        for (const utxo of this.utxoSet){
	            for(const nextTx of this.graph[utxo]){
	                const success = await nextTx.tryExecute(this.actorId)
	                if(success)
	                    return
	            }
	        }

		})
	}

    updateUtxoSet(txid, txHex){
    	const tx = Tx.decode(txHex)
    	// TODO: this key should be the outpoint (txid, vout) instead of just a txid
    	tx.vin.forEach(vin => this.utxoSet.delete(tx.vin[0].txid))
    	this.utxoSet.add(txid)
    }
}


export const createPaulClient = async (outpoint, program, data) => {
	const vm = new VM(program, data)
	const vickyJson = await fetchJson('vicky.json')
	const vicky = new VickyOpponent(vickyJson)
    const paul = new PaulPlayer('d898098e09898a0980989b980809809809f09809884324874302975287524398', vicky, vm)
	return new BitVMClient(outpoint, vicky, paul, program, PAUL)
}


export const createVickyClient = async (outpoint, program, data) => {
	const vm = new VM(program, data)
	const paulJson = await fetchJson('paul.json')
	const paul = new PaulOpponent(paulJson)
	const vicky = new VickyPlayer('a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497', paul, vm)
	return new BitVMClient(outpoint, vicky, paul, program, VICKY)
}

export async function startListening(onBlock){
	let prevHeight = await Esplora.fetchLatestBlockHeight() - 3
	console.log(`Started listening at height ${prevHeight}`)
	setInterval(async _ => {
		const latestHeight = await Esplora.fetchLatestBlockHeight()
		while( prevHeight < latestHeight ){
			const blockHash = await Esplora.fetchBlockAtHeight(prevHeight + 1)
			console.log(`new chain tip: ${blockHash}`)
			const txids = await Esplora.fetchTXIDsInBlock(blockHash)
			await onBlock({latestHeight, txids})
			prevHeight += 1
		}
	}, 15000)
}