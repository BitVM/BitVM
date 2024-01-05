import * as Esplora  from '../libs/esplora.js'
import { fetchJson }  from '../libs/common.js'
import { 
	PaulPlayer, VickyOpponent, PAUL,
	VickyPlayer, PaulOpponent, VICKY  
} from '../bitvm/bitvm-player.js'
import { compileGraph } from '../scripts/transaction.js'
import { BITVM_GRAPH } from '../bitvm/bitvm-graph.js'
import { Tx } from '../libs/tapscript.js'
import { VM } from './vm.js'


class BitVMClient {
	vicky
	paul
	actorId

	constructor(outpoint, vicky, paul, program, actorId) {
		this.vicky = vicky
		this.paul = paul
		this.graph = compileGraph(BITVM_GRAPH, outpoint, {vicky, paul, program})
		this.utxoSet = {}
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
				this.updateUtxoSet(txid, txHex, block.height)
			}

			// Iterate through our UTXO set and execute the first executable TX
			for (const txid in this.utxoSet){
				const utxo = this.utxoSet[txid]
				for(const nextTx of this.graph[txid]){
					const success = await nextTx.tryExecute(this.actorId, block.height - utxo.blockHeight)
					if(success)
						return
				}
			}

		})
	}

	updateUtxoSet(txid, txHex, blockHeight){
		const tx = Tx.decode(txHex)
		// TODO: this key should be the outpoint (txid, vout) instead of just a txid
		tx.vin.forEach(vin => delete this.utxoSet[tx.vin[0].txid])
		this.utxoSet[txid] = { blockHeight }
	}
}

async function startListening(onBlock){
	let prevHeight = await Esplora.fetchLatestBlockHeight() - 3
	console.log(`Started listening at height ${prevHeight}`)
	setInterval(async _ => {
		const latestHeight = await Esplora.fetchLatestBlockHeight()
		while( prevHeight < latestHeight ){
			const blockHash = await Esplora.fetchBlockAtHeight(prevHeight + 1)
			console.log(`new chain tip: ${blockHash}`)
			const txids = await Esplora.fetchTXIDsInBlock(blockHash)
			await onBlock({ txids, height: latestHeight })
			prevHeight += 1
		}
	}, 15000)
}


export const createPaulClient = async (secret, outpoint, program, data) => {
	const vm = new VM(program, data)
	const vickyJson = await fetchJson('vicky.json')
	const vicky = new VickyOpponent(vickyJson)
    const paul = new PaulPlayer(secret, vicky, vm)
	return new BitVMClient(outpoint, vicky, paul, program, PAUL)
}

export const createVickyClient = async (secret, outpoint, program, data) => {
	const vm = new VM(program, data)
	const paulJson = await fetchJson('paul.json')
	const paul = new PaulOpponent(paulJson)
	const vicky = new VickyPlayer(secret, paul, vm)
	return new BitVMClient(outpoint, vicky, paul, program, VICKY)
}