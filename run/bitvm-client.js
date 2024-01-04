import { PaulPlayer, VickyOpponent, PAUL } from '../transactions/bitvm-player.js'
import { VickyPlayer, PaulOpponent, VICKY } from '../transactions/bitvm-player.js'
import { BITVM_GRAPH, compileGraph } from '../transactions/graph.js'
import * as Esplora from '../libs/esplora.js'
import { startListening } from './client.js'
import { Tx } from '../libs/tapscript.js'
import { program } from './dummy-program.js'

class BitVMClient {
	player_id
	vicky
	paul

	constructor(outpoint, player_id, vicky, paul) {
		this.player_id = player_id
		this.vicky = vicky
		this.paul = paul
		// TODO: the first step of the sequence should be a joined funding TXs taking an input from Paul and an input from Vicky and outputs the joined funding output, which will be used as the start of the sequence. They sign this transaction last, only after they have signed and validated all the rest of the sequence.
	    this.graph = compileGraph(BITVM_GRAPH, outpoint, {paul, vicky, program})
	    this.utxoSet = new Set()
	}

	listen() {
		const player = this.player_id !== PAUL ? this.paul : this.vicky

	    startListening(async block => {

			for(const txid of block.txids){
				// Check if this transaction belongs to our graph
				const tx = this.graph[txid]
				if(!tx) 
					continue
				console.log(`observed Tx: ${txid}`)
				
				// Read commited values from transaction
				const txHex = await Esplora.fetchTransaction(txid, 'hex')
				console.log(this.player_id, 'witnessTx')
				player.witnessTx(txHex)

				// Update our UTXO set
				this.updateUtxoSet(txid, txHex)
			}


			// Iterate through our UTXO set and execute the first executable TX
			for (const utxo of this.utxoSet){
				const nextTx = this.graph[utxo][0]
				if(nextTx.actor !== this.player_id) 
					continue
				await nextTx.getLeaf(0).execute()
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

export class PaulBitVMClient extends BitVMClient {
	constructor(vm, outpoint, opponent_json) {
		const vicky = new VickyOpponent(opponent_json)
	    const paul = new PaulPlayer('d898098e09898a0980989b980809809809f09809884324874302975287524398', vicky, vm)
		super(outpoint, PAUL, vicky, paul)
	}
}

export class VickyBitVMClient extends BitVMClient {
	constructor(vm, outpoint, opponent_json) {
		const paul = new PaulOpponent(opponent_json)
		const vicky = new VickyPlayer('a9bd8b8ade888ed12301b21318a3a73429232343587049870132987481723497', paul, vm)
		super(outpoint, VICKY, vicky, paul)
		this.graph['START'][0].getLeaf(0).execute()
	}
}