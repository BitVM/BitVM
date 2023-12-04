import * as Esplora  from '../libs/esplora.js'

export async function startListening(onTransaction){
	let prevHeight = await Esplora.fetchLatestBlockHeight() - 3
	console.log(`Started listening at height ${prevHeight}`)
	setInterval(async _ => {
		const latestHeight = await Esplora.fetchLatestBlockHeight()
		while( prevHeight < latestHeight ){
			const blockHash = await Esplora.fetchBlockAtHeight(prevHeight + 1)
			const txids = await Esplora.fetchTXIDsInBlock(blockHash)
			for (const txid of txids) await onTransaction(txid)
			prevHeight += 1
		}
	}, 15000)
}