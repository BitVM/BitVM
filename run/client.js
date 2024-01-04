import * as Esplora  from '../libs/esplora.js'

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