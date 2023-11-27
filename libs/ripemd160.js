
let ripemd160_wasm_exports = undefined

if (!ripemd160_wasm_exports) {
	const ripemd160_wasm = await (await fetch('../libs/ripemd160.wasm')).arrayBuffer()
	ripemd160_wasm_exports = (await WebAssembly.instantiate(ripemd160_wasm)).instance.exports
}

export function ripemd160(data) {

	const wasm_data = new Uint8Array(ripemd160_wasm_exports.memory.buffer, 0, data.length)
	const wasm_hash = new Uint8Array(ripemd160_wasm_exports.memory.buffer, data.length, 20)
	wasm_data.set(data)
	ripemd160_wasm_exports.RIPEMD160(wasm_data.byteOffset, wasm_hash.byteOffset);
	return wasm_hash.slice(0, 20)
}
