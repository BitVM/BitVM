const fileUrl = import.meta.url.replace(/\.js$/, '.wasm');
const blake3_wasm = await (await fetch(fileUrl)).arrayBuffer()
const blake3_wasm_exports = (await WebAssembly.instantiate(blake3_wasm)).instance.exports

export function blake3(data) {
	const wasm_data = new Uint8Array(blake3_wasm_exports.memory.buffer, 0, data.byteLength)
	const wasm_hash = new Uint8Array(blake3_wasm_exports.memory.buffer, data.byteLength, 32)
	wasm_data.set(new Uint8Array(data))
	blake3_wasm_exports.BLAKE3(wasm_data.byteOffset, wasm_hash.byteOffset)
	return wasm_hash.slice(0, 32)
}
