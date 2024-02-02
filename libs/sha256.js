const fileUrl = import.meta.url.replace(/\.js$/, '.wasm');
const sha256_wasm = await (await fetch(fileUrl)).arrayBuffer()
const sha256_wasm_exports = (await WebAssembly.instantiate(sha256_wasm)).instance.exports

export function sha256(data) {
	const wasm_data = new Uint8Array(sha256_wasm_exports.memory.buffer, 0, data.length)
	const wasm_hash = new Uint8Array(sha256_wasm_exports.memory.buffer, data.length, 32)
	wasm_data.set(data)
	sha256_wasm_exports.SHA256(wasm_data.byteOffset, wasm_hash.byteOffset);
	return wasm_hash.slice(0, 32)
}