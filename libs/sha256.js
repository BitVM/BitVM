const fileUrl = import.meta.url.replace(/\.js$/, '.wasm');
const sha256_wasm = await (await fetch(fileUrl)).arrayBuffer()

const sha256_wasm_exports = (await WebAssembly.instantiate(sha256_wasm)).instance.exports
const memory = sha256_wasm_exports.memory
const bytesPerPage = 64 * 1024

export function sha256(data) {
	// Increase the size of the wasm memory if necessary
	if(data.length > memory.buffer.byteLength){
		const delta = Math.floor((data.length - memory.buffer.byteLength) / bytesPerPage ) + 1
		memory.grow(delta)
	}

	const wasm_data = new Uint8Array(memory.buffer, 0, data.length)
	const wasm_hash = new Uint8Array(memory.buffer, data.length, 32)
	wasm_data.set(data)
	sha256_wasm_exports.SHA256(wasm_data.byteOffset, wasm_hash.byteOffset);
	return wasm_hash.slice(0, 32)
}