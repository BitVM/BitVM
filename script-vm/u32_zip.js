const u32_zip = (a, b) => {
	if(a >= b)
		throw 'Error: a >= b'

	a = (a+1) * 4 - 1
	b = (b+1) * 4 - 1
	return `
<${a}>
OP_ROLL
<${b}>
OP_ROLL
<${a+1}>
OP_ROLL
<${b}>
OP_ROLL
<${a+2}>
OP_ROLL
<${b}>
OP_ROLL
<${a+3}>
OP_ROLL
<${b}>
OP_ROLL
`
}

const u32_pick = a => {
	a = (a+1) * 4 - 1
	return `
<${a}>
OP_PICK
<${a}>
OP_PICK
<${a}>
OP_PICK
<${a}>
OP_PICK
`
}

// const u32_zip_input = (a, b) => {
// 	if(b > 0)
// 		throw 'Error: b > 0'

// 	a = (a+1) * 4 - 1
// 	b = ap * 4 + 256 - 4 * b - 1
// 	return `
// <${a}>
// OP_ROLL
// <${b}>
// OP_ROLL
// <${a+1}>
// OP_ROLL
// <${b}>
// OP_ROLL
// <${a+2}>
// OP_ROLL
// <${b}>
// OP_ROLL
// <${a+3}>
// OP_ROLL
// <${b}>
// OP_ROLL
// `
// }


// const u32_zip_input_copy = (a, b) => {
// 	if(b > 0)
// 		throw 'Error: b > 0'

// 	a = (a+1) * 4 - 1
// 	b = ap * 4 + 256 - 4 * b - 1
// 	return `
// <${a}>
// OP_PICK
// <${b+1}>
// OP_ROLL
// <${a}>
// OP_PICK
// <${b+2}>
// OP_ROLL
// <${a}>
// OP_PICK
// <${b+3}>
// OP_ROLL
// <${a}>
// OP_PICK
// <${b+4}>
// OP_ROLL
// `
// }


// const u32_zip_inputs = (a, b) => {
// 	if(a < b)
// 		throw 'Error: a >= b'

// 	a = ap * 4 + 256 - 4 * a - 1
// 	b = ap * 4 + 256 - 4 * b - 1
// 	return `
// <${a}>
// OP_ROLL
// <${b}>
// OP_ROLL
// <${a+1}>
// OP_ROLL
// <${b}>
// OP_ROLL
// <${a+2}>
// OP_ROLL
// <${b}>
// OP_ROLL
// <${a+3}>
// OP_ROLL
// <${b}>
// OP_ROLL
// `
// }



// const u32_copy_input = a => {
// 	if(a > 0)
// 		throw 'Error: a > 0'

// 	a = ap * 4 + 256 - 4 * a - 1
// 	return `
// <${a}>
// OP_PICK
// <${a}>
// OP_PICK
// <${a}>
// OP_PICK
// <${a}>
// OP_PICK
// `
// }


