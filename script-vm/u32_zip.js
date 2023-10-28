const u32_zip = (a, b) => {
	if(a >= b) throw 'Error: a >= b'

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
