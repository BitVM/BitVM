import * as pseudoOpcodes from './pseudo-opcodes.js'
Object.assign(window, pseudoOpcodes)

export const loop = (count, template) => {
    let res = [];
    for (let i = 0; i < count; i++) {
        res.push( template(i, count) );
    }
    return res
}

window.loop = loop
