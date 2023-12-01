import {runVM} from './vm.js'
import {program, data} from './dummy-program.js'

export const USER_PAUL = 'USER_PAUL'
export const USER_VICKY = 'USER_VICKY'

export const MSG_TYPE_HAND = 'MSG_TYPE_HAND'
export const MSG_TYPE_SHAKE = 'MSG_TYPE_SHAKE'
export const MSG_TYPE_ENDSTATE = 'MSG_TYPE_ENDSTATE'

export const protocol = (socket, clientId, msg) => {
    console.log(clientId, msg)
    switch (msg.type) {
        case MSG_TYPE_HAND:
            return onHand(socket, clientId, msg)
        case MSG_TYPE_SHAKE:
            return onShake(socket, clientId, msg)
        case MSG_TYPE_ENDSTATE:
            return onEndState(socket, clientId, msg)
        default:
            console.log(`Msg type ${msg.type} not implemented`)
    }
}


const onHand = (socket, clientId, msg) => {
    socket.sendTo(clientId, { type: MSG_TYPE_SHAKE })
}

const onShake = (socket, clientId, msg) => {
    console.log('Connected with', clientId)
    const endState = runVM(program, data)
    socket.sendTo(clientId, { type: MSG_TYPE_ENDSTATE, endState })
}

const onEndState = (socket, clientId, msg) => {
    const theirEndState = msg.endState
    const endState = runVM(program, data)
    console.log(theirEndState, endState)
}