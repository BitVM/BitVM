import {
    MSG_TYPE_REGISTER,
    MSG_TYPE_REGISTERED,
    MSG_TYPE_FORWARD,
} from './constants.js'

export const connect = clientId => {
    return new Promise( resolve => {
        const socket = new Socket(clientId)
        socket.onopen = _ => resolve(socket)
    })
}


export class Socket {

    constructor(clientId, endpoint = 'ws://localhost:8080') {
        const ws = new WebSocket(endpoint)
        this.ws = ws
        this.clientId = clientId

        ws.onopen = _ => this.send({
            type: MSG_TYPE_REGISTER,
            clientId: clientId
        })

        ws.onerror = console.error

        ws.onmessage = event => {
            const msg = JSON.parse(event.data)
            switch (msg.type) {
                case MSG_TYPE_FORWARD:
                    this.onmessage(msg.clientId, JSON.parse(msg.payload))
                    break
                case MSG_TYPE_REGISTERED:
                    this.onopen()
                    break
            }
        }

    }

    send(obj) {
        this.ws.send(JSON.stringify(obj))
    }

    sendTo(recipient, obj) {
        this.send({
            type: MSG_TYPE_FORWARD,
            clientId: recipient,
            payload: JSON.stringify(obj)
        })
    }
}