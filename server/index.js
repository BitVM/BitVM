import { WebSocketServer } from 'ws'
import {
    MSG_TYPE_REGISTER,
    MSG_TYPE_REGISTERED,
    MSG_TYPE_FORWARD,
} from './constants.js'

const wss = new WebSocketServer({ port: 8080 })


const clients = {}

wss.on('connection', ws => {
    ws.on('error', console.error)

    ws.on('message', data => {
        try {
            const msg = JSON.parse(data)
            console.log('received', msg)

            switch (msg.type) {
                case MSG_TYPE_REGISTER:
                    return register(ws, msg)
                case MSG_TYPE_FORWARD:
                    return forward(ws, msg)
            }
        } catch (e) {
            console.error(e)
        }
    })

    ws.on('close', ws => {
        delete clients[ws.clientId]
    })
})

const register = (ws, msg) => {
    const clientId = msg.clientId
    ws.clientId = clientId
    clients[clientId] = ws
    ws.send(JSON.stringify({ type: MSG_TYPE_REGISTERED }))
}

const forward = (ws, msg) => {
    const recipientId = msg.clientId
    const client = clients[recipientId]
    if (!client) return
    client.send(JSON.stringify(msg))
}