'use strict';

const WebSocket = require('isomorphic-ws');
const rpcCall = require('./rpc');
const consts = require('./const');

module.exports = Client;

function Client(key, identifier, options = {}) {
  if (!(this instanceof Client)) {
    return new Client(key, identifier, options);
  }

  if (typeof identifier === 'object') {
    options = identifier;
    identifier = undefined;
  }

  if (identifier === undefined || identifier === null) {
    identifier = '';
  }

  const pubkey = key.publicKey;
  const addr = (identifier ? identifier + '.' : '') + pubkey;

  this.key = key;
  this.identifier = identifier;
  this.addr = addr;
  this.eventListeners = {};
  this.latestBlockHash = null;

  rpcCall(options.rpcServerAddr, 'getwsaddr', [addr]).then(res => {
    const ws = new WebSocket('ws://' + res.result);
    this.ws = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({
        Action: 'setClient',
        Addr: addr,
      }));
    };

    ws.onmessage = (event) => {
      let msg = JSON.parse(event.data);
      if (msg.Error !== undefined && msg.Error !== consts.errCodes.success) {
        console.error(msg);
        return;
      }
      switch (msg.Action) {
        case 'setClient':
          if (this.eventListeners.connect) {
            this.eventListeners.connect.forEach(f => f());
          }
          break;
        case 'sendRawBlock':
          this.latestBlockHash = msg.Result.Hash;
          break;
        case 'receivePacket':
          if (this.eventListeners.message) {
            this.eventListeners.message.forEach(f => f(msg.Src, msg.Payload));
          }
          break;
        case 'sendPacket':
          break;
        default:
          console.warn('Unknown msg type:', msg.Action);
      }
    };
  }).catch(err => {
    console.error(err);
  });
}

Client.prototype.on = function (event, func) {
  if (this.eventListeners[event]) {
    this.eventListeners[event].push(func);
  } else {
    this.eventListeners[event] = [func];
  }
}

Client.prototype.send = function (dest, payload) {
  this.ws.send(JSON.stringify({
    Action: 'sendPacket',
    Dest: dest,
    Payload: payload,
    Signature: '',
  }));
};
