'use strict';

const WebSocket = require('isomorphic-ws');
const rpcCall = require('./rpc');
const consts = require('./const');

module.exports = Client;

function Client(key, identifier, options) {
  if (!(this instanceof Client)) {
    return new Client(key, identifier, options);
  }

  if (typeof identifier === 'object') {
    options = identifier;
    identifier = undefined;
  }

  options = options || {};

  if (identifier === undefined || identifier === null) {
    identifier = '';
  }

  const pubkey = key.getPublic().encode('hex', true);
  const addr = (identifier ? identifier + '.' : '') + pubkey;

  this.key = key;
  this.identifier = identifier;
  this.pubkey = pubkey;
  this.addr = addr;
  this.eventListeners = {};

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
      if (msg.Action === 'setClient' && msg.Error === consts.errCodes.success) {
        if (this.eventListeners.connect) {
          this.eventListeners.connect.forEach(f => f());
        }
      }
      if (msg.Action === 'receivePacket') {
        if (this.eventListeners.message) {
          this.eventListeners.message.forEach(f => f(null, msg.Payload));
        }
      }
      if (msg.Error !== undefined && msg.Error !== consts.errCodes.success) {
        console.error(msg);
      }
    };
  }).catch(err => {
    console.log(err);
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
