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
  this.options = options;
  this.addr = addr;
  this.eventListeners = {};
  this.sigChainBlockHash = null;
  this.shouldReconnect = false;
  this.reconnectInterval = options.reconnectIntervalMin;
  this.ws = null;
  this.nodeAddr = null;

  this.connect();
};

Client.prototype.connect = function () {
  rpcCall(
    this.options.rpcServerAddr,
    'getwsaddr',
    { address: this.addr },
  ).then(res => {
    var ws;
    try {
      ws = new WebSocket('ws://' + res.result);
    } catch (e) {
      if (this.shouldReconnect) {
        console.log('Create WebSocket failed.');
        this.reconnect();
      }
      return;
    }
    this.ws = ws;
    this.nodeAddr = res.result;

    ws.onopen = () => {
      ws.send(JSON.stringify({
        Action: 'setClient',
        Addr: this.addr,
      }));
      this.shouldReconnect = true;
      this.reconnectInterval = this.options.reconnectIntervalMin;
    };

    ws.onmessage = (event) => {
      let msg = JSON.parse(event.data);
      if (msg.Error !== undefined && msg.Error !== consts.errCodes.success) {
        console.error(msg);
        if (msg.Action === 'setClient') {
          this.ws.close();
        }
        return;
      }
      switch (msg.Action) {
        case 'setClient':
          if (this.eventListeners.connect) {
            this.eventListeners.connect.forEach(f => f());
          }
          break;
        case 'updateSigChainBlockHash':
          this.sigChainBlockHash = msg.Result;
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

    ws.onclose = () => {
      if (this.shouldReconnect) {
        console.log('WebSocket unexpectedly closed.');
        this.reconnect();
      }
    };

    ws.onerror = (err) => {
      console.log(err.message);
    }
  }).catch(err => {
    console.error(err);
    if (this.shouldReconnect) {
      console.log('RPC call failed.');
      this.reconnect();
    }
  });
};

Client.prototype.reconnect = function () {
  console.log('Reconnecting in ' + this.reconnectInterval/1000 + 's...');
  setTimeout(() => this.connect(), this.reconnectInterval);
  this.reconnectInterval *= 2;
  if (this.reconnectInterval > this.options.reconnectIntervalMax) {
    this.reconnectInterval = this.options.reconnectIntervalMax;
  }
};

Client.prototype.on = function (event, func) {
  if (this.eventListeners[event]) {
    this.eventListeners[event].push(func);
  } else {
    this.eventListeners[event] = [func];
  }
};

Client.prototype.send = function (dest, payload) {
  this.ws.send(JSON.stringify({
    Action: 'sendPacket',
    Dest: dest,
    Payload: payload,
    Signature: '',
  }));
};

Client.prototype.close = function () {
  this.shouldReconnect = false;
  this.ws.close();
};
