'use strict';

const WebSocket = require('isomorphic-ws');
const Is = require('is')
const Moment = require('moment')

const nknProtocol = require('./protocol');
const rpcCall = require('./rpc');
const consts = require('./const');

const HALF_SECOND = 500;

module.exports = Client;

function ACKProcessor(pid, timeout) {
  let ackHandler = null
  let timeoutHandler = null

  let outTime = (new Moment()).add(timeout, 's')

  this.checkTimeout = function (now) {
    return now.isAfter(outTime)
  }

  this.pid = pid

  this.onACK = function (handler) {
    ackHandler = handler
    return this
  }

  this.onTimeout = function (handler) {
    timeoutHandler = handler
    return this
  }

  this.handleACK = function () {
    if(Is.function(ackHandler)) {
      ackHandler(this.pid)
    }
  }

  this.handleTimeout = function () {
    if(Is.function(timeoutHandler)) {
      timeoutHandler(this.pid)
    }
  }
}

function ACKProcessorTask() {
  let ackProcessorList = {};
  let timer = null;

  this.setProcessor = function (proceccor) {
    ackProcessorList[proceccor.pid] = proceccor
  }

  this.clearProcessor = function () {
    for(let pid in ackProcessorList) {
      ackProcessorList[pid].handleTimeout()
    }
    ackProcessorList = {}
  }

  this.stopProcessor = function () {
    clearTimeout(timer);
    this.clearProcessor();
  }

  this.callACKHandler = function (pid) {
    if(Is.instanceof(ackProcessorList[pid], ACKProcessor)) {
      ackProcessorList[pid].handleACK()
      delete ackProcessorList[pid]
    }
  }

  function timeoutCheck() {
    let timeoutProcessor = []
    let now = new Moment()
    for(let pid in ackProcessorList) {
      if(ackProcessorList[pid].checkTimeout(now)) {
        timeoutProcessor.push(ackProcessorList[pid])
      }
    }

    timeoutProcessor.forEach(p => {
      p.handleTimeout()
      delete ackProcessorList[p.pid]
    })

    timer = setTimeout(timeoutCheck, HALF_SECOND)
  }

  timeoutCheck()
}

function sendACK(ws, dest, pid) {
  let msgPayload = new nknProtocol.ack(pid)

  ws.send(JSON.stringify({
    Action: 'sendPacket',
    Dest: dest,
    Payload: msgPayload.toJSON(),
    Signature: '',
  }));
};

function handleMsg(msg) {
  let ret = false

  let msgObj = nknProtocol.dataParse(msg.Payload)
  if(!msgObj) {
    console.error('invalid protocol data:', msg.Payload)
    return ret
  }

  switch (msgObj.header.type) {
    case nknProtocol.payloadTypes.MESSAGE_PAYLOAD:
      sendACK(this.ws, msg.Src, msgObj.header.pid)
      this.eventListeners.message && this.eventListeners.message.forEach(f => {
        f(msg.Src, msgObj.payload)
      })

      ret = true
      break

    case nknProtocol.payloadTypes.ACK_PAYLOAD:
      this.ackProcessorTask.callACKHandler(msgObj.payload)
      ret = true
      break
  }

  return ret
}

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
  this.ackTimeout = options.ackTimeout;
  this.ackProcessorTask = new ACKProcessorTask();
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
          let handled = handleMsg.call(this, msg);
          if(!handled) {
            console.warn('Unknown msg payload:', msg.Payload);
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

Client.prototype.send = function (dest, payload, options = {}) {
  let msgPayload = new nknProtocol.stringMessage(payload)

  this.ws.send(JSON.stringify({
    Action: 'sendPacket',
    Dest: dest,
    Payload: msgPayload.toJSON(),
    Signature: '',
  }))

  let ackProcessor = new ACKProcessor(msgPayload.header.pid, options.ackTimeout || this.ackTimeout)
  this.ackProcessorTask.setProcessor(ackProcessor)
  return new Promise(function(resolve, reject) {
    ackProcessor.onACK(resolve);
    ackProcessor.onTimeout(() => reject('Message timeout.'));
  });
};

Client.prototype.close = function () {
  this.shouldReconnect = false;
  this.ws.close();
  this.ackProcessorTask.stopProcessor()
};
