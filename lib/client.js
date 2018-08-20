'use strict';

const WebSocket = require('isomorphic-ws');
const Is = require('is')
const Moment = require('moment')

const protocol = require('./protocol');
const rpcCall = require('./rpc');
const consts = require('./const');

const HALF_SECOND = 500;

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
  let payload = protocol.newAckPayload(pid);
  let msg = new protocol.messages.OutboundMessage();
  msg.setDest(dest);
  msg.setPayload(payload.serializeBinary());
  ws.send(msg.serializeBinary());
};

function handleMsg(raw) {
  let handled = false;
  let msg = protocol.messages.InboundMessage.deserializeBinary(raw);
  let payload = protocol.payloads.Payload.deserializeBinary(msg.getPayload());
  let data = payload.getData();

  switch (payload.getType()) {
    case protocol.payloads.PayloadType.TEXT:
      let textData = protocol.payloads.TextData.deserializeBinary(data);
      data = textData.getText();
    case protocol.payloads.PayloadType.BINARY:
      sendACK(this.ws, msg.getSrc(), payload.getPid());
      this.eventListeners.message && this.eventListeners.message.forEach(f => {
        f(msg.getSrc(), data, payload.getType());
      });
      handled = true;
      break;
    case protocol.payloads.PayloadType.ACK:
      this.ackProcessorTask.callACKHandler(payload.getReplyToPid());
      handled = true;
      break;
  }

  return handled;
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
      ws.binaryType = "arraybuffer";
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
      if (event.data instanceof ArrayBuffer) {
        let handled = handleMsg.call(this, event.data);
        if(!handled) {
          console.warn('Unhandled msg.');
        }
        return;
      }

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

Client.prototype.send = function (dest, data, options = {}) {
  var payload;

  if (Is.string(data)) {
    payload = protocol.newTextPayload(data);
  } else {
    payload = protocol.newBinaryPayload(data);
  }

  let msg = new protocol.messages.OutboundMessage();
  msg.setDest(dest);
  msg.setPayload(payload.serializeBinary());
  this.ws.send(msg.serializeBinary());

  let ackProcessor = new ACKProcessor(payload.getPid(), options.ackTimeout || this.ackTimeout)
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

module.exports = Client;
