'use strict';

require('es6-promise/auto');

const WebSocket = require('isomorphic-ws');
const Is = require('is')
const Moment = require('moment')

const protocol = require('./protocol');
const rpcCall = require('./rpc');
const consts = require('./const');

const TIMEOUT_CHECK_INTERVAL = 250;

function ResponseProcessor(pid, timeout) {
  let responseHandler = null
  let timeoutHandler = null

  let now = new Moment()
  let deadline = now.add(timeout, 's')

  this.checkTimeout = function (now) {
    return now.isAfter(deadline)
  }

  this.pid = pid

  this.onResponse = function (handler) {
    responseHandler = handler
    return this
  }

  this.onTimeout = function (handler) {
    timeoutHandler = handler
    return this
  }

  this.handleResponse = function (data) {
    if(Is.function(responseHandler)) {
      responseHandler(data)
    }
  }

  this.handleTimeout = function () {
    if(Is.function(timeoutHandler)) {
      timeoutHandler(this.pid)
    }
  }
}

function ResponseManager() {
  let responseProcessorList = {};
  let timer = null;

  this.setProcessor = function (proceccor) {
    responseProcessorList[proceccor.pid] = proceccor
  }

  this.clearProcessor = function () {
    for(let pid in responseProcessorList) {
      responseProcessorList[pid].handleTimeout()
    }
    responseProcessorList = {}
  }

  this.stopProcessor = function () {
    clearTimeout(timer);
    this.clearProcessor();
  }

  this.callResponseHandler = function (pid, data) {
    if(Is.instanceof(responseProcessorList[pid], ResponseProcessor)) {
      responseProcessorList[pid].handleResponse(data)
      delete responseProcessorList[pid]
    }
  }

  function timeoutCheck() {
    let timeoutProcessor = []
    let now = new Moment()
    for(let pid in responseProcessorList) {
      if(responseProcessorList[pid].checkTimeout(now)) {
        timeoutProcessor.push(responseProcessorList[pid])
      }
    }

    timeoutProcessor.forEach(p => {
      p.handleTimeout()
      delete responseProcessorList[p.pid]
    })

    timer = setTimeout(timeoutCheck, TIMEOUT_CHECK_INTERVAL)
  }

  timeoutCheck()
}

function sendMsg(ws, dest, data, maxHoldingSeconds, replyToPid) {
  let payload;
  if (Is.string(data)) {
    payload = protocol.newTextPayload(data, replyToPid);
  } else {
    payload = protocol.newBinaryPayload(data, replyToPid);
  }

  let msg = new protocol.messages.OutboundMessage();

  if (Array.isArray(dest)) {
    if (dest.length === 0) {
      return null;
    }
    msg.setDestsList(dest);
  } else {
    msg.setDest(dest);
  }

  msg.setPayload(payload.serializeBinary());

  msg.setMaxHoldingSeconds(maxHoldingSeconds);

  ws.send(msg.serializeBinary());

  return payload.getPid();
}

function sendACK(ws, dest, pid) {
  let payload = protocol.newAckPayload(pid);
  let msg = new protocol.messages.OutboundMessage();
  msg.setDest(dest);
  msg.setPayload(payload.serializeBinary());
  msg.setMaxHoldingSeconds(0);
  ws.send(msg.serializeBinary());
};

async function handleMsg(rawMsg) {
  let msg = protocol.messages.InboundMessage.deserializeBinary(rawMsg);
  let payload = protocol.payloads.Payload.deserializeBinary(msg.getPayload());
  let data = payload.getData();

  // process data
  switch (payload.getType()) {
    case protocol.payloads.PayloadType.TEXT:
      let textData = protocol.payloads.TextData.deserializeBinary(data);
      data = textData.getText();
      break;
    case protocol.payloads.PayloadType.ACK:
      data = undefined;
      break;
  }

  // handle response if applicable
  if (payload.getReplyToPid().length) {
    this.responseManager.callResponseHandler(payload.getReplyToPid(), data, payload.getType());
    return true;
  }

  // handle msg
  switch (payload.getType()) {
    case protocol.payloads.PayloadType.TEXT:
    case protocol.payloads.PayloadType.BINARY:
      let responses = [];
      if (this.eventListeners.message) {
        responses = await Promise.all(this.eventListeners.message.map(f => {
          try {
            return Promise.resolve(f(msg.getSrc(), data, payload.getType()));
          } catch (e) {
            console.error(e);
            return Promise.resolve(null);
          }
        }));
      }
      let responded = false;
      for (let response of responses) {
        if (response !== undefined && response !== null) {
          sendMsg(this.ws, msg.getSrc(), response, 0, payload.getPid());
          responded = true;
          break;
        }
      }
      if (!responded) {
        sendACK(this.ws, msg.getSrc(), payload.getPid());
      }
      return true;
  }

  return false;
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
  this.responseTimeout = options.responseTimeout;
  this.msgHoldingSeconds = options.msgHoldingSeconds;
  this.responseManager = new ResponseManager();
  this.ws = null;
  this.nodeAddr = null;

  this.connect();
};

function newWsAddr(addr) {
  var ws;
  try {
    ws = new WebSocket('ws://' + addr);
    ws.binaryType = "arraybuffer";
  } catch (e) {
    if (this.shouldReconnect) {
      console.log('Create WebSocket failed.');
      this.reconnect();
    }
    return;
  }

  if (this.ws) {
    this.ws.onclose = () => {};
    this.ws.close();
  }

  this.ws = ws;
  this.nodeAddr = addr;

  ws.onopen = () => {
    ws.send(JSON.stringify({
      Action: 'setClient',
      Addr: this.addr,
    }));
    this.shouldReconnect = true;
    this.reconnectInterval = this.options.reconnectIntervalMin;
  };

  ws.onmessage = async (event) => {
    if (event.data instanceof ArrayBuffer) {
      try {
        let handled = await handleMsg.bind(this)(event.data);
        if(!handled) {
          console.warn('Unhandled msg.');
        }
      } catch (e) {
        console.error(e);
      }
      return;
    }

    let msg = JSON.parse(event.data);
    if (msg.Error !== undefined && msg.Error !== consts.errCodes.success) {
      console.error(msg);
      if (msg.Error === consts.errCodes.wrongNode) {
        newWsAddr.call(this, msg.Result);
      } else if (msg.Action === 'setClient') {
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
      case 'sendRawBlock':
        if (this.eventListeners.block) {
          this.eventListeners.block.forEach(f => f(msg.Result));
        }
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
}

Client.prototype.connect = function () {
  rpcCall(
    this.options.rpcServerAddr,
    'getwsaddr',
    { address: this.addr },
  ).then(res => {
    newWsAddr.call(this, res.result);
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
  let msgHoldingSeconds = options.msgHoldingSeconds
  if (msgHoldingSeconds === undefined) {
    msgHoldingSeconds = this.msgHoldingSeconds
  }

  let pid = sendMsg(this.ws, dest, data, msgHoldingSeconds);
  if (pid === null) {
    return null;
  }

  let responseProcessor = new ResponseProcessor(pid, options.responseTimeout || this.responseTimeout)
  this.responseManager.setProcessor(responseProcessor)

  return new Promise(function(resolve, reject) {
    responseProcessor.onResponse(resolve);
    responseProcessor.onTimeout(() => reject('Message timeout.'));
  });
};

Client.prototype.publish = function (topic, bucket, data, options = {}) {
  let msgHoldingSeconds = options.msgHoldingSeconds
  if (msgHoldingSeconds === undefined) {
    msgHoldingSeconds = this.msgHoldingSeconds
  }
  rpcCall(
      this.options.rpcServerAddr,
      'getsubscribers',
      { topic: topic, bucket: bucket },
  ).then(res => {
    sendMsg.call(this, this.ws, Object.keys(res.result), data, msgHoldingSeconds);
  }).catch(err => {
    console.error(err);
    if (this.shouldReconnect) {
      console.log('RPC call failed.');
      this.reconnect();
    }
  });
}

Client.prototype.close = function () {
  this.shouldReconnect = false;
  this.ws.close();
  this.responseManager.stopProcessor()
};

module.exports = Client;
