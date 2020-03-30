'use strict';

require('es6-promise/auto');

const WebSocket = require('isomorphic-ws');
const Is = require('is');

const protocol = require('./protocol');
const rpcCall = require('./rpc');
const consts = require('./const');
const tools = require('./crypto/tools');

const TIMEOUT_CHECK_INTERVAL = 250;

function ResponseProcessor(pid, timeout) {
  if (pid instanceof Uint8Array) {
    pid = tools.bytesToHex(pid);
  }

  let responseHandler = null
  let timeoutHandler = null

  let now = Date.now()
  let deadline = now + timeout * 1000

  this.checkTimeout = function (now) {
    return now > deadline
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
    if (pid instanceof Uint8Array) {
      pid = tools.bytesToHex(pid);
    }

    if(Is.instanceof(responseProcessorList[pid], ResponseProcessor)) {
      responseProcessorList[pid].handleResponse(data)
      delete responseProcessorList[pid]
    }
  }

  function timeoutCheck() {
    let timeoutProcessor = []
    let now = Date.now()
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

function messageFromPayload(payload, encrypt, dest) {
  if (encrypt) {
    return protocol.encryption.encryptPayload.call(this, payload.serializeBinary(), dest);
  }
  return protocol.newMessage(payload.serializeBinary(), false);
}

async function sendMsg(dest, data, encrypt, maxHoldingSeconds, replyToPid, msgPid) {
  if (Array.isArray(dest)) {
    if (dest.length === 0) {
      return null;
    }
    if (dest.length === 1) {
      return await sendMsg.call(this, dest[0], data, encrypt, maxHoldingSeconds, replyToPid, msgPid);
    }
  }

  let payload;
  if (Is.string(data)) {
    payload = protocol.newTextPayload(data, replyToPid, msgPid);
  } else {
    payload = protocol.newBinaryPayload(data, replyToPid, msgPid);
  }

  let pldMsg = messageFromPayload.call(this, payload, encrypt, dest);
  if (Array.isArray(pldMsg)) {
    pldMsg = pldMsg.map(pld => pld.serializeBinary());
  } else {
    pldMsg = pldMsg.serializeBinary();
  }

  let msgs = [];
  if (Array.isArray(pldMsg)) {
    let destList = [], pldList = [], totalSize = 0, size = 0;
    for (var i = 0; i < pldMsg.length; i++) {
      size = pldMsg[i].length + dest[i].length + protocol.signatureLength;
      if (size > protocol.maxClientMessageSize) {
        throw "message size is greater than " + protocol.maxClientMessageSize + " bytes";
      }
      if (totalSize + size > protocol.maxClientMessageSize) {
        msgs.push(await protocol.newOutboundMessage.call(this, destList, pldList, maxHoldingSeconds));
        destList = [];
        pldList = [];
        totalSize = 0;
      }
      destList.push(dest[i]);
      pldList.push(pldMsg[i]);
      totalSize += size;
    }
    msgs.push(await protocol.newOutboundMessage.call(this, destList, pldList, maxHoldingSeconds));
  } else {
    if (pldMsg.length + dest.length + protocol.signatureLength > protocol.maxClientMessageSize) {
      throw "message size is greater than " + protocol.maxClientMessageSize + " bytes";
    }
    msgs.push(await protocol.newOutboundMessage.call(this, dest, pldMsg, maxHoldingSeconds));
  }

  if (msgs.length > 1) {
    console.log(`Client message size is greater than ${protocol.maxClientMessageSize} bytes, split into ${msgs.length} batches.`);
  }

  msgs.forEach((msg) => {
    this.ws.send(msg.serializeBinary());
  });

  return payload.getPid();
}

async function handleInboundMsg(rawMsg) {
  let msg = protocol.messages.InboundMessage.deserializeBinary(rawMsg);

  let prevSignature = msg.getPrevSignature();
  if (prevSignature.length > 0) {
    prevSignature = tools.bytesToHex(prevSignature);
    let receipt = await protocol.newReceipt.call(this, prevSignature);
    this.ws.send(receipt.serializeBinary());
  }

  let pldMsg = protocol.payloads.Message.deserializeBinary(msg.getPayload());
  let pldBytes;
  if (pldMsg.getEncrypted()) {
    pldBytes = protocol.encryption.decryptPayload.call(this, pldMsg, msg.getSrc());
  } else {
    pldBytes = pldMsg.getPayload();
  }
  let payload = protocol.payloads.Payload.deserializeBinary(pldBytes);
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
            return Promise.resolve(f(msg.getSrc(), data, payload.getType(), pldMsg.getEncrypted(), payload.getPid()));
          } catch (e) {
            console.log(e);
            return Promise.resolve(null);
          }
        }));
      }
      let responded = false;
      for (let response of responses) {
        if (response === false) {
          return true;
        } else if (response !== undefined && response !== null) {
          this.send(msg.getSrc(), response, {
            encrypt: pldMsg.getEncrypted(),
            msgHoldingSeconds: 0,
            replyToPid: payload.getPid(),
            noReply: true,
          });
          responded = true;
          break;
        }
      }
      if (!responded) {
        await this.sendACK(msg.getSrc(), payload.getPid(), pldMsg.getEncrypted());
      }
      return true;
  }

  return false;
}

async function handleMsg(rawMsg) {
  let msg = protocol.messages.ClientMessage.deserializeBinary(rawMsg);
  switch (msg.getMessageType()) {
    case protocol.messages.ClientMessageType.INBOUND_MESSAGE:
      return await handleInboundMsg.call(this, msg.getMessage());
    default:
      return false
  }
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
  this.responseManager = new ResponseManager();
  this.ws = null;
  this.node = null;
  this.ready = false;

  this.connect();
};

function isTls() {
  if (this.options && Is.bool(this.options.tls)) {
    return this.options.tls;
  }
  if (typeof window === 'undefined') {
    return false;
  }
  if (window.location && window.location.protocol === "https:") {
    return true;
  }
  return false;
}

function newWsAddr(nodeInfo) {
  if (!nodeInfo.addr) {
    console.log('No address in node info', nodeInfo);
    if (this.shouldReconnect) {
      this.reconnect();
    }
    return;
  }

  var ws;
  try {
    ws = new WebSocket((isTls.call(this) ? 'wss://' : 'ws://') + nodeInfo.addr);
    ws.binaryType = "arraybuffer";
  } catch (e) {
    console.log('Create WebSocket failed,', e);
    if (this.shouldReconnect) {
      this.reconnect();
    }
    return;
  }

  if (this.ws) {
    this.ws.onclose = () => {};
    this.ws.close();
  }

  this.ws = ws;
  this.node = nodeInfo;

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
        console.log(e);
      }
      return;
    }

    let msg = JSON.parse(event.data);
    if (msg.Error !== undefined && msg.Error !== consts.errCodes.success) {
      console.log(msg);
      if (msg.Error === consts.errCodes.wrongNode) {
        newWsAddr.call(this, msg.Result);
      } else if (msg.Action === 'setClient') {
        this.ws.close();
      }
      return;
    }
    switch (msg.Action) {
      case 'setClient':
        this.sigChainBlockHash = msg.Result.sigChainBlockHash;
        this.ready = true;
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
      console.warn('WebSocket unexpectedly closed.');
      this.reconnect();
    }
  };

  ws.onerror = (err) => {
    console.log(err.message);
  }
}

Client.prototype.connect = async function () {
  try {
    let res = await rpcCall(
      this.options.seedRpcServerAddr,
      isTls.call(this) ? 'getwssaddr' : 'getwsaddr',
      { address: this.addr },
    );
    newWsAddr.call(this, res);
  } catch (err) {
    console.log('RPC call failed,', err);
    if (this.shouldReconnect) {
      this.reconnect();
    }
  }
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

function getOrDefault(value, defaultValue) {
  if (value === undefined) {
    return defaultValue;
  }
  return value;
}

Client.prototype.send = async function (dest, data, options = {}) {
  let msgHoldingSeconds = getOrDefault(options.msgHoldingSeconds, this.options.msgHoldingSeconds);
  let encrypt = getOrDefault(options.encrypt, this.options.encrypt);

  let pid = await sendMsg.call(this, dest, data, encrypt, msgHoldingSeconds, options.replyToPid, options.pid);
  if (pid === null || options.noReply) {
    return null;
  }

  let responseProcessor = new ResponseProcessor(pid, options.responseTimeout || this.options.responseTimeout)
  this.responseManager.setProcessor(responseProcessor)

  return await new Promise(function(resolve, reject) {
    responseProcessor.onResponse(resolve);
    responseProcessor.onTimeout(() => reject('Message timeout.'));
  });
};

Client.prototype.sendACK = async function (dest, pid, encrypt) {
  if (Array.isArray(dest)) {
    if (dest.length === 0) {
      return;
    }
    if (dest.length === 1) {
      return await this.sendACK(dest[0], pid, encrypt);
    }
    if (dest.length > 1 && encrypt) {
      console.warn("Encrypted ACK with multicast is not supported, fallback to unicast.")
      for (var i = 0; i < dest.length; i++) {
        await this.sendACK(dest[i], pid, encrypt);
      }
      return;
    }
  }

  let payload = protocol.newAckPayload(pid);
  let pldMsg = messageFromPayload.call(this, payload, encrypt, dest);
  let msg = protocol.newOutboundMessage.call(this, dest, pldMsg.serializeBinary(), 0);
  this.ws.send(msg.serializeBinary());
};

Client.prototype.getSubscribers = function (topic, options = {}) {
  options = Object.assign({}, {offset: 0, limit: 1000, meta: false, txPool: false}, options );
  return rpcCall(
    this.options.seedRpcServerAddr,
    'getsubscribers',
    { topic: topic, offset: options.offset, limit: options.limit, meta: options.meta, txPool: options.txPool },
  );
}

Client.prototype.getSubscribersCount = function (topic) {
  return rpcCall(
    this.options.seedRpcServerAddr,
    'getsubscriberscount',
    { topic: topic },
  );
}

Client.prototype.getSubscription = function (topic, subscriber) {
  return rpcCall(
    this.options.seedRpcServerAddr,
    'getsubscription',
    { topic: topic, subscriber: subscriber },
  );
}

Client.prototype.publish = async function (topic, data, options = {}) {
  let offset = 0;
  let limit = 1000;
  let res = await this.getSubscribers(topic, { offset, limit, txPool: options.txPool || false });
  let subscribers = res.subscribers;
  let subscribersInTxPool = res.subscribersInTxPool;
  while (res.subscribers && res.subscribers.length >= limit) {
    offset += limit;
    res = await this.getSubscribers(topic, { offset, limit });
    subscribers = subscribers.concat(res.subscribers);
  }
  if (options.txPool) {
    subscribers = subscribers.concat(subscribersInTxPool);
  }
  options = Object.assign({}, options, { noReply: true });
  return this.send(subscribers, data, options);
}

Client.prototype.close = function () {
  this.shouldReconnect = false;
  this.ws.close();
  this.responseManager.stopProcessor()
};

module.exports = Client;
