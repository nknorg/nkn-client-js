'use strict';

const Client = require('./client');
const consts = require('./const');
const crypto = require('./crypto');
const protocol = require('./protocol');

function nkn(options = {}) {
  let key = crypto.Key({
    privateKey: options.privateKey,
  });

  let msgHoldingSeconds = options.msgHoldingSeconds
  if (msgHoldingSeconds === undefined) {
    msgHoldingSeconds = consts.msgHoldingSeconds
  }

  let client = Client(key, options.identifier, {
    reconnectIntervalMin: options.reconnectIntervalMin || consts.reconnectIntervalMin,
    reconnectIntervalMax: options.reconnectIntervalMax || consts.reconnectIntervalMax,
    responseTimeout: options.responseTimeout || consts.responseTimeout,
    msgHoldingSeconds: msgHoldingSeconds,
    rpcServerAddr: options.seedRpcServerAddr || consts.seedRpcServerAddr,
  });

  return client;
}

module.exports = nkn;
module.exports.PayloadType = protocol.payloads.PayloadType;
