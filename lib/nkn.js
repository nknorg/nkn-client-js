'use strict';

const Client = require('./client');
const consts = require('./const');
const crypto = require('./crypto');

module.exports = nkn;

function nkn(options = {}) {
  let key = crypto.Key({
    privateKey: options.privateKey,
  });
  let client = Client(key, options.identifier, {
    reconnectIntervalMin: options.reconnectIntervalMin || consts.reconnectIntervalMin,
    reconnectIntervalMax: options.reconnectIntervalMax || consts.reconnectIntervalMax,
    ackTimeout: options.ackTimeout || consts.ackTimeout,
    rpcServerAddr: options.seedRpcServerAddr || consts.seedRpcServerAddr,
  });
  return client;
}
