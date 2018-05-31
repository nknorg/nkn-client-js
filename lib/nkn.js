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
    rpcServerAddr: options.seedRpcServerAddr || consts.seedRpcServerAddr,
  });
  return client;
}
