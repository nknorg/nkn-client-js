'use strict';

const EC = require('elliptic').ec;
const Client = require('./client');
const consts = require('./const');

var ec = new EC('p256');

module.exports = nkn;

function nkn() {
  let key = ec.genKeyPair();
  let client = Client(key, {
    rpcServerAddr: consts.seedRpcServerAddr,
  });
  return client;
}
