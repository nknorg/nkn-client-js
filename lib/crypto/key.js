'use strict';

const nacl = require('tweetnacl');
const { hexToBytes, bytesToHex } = require('./tools');

module.exports = Key;

function Key(options = {}) {
  if (!(this instanceof Key)) {
    return new Key(options);
  }

  var key, seed;

  if (options.seed) {
    seed = hexToBytes(options.seed);
  } else {
    seed = nacl.randomBytes(nacl.sign.seedLength);
  }

  key = nacl.sign.keyPair.fromSeed(seed);

  this.key = key;
  this.publicKey = bytesToHex(key.publicKey);
  this.privateKey = bytesToHex(key.secretKey);
  this.seed = bytesToHex(seed);
}
