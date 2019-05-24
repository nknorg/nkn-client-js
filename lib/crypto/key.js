'use strict';

const nacl = require('tweetnacl');
const ed2curve = require('ed2curve');
const { hexToBytes, bytesToHex } = require('./tools');

module.exports = Key;

function Key(options = {}) {
  if (!(this instanceof Key)) {
    return new Key(options);
  }

  let key, seed;

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
  this.curveSecretKey = ed2curve.convertSecretKey(key.secretKey);
  this.sharedKeyCache = {};
}

Key.prototype.getOrComputeSharedKey = function (otherPubkey) {
  if (!this.sharedKeyCache[otherPubkey]) {
    let otherCurvePubkey = ed2curve.convertPublicKey(otherPubkey);
    this.sharedKeyCache[otherPubkey] = nacl.box.before(otherCurvePubkey, this.curveSecretKey);
  }
  return this.sharedKeyCache[otherPubkey];
}

Key.prototype.encrypt = function (message, destPubkey, options = {}) {
  let sharedKey = this.getOrComputeSharedKey(destPubkey);
  let nonce = options.nonce || nacl.randomBytes(nacl.box.nonceLength);
  return {
    message: nacl.box.after(message, nonce, sharedKey),
    nonce: nonce,
  };
}

Key.prototype.decrypt = function (encryptedMessage, nonce, srcPubkey, options = {}) {
  let sharedKey = this.getOrComputeSharedKey(srcPubkey);
  return nacl.box.open.after(encryptedMessage, nonce, sharedKey);
}
