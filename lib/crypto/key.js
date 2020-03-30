'use strict';

const nacl = require('tweetnacl');
const ed2curve = require('ed2curve');
const tools = require('./tools');

module.exports = Key;

function Key(options = {}) {
  if (!(this instanceof Key)) {
    return new Key(options);
  }

  let key, seed;

  if (options.seed) {
    seed = tools.hexToBytes(options.seed);
  } else {
    seed = tools.randomBytes(nacl.sign.seedLength);
  }

  key = nacl.sign.keyPair.fromSeed(seed);

  this.key = key;
  this.publicKey = tools.bytesToHex(key.publicKey);
  this.privateKey = tools.bytesToHex(key.secretKey);
  this.seed = tools.bytesToHex(seed);
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
  let nonce = options.nonce || tools.randomBytes(nacl.box.nonceLength);
  return {
    message: nacl.box.after(message, nonce, sharedKey),
    nonce: nonce,
  };
}

Key.prototype.decrypt = function (encryptedMessage, nonce, srcPubkey, options = {}) {
  let sharedKey = this.getOrComputeSharedKey(srcPubkey);
  return nacl.box.open.after(encryptedMessage, nonce, sharedKey);
}

Key.prototype.sign = async function (message) {
  let sig = nacl.sign.detached(message, this.key.secretKey);
  return tools.paddingSignature(tools.bytesToHex(sig), nacl.sign.signatureLength);
}
