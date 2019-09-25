'use strict';

const nacl = require('tweetnacl');

const tools = require('../crypto/tools');
const address = require('./address');
const protocol = require('.');

module.exports.encryptPayload = function (payload, dest) {
  if (Array.isArray(dest)) {
    let nonce = tools.randomBytes(nacl.secretbox.nonceLength);
    let key = tools.randomBytes(nacl.secretbox.keyLength);
    let encryptedPayload = nacl.secretbox(payload, nonce, key);

    let msgs = [];
    for (var i = 0; i < dest.length; i++) {
      let encryptedKey = this.key.encrypt(key, address.getPubkey(dest[i]));
      let mergedNonce = tools.mergeBytes(encryptedKey.nonce, nonce);
      let msg = protocol.newMessage(encryptedPayload, true, mergedNonce, encryptedKey.message);
      msgs.push(msg);
    }
    return msgs;
  } else {
    let encrypted = this.key.encrypt(payload, address.getPubkey(dest));
    return protocol.newMessage(encrypted.message, true, encrypted.nonce);
  }
}

module.exports.decryptPayload = function (msg, srcAddr) {
  let rawPayload = msg.getPayload();
  let srcPubkey = address.getPubkey(srcAddr)
  let nonce = msg.getNonce();
  let encryptedKey = msg.getEncryptedKey();
  let decryptedPayload;
  if (encryptedKey && encryptedKey.length > 0) {
    if (nonce.length != nacl.box.nonceLength + nacl.secretbox.nonceLength) {
      throw "Invalid nonce length."
    }
    let sharedKey = this.key.decrypt(encryptedKey, nonce.slice(0, nacl.box.nonceLength), srcPubkey);
    if (sharedKey === null) {
      throw "Decrypt shared key failed."
    }
    decryptedPayload = nacl.secretbox.open(rawPayload, nonce.slice(nacl.box.nonceLength), sharedKey)
    if (decryptedPayload === null) {
      throw "Decrypt message failed."
    }
  } else {
    if (nonce.length != nacl.box.nonceLength) {
      throw "Invalid nonce length."
    }
    decryptedPayload = this.key.decrypt(rawPayload, nonce, srcPubkey);
    if (decryptedPayload === null) {
      throw "Decrypt message failed."
    }
  }
  return decryptedPayload;
}
