'use strict';

const CryptoJS = require('crypto-js');
const nacl = require('tweetnacl');

function hexToBytes(hex) {
  for (var bytes = [], c = 0; c < hex.length; c += 2) {
    bytes.push(parseInt(hex.substr(c, 2), 16));
  }
  return new Uint8Array(bytes);
}

function bytesToHex(bytes) {
  return Array.from(bytes, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2)
  }).join('');
}

var randomBytes;
if (typeof navigator != 'undefined' && navigator.product === "ReactNative") {
  randomBytes = require('crypto').randomBytes;
} else {
  randomBytes = nacl.randomBytes;
}

function randomInt32() {
  let b = randomBytes(4);
  b[0] &= 127
  return (b[0]<<24) + (b[1]<<16) + (b[2]<<8) + b[3];
}

function paddingSignature(data, len) {
  for(let i = 0; i < len - data.length; i++){
    data = '0' + data
  }
  return data
}

module.exports = {
  hexToBytes,
  bytesToHex,
  randomBytes,
  randomInt32,
  paddingSignature,
}
