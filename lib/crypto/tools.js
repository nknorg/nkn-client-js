'use strict';

const Is = require('is')
const SHA256 = require('crypto-js/sha256')
const Mathjs = require('mathjs')

function array2HexString (bytes) {
  return Array.from(bytes, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2)
  }).join('')
}

function genProtocolPID(timestamp) {
  let nonce = array2HexString(Mathjs.random([32], 255))
  let pid = SHA256(timestamp + nonce).toString()

  return {
    nonce: nonce,
    pid: pid,
  }
}

module.exports = {
  genProtocolPID: genProtocolPID,
}