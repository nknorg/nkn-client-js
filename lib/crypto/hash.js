'use strict';

const CryptoJS = require('crypto-js');

function cryptoHexStringParse(hexString) {
  return CryptoJS.enc.Hex.parse(hexString)
}

function sha256(str) {
  return CryptoJS.SHA256(str).toString();
}

function sha256Hex(hexStr) {
  return sha256(cryptoHexStringParse(hexStr));
}

function doubleSha256(str) {
  return CryptoJS.SHA256(CryptoJS.SHA256(str)).toString();
}

function doubleSha256Hex(hexStr) {
  return CryptoJS.SHA256(CryptoJS.SHA256(cryptoHexStringParse(hexStr))).toString();
}

function ripemd160(str) {
  return CryptoJS.RIPEMD160(str).toString();
}

function ripemd160Hex(hexStr) {
  return CryptoJS.RIPEMD160(cryptoHexStringParse(hexStr)).toString();
}

module.exports = {
  sha256,
  sha256Hex,
  doubleSha256,
  doubleSha256Hex,
  ripemd160,
  ripemd160Hex,
  cryptoHexStringParse,
}
