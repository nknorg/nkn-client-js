'use strict';

function encodeUint8(value) {
  let buf = Buffer.alloc(1, 0);
  buf.writeUInt8(value);
  return buf.toString('hex');
}

function encodeUint16(value) {
  let buf = Buffer.alloc(2, 0);
  buf.writeUInt16LE(value);
  return buf.toString('hex');
}

function encodeUint32(value) {
  let buf = Buffer.alloc(4, 0);
  buf.writeUInt32LE(value);
  return buf.toString('hex');
}

function encodeUint64(value) {
  if (value >= 0xffffffffffff) {
    throw 'Value out of range. 48+ bit integer is not supported in JavaScript'
  }
  let buf = Buffer.alloc(8, 0);
  buf.writeUIntLE(value, 0, 6);
  return buf.toString('hex');
}

function encodeUint(value) {
  if (value < 0xfd) {
    return encodeUint8(value);
  } else if (value <= 0xffff) {
    return 'fd' + encodeUint16(value);
  } else if (value <= 0xffffffff) {
    return 'fe' + encodeUint32(value);
  } else {
    return 'ff' + encodeUint64(value);
  }
}

function encodeBytes(value) {
  let buf = Buffer.from(value);
  return encodeUint(buf.length) + buf.toString('hex');
}

function encodeString(value) {
  let buf = Buffer.from(value, 'utf8');
  return encodeUint(buf.length) + buf.toString('hex');
}

function encodeBool(value) {
  return encodeUint8(value ? 1 : 0);
}

module.exports = {
  encodeUint8,
  encodeUint16,
  encodeUint32,
  encodeUint64,
  encodeUint,
  encodeBytes,
  encodeString,
  encodeBool,
}
