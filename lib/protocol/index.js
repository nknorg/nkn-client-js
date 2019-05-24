'use strict';

const crypto = require('../crypto');
const messages = require('./messages_pb');
const payloads = require('./payloads_pb');

function newPayload(type, replyToPid, data) {
  let payload = new payloads.Payload();
  payload.setType(type);
  if (replyToPid) {
    payload.setReplyToPid(replyToPid);
  } else {
    payload.setPid(crypto.tools.genPID());
  }
  payload.setData(data);
  return payload;
}

module.exports.newBinaryPayload = function (data, replyToPid) {
  return newPayload(payloads.PayloadType.BINARY, replyToPid, data);
}

module.exports.newTextPayload = function (text, replyToPid) {
  let data = new payloads.TextData();
  data.setText(text);
  return newPayload(payloads.PayloadType.TEXT, replyToPid, data.serializeBinary());
}

module.exports.newAckPayload = function (replyToPid) {
  return newPayload(payloads.PayloadType.ACK, replyToPid);
}

module.exports.newMessage = function (payload, encrypted, nonce) {
  let msg = new payloads.Message();
  msg.setPayload(payload);
  msg.setEncrypted(encrypted);
  if (encrypted) {
    msg.setNonce(nonce);
  }
  return msg;
}

module.exports.messages = messages;
module.exports.payloads = payloads;
