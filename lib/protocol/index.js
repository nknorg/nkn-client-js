'use strict';

const crypto = require('../crypto');
const messages = require('./messages_pb');
const payloads = require('./payloads_pb');

module.exports.newBinaryPayload = function (data, replyToPid) {
  let payload = new payloads.Payload();
  payload.setType(payloads.PayloadType.BINARY);
  if (replyToPid) {
    payload.setReplyToPid(replyToPid);
  } else {
    payload.setPid(crypto.tools.genPID());
  }
  payload.setData(data);
  return payload;
}

module.exports.newTextPayload = function (text, replyToPid) {
  let payload = new payloads.Payload();
  payload.setType(payloads.PayloadType.TEXT);
  if (replyToPid) {
    payload.setReplyToPid(replyToPid);
  } else {
    payload.setPid(crypto.tools.genPID());
  }
  let data = new payloads.TextData();
  data.setText(text);
  payload.setData(data.serializeBinary());
  return payload;
}

module.exports.newAckPayload = function (pid) {
  let payload = new payloads.Payload();
  payload.setType(payloads.PayloadType.ACK);
  payload.setReplyToPid(pid);
  return payload;
}

module.exports.messages = messages;
module.exports.payloads = payloads;
