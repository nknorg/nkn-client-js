'use strict';

const crypto = require('../crypto');
const messages = require('./messages_pb');
const payloads = require('./payloads_pb');

module.exports.newBinaryPayload = function (data, replyToPid) {
  let payload = new payloads.Payload();
  payload.setType(payloads.PayloadType.BINARY);
  payload.setPid(crypto.tools.genPID());
  payload.setData(data);
  if (replyToPid) {
    payload.setReplyToPid(replyToPid);
  }
  return payload;
}

module.exports.newTextPayload = function (text, replyToPid) {
  let data = new payloads.TextData();
  data.setText(text);

  let payload = new payloads.Payload();
  payload.setType(payloads.PayloadType.TEXT);
  payload.setPid(crypto.tools.genPID());
  payload.setData(data.serializeBinary());
  if (replyToPid) {
    payload.setReplyToPid(replyToPid);
  }
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
