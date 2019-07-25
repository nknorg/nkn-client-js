'use strict';

const hash = require('../crypto/hash');
const tools = require('../crypto/tools');
const messages = require('./pb/messages_pb');
const payloads = require('./pb/payloads_pb');
const sigchain = require('./pb/sigchain_pb');
const serialize = require('./serialize');

const pidSize = 8; // in bytes

function newPayload(type, replyToPid, data, msgPid) {
  let payload = new payloads.Payload();
  payload.setType(type);
  if (replyToPid) {
    payload.setReplyToPid(replyToPid);
  } else if (msgPid) {
    payload.setPid(msgPid);
  } else {
    payload.setPid(tools.randomBytes(pidSize));
  }
  payload.setData(data);
  return payload;
}

module.exports.newBinaryPayload = function (data, replyToPid, msgPid) {
  return newPayload(payloads.PayloadType.BINARY, replyToPid, data, msgPid);
}

module.exports.newTextPayload = function (text, replyToPid, msgPid) {
  let data = new payloads.TextData();
  data.setText(text);
  return newPayload(payloads.PayloadType.TEXT, replyToPid, data.serializeBinary(), msgPid);
}

module.exports.newAckPayload = function (replyToPid, msgPid) {
  return newPayload(payloads.PayloadType.ACK, replyToPid, null, msgPid);
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

function newClientMessage(messageType, message) {
  let msg = new messages.ClientMessage();
  msg.setMessageType(messageType);
  msg.setMessage(message);
  return msg;
}

module.exports.newOutboundMessage = function (dest, payload, maxHoldingSeconds) {
  if (!Array.isArray(dest)) {
    dest = [dest];
  }

  if (dest.length === 0) {
    throw "no destination";
  }

  let sigChainElem = new sigchain.SigChainElem();
  sigChainElem.setNextPubkey(tools.hexToBytes(this.node.pubkey));
  let sigChainElemSerialized = serializeSigChainElem(sigChainElem);

  let sigChain = new sigchain.SigChain();
  sigChain.setNonce(tools.randomInt32());
  sigChain.setDataSize(payload.length);
  if (this.sigChainBlockHash) {
    sigChain.setBlockHash(tools.hexToBytes(this.sigChainBlockHash));
  }
  sigChain.setSrcId(tools.hexToBytes(addr2Id(this.addr)));
  sigChain.setSrcPubkey(tools.hexToBytes(this.key.publicKey));

  let signatures = [];
  let hex, digest, signature;
  for (var i = 0; i < dest.length; i++) {
    // TODO: handle name service
    sigChain.setDestId(tools.hexToBytes(addr2Id(dest[i])));
    sigChain.setDestPubkey(tools.hexToBytes(addr2Pubkey(dest[i])));
    hex = serializeSigChainMetadata(sigChain);
    digest = hash.sha256Hex(hex);
    digest = hash.sha256Hex(digest + sigChainElemSerialized);
    signature = this.key.sign(Buffer.from(digest, 'hex'));
    signatures.push(tools.hexToBytes(signature));
  }

  let msg = new messages.OutboundMessage();
  msg.setDestsList(dest);
  msg.setPayload(payload);
  msg.setMaxHoldingSeconds(maxHoldingSeconds);
  msg.setNonce(sigChain.getNonce());
  msg.setBlockHash(sigChain.getBlockHash());
  msg.setSignaturesList(signatures);

  return newClientMessage(messages.ClientMessageType.OUTBOUND_MESSAGE, msg.serializeBinary());
}

module.exports.newReceipt = function (prevSignature) {
  let sigChainElem = new sigchain.SigChainElem();
  let sigChainElemSerialized = serializeSigChainElem(sigChainElem);
  let digest = hash.sha256Hex(prevSignature);
  digest = hash.sha256Hex(digest + sigChainElemSerialized);
  let signature = this.key.sign(Buffer.from(digest, 'hex'));
  let msg = new messages.Receipt();
  msg.setPrevSignature(tools.hexToBytes(prevSignature));
  msg.setSignature(tools.hexToBytes(signature));
  return newClientMessage(messages.ClientMessageType.RECEIPT, msg.serializeBinary());
}

function serializeSigChainMetadata(sigChain) {
  let hex = '';
  hex += serialize.encodeUint32(sigChain.getNonce());
  hex += serialize.encodeUint32(sigChain.getDataSize());
  hex += serialize.encodeBytes(sigChain.getBlockHash());
  hex += serialize.encodeBytes(sigChain.getSrcId());
  hex += serialize.encodeBytes(sigChain.getSrcPubkey());
  hex += serialize.encodeBytes(sigChain.getDestId());
  hex += serialize.encodeBytes(sigChain.getDestPubkey());
  return hex;
}

function serializeSigChainElem(sigChainElem) {
  let hex = '';
  hex += serialize.encodeBytes(sigChainElem.getId());
  hex += serialize.encodeBytes(sigChainElem.getNextPubkey());
  hex += serialize.encodeBool(sigChainElem.getMining());
  return hex;
}

function addr2Id(addr) {
  return hash.sha256(addr)
}

function addr2Pubkey(addr) {
  let s = addr.split('.');
  return s[s.length - 1];
}

module.exports.messages = messages;
module.exports.payloads = payloads;
module.exports.pidSize = pidSize;
