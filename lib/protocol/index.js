'use strict';

const pako = require('pako');
const nacl = require('tweetnacl');

const hash = require('../crypto/hash');
const tools = require('../crypto/tools');
const messages = require('./pb/messages_pb');
const payloads = require('./pb/payloads_pb');
const sigchain = require('./pb/sigchain_pb');
const serialize = require('./serialize');
const encryption = require('./encryption');

const pidSize = 8; // in bytes
const maxClientMessageSize = 4000000; // in bytes. Node is using 4*1024*1024 as limit, we give some additional space for serialization overhead.
const signatureLength = nacl.sign.signatureLength;

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

module.exports.newMessage = function (payload, encrypted, nonce, encryptedKey) {
  let msg = new payloads.Message();
  msg.setPayload(payload);
  msg.setEncrypted(encrypted);
  if (nonce) {
    msg.setNonce(nonce);
  }
  if (encryptedKey) {
    msg.setEncryptedKey(encryptedKey);
  }
  return msg;
}

function newClientMessage(messageType, message, compressionType) {
  let msg = new messages.ClientMessage();
  msg.setMessageType(messageType);
  msg.setCompressionType(compressionType);
  switch (compressionType) {
    case messages.CompressionType.COMPRESSION_NONE:
      break;
    case messages.CompressionType.COMPRESSION_ZLIB:
      message = pako.deflate(message);
      break;
    default:
      throw "unknown compression type " + compressionType;
  }
  msg.setMessage(message);
  return msg;
}

module.exports.newOutboundMessage = async function (dest, payload, maxHoldingSeconds) {
  if (!Array.isArray(dest)) {
    dest = [dest];
  }
  if (dest.length === 0) {
    throw "no destination";
  }

  if (!Array.isArray(payload)) {
    payload = [payload];
  }
  if (payload.length === 0) {
    throw "no payloads";
  }

  if (payload.length > 1 && payload.length !== dest.length) {
    throw "invalid payload count";
  }

  let sigChainElem = new sigchain.SigChainElem();
  sigChainElem.setNextPubkey(tools.hexToBytes(this.node.pubkey));
  let sigChainElemSerialized = serializeSigChainElem(sigChainElem);

  let sigChain = new sigchain.SigChain();
  sigChain.setNonce(tools.randomInt32());
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
    if (payload.length > 1) {
      sigChain.setDataSize(payload[i].length);
    } else {
      sigChain.setDataSize(payload[0].length);
    }
    hex = serializeSigChainMetadata(sigChain);
    digest = hash.sha256Hex(hex);
    digest = hash.sha256Hex(digest + sigChainElemSerialized);
    signature = await this.key.sign(Buffer.from(digest, 'hex'));
    signatures.push(tools.hexToBytes(signature));
  }

  let msg = new messages.OutboundMessage();
  msg.setDestsList(dest);
  msg.setPayloadsList(payload);
  msg.setMaxHoldingSeconds(maxHoldingSeconds);
  msg.setNonce(sigChain.getNonce());
  msg.setBlockHash(sigChain.getBlockHash());
  msg.setSignaturesList(signatures);

  let compressionType;
  if (payload.length > 1) {
    compressionType = messages.CompressionType.COMPRESSION_ZLIB;
  } else {
    compressionType = messages.CompressionType.COMPRESSION_NONE;
  }

  return newClientMessage(messages.ClientMessageType.OUTBOUND_MESSAGE, msg.serializeBinary(), compressionType);
}

module.exports.newReceipt = async function (prevSignature) {
  let sigChainElem = new sigchain.SigChainElem();
  let sigChainElemSerialized = serializeSigChainElem(sigChainElem);
  let digest = hash.sha256Hex(prevSignature);
  digest = hash.sha256Hex(digest + sigChainElemSerialized);
  let signature = await this.key.sign(Buffer.from(digest, 'hex'));
  let msg = new messages.Receipt();
  msg.setPrevSignature(tools.hexToBytes(prevSignature));
  msg.setSignature(tools.hexToBytes(signature));
  return newClientMessage(messages.ClientMessageType.RECEIPT, msg.serializeBinary(), messages.CompressionType.COMPRESSION_NONE);
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
module.exports.serialize = serialize;
module.exports.encryption = encryption;
module.exports.maxClientMessageSize = maxClientMessageSize;
module.exports.signatureLength = signatureLength;
