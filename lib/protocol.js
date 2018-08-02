'use strict';

const Is = require('is')
const crypto = require('./crypto')

const NKN_CLIENT_PROTOCOL_VERSION = '0.1'

let payloadTypes = {
  MESSAGE_PAYLOAD: 0,
  ACK_PAYLOAD: 1,
}

function genProtocolBasicHeader(type) {
  let timestamp = new Date().getTime()

  let pidInfo = crypto.tools.genProtocolPID(timestamp)

  return {
    version: NKN_CLIENT_PROTOCOL_VERSION,
    type: type,
    timestamp: timestamp,
    nonce: pidInfo.nonce,
    pid: pidInfo.pid,
  }
}

function protocolHeaderSimpleCheck(header) {
  return (
    Is.object(header)
    && Is.string(header.version)
    && Is.number(header.type)
  )
}

function toJSON() {
  return JSON.stringify({
    header: this.header,
    payload: this.payload
  })
}

function dataParse(dataJSON) {
  if(!Is.string(dataJSON)) {
    return false
  }

  let dataObj = JSON.parse(dataJSON)
  if(!dataObj) {
    return false
  }

  if(!protocolHeaderSimpleCheck(dataObj.header)) {
    return false
  }

  if(!Is.string(dataObj.payload)) {
    return false
  }

  return dataObj
}

function StringMessage(payload) {
  if(Is.undefined(payload)) {
    this.header = null
    this.payload = null

    return
  }

  this.header = genProtocolBasicHeader(payloadTypes.MESSAGE_PAYLOAD)
  this.payload = payload

  this.toJSON = function () {
    return toJSON.call(this)
  }
}

function genProtocolACKHeader() {
  return {
    version: NKN_CLIENT_PROTOCOL_VERSION,
    type: payloadTypes.ACK_PAYLOAD
  }
}

function ACK(pid) {
  this.header = genProtocolACKHeader()
  this.payload = pid

  this.toJSON = function () {
    return toJSON.call(this)
  }
}

module.exports = {
  payloadTypes: payloadTypes,
  dataParse: dataParse,

  stringMessage: StringMessage,
  ack: ACK,
}