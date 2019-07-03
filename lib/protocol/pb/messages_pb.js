/**
 * @fileoverview
 * @enhanceable
 * @suppress {messageConventions} JS Compiler reports an error if a variable or
 *     field starts with 'MSG_' and isn't a translatable message.
 * @public
 */
// GENERATED CODE -- DO NOT EDIT!

var jspb = require('google-protobuf');
var goog = jspb;
var global = Function('return this')();

goog.exportSymbol('proto.pb.ClientMessage', null, global);
goog.exportSymbol('proto.pb.ClientMessageType', null, global);
goog.exportSymbol('proto.pb.InboundMessage', null, global);
goog.exportSymbol('proto.pb.OutboundMessage', null, global);
goog.exportSymbol('proto.pb.Receipt', null, global);

/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.pb.ClientMessage = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.pb.ClientMessage, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  proto.pb.ClientMessage.displayName = 'proto.pb.ClientMessage';
}


if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto suitable for use in Soy templates.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     com.google.apps.jspb.JsClassTemplate.JS_RESERVED_WORDS.
 * @param {boolean=} opt_includeInstance Whether to include the JSPB instance
 *     for transitional soy proto support: http://goto/soy-param-migration
 * @return {!Object}
 */
proto.pb.ClientMessage.prototype.toObject = function(opt_includeInstance) {
  return proto.pb.ClientMessage.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Whether to include the JSPB
 *     instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.pb.ClientMessage} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.pb.ClientMessage.toObject = function(includeInstance, msg) {
  var f, obj = {
    messageType: jspb.Message.getFieldWithDefault(msg, 1, 0),
    message: msg.getMessage_asB64()
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.pb.ClientMessage}
 */
proto.pb.ClientMessage.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.pb.ClientMessage;
  return proto.pb.ClientMessage.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.pb.ClientMessage} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.pb.ClientMessage}
 */
proto.pb.ClientMessage.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {!proto.pb.ClientMessageType} */ (reader.readEnum());
      msg.setMessageType(value);
      break;
    case 2:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setMessage(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.pb.ClientMessage.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.pb.ClientMessage.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.pb.ClientMessage} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.pb.ClientMessage.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getMessageType();
  if (f !== 0.0) {
    writer.writeEnum(
      1,
      f
    );
  }
  f = message.getMessage_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      2,
      f
    );
  }
};


/**
 * optional ClientMessageType message_type = 1;
 * @return {!proto.pb.ClientMessageType}
 */
proto.pb.ClientMessage.prototype.getMessageType = function() {
  return /** @type {!proto.pb.ClientMessageType} */ (jspb.Message.getFieldWithDefault(this, 1, 0));
};


/** @param {!proto.pb.ClientMessageType} value */
proto.pb.ClientMessage.prototype.setMessageType = function(value) {
  jspb.Message.setProto3EnumField(this, 1, value);
};


/**
 * optional bytes message = 2;
 * @return {!(string|Uint8Array)}
 */
proto.pb.ClientMessage.prototype.getMessage = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * optional bytes message = 2;
 * This is a type-conversion wrapper around `getMessage()`
 * @return {string}
 */
proto.pb.ClientMessage.prototype.getMessage_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getMessage()));
};


/**
 * optional bytes message = 2;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getMessage()`
 * @return {!Uint8Array}
 */
proto.pb.ClientMessage.prototype.getMessage_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getMessage()));
};


/** @param {!(string|Uint8Array)} value */
proto.pb.ClientMessage.prototype.setMessage = function(value) {
  jspb.Message.setProto3BytesField(this, 2, value);
};



/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.pb.OutboundMessage = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.pb.OutboundMessage.repeatedFields_, null);
};
goog.inherits(proto.pb.OutboundMessage, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  proto.pb.OutboundMessage.displayName = 'proto.pb.OutboundMessage';
}
/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.pb.OutboundMessage.repeatedFields_ = [3,7];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto suitable for use in Soy templates.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     com.google.apps.jspb.JsClassTemplate.JS_RESERVED_WORDS.
 * @param {boolean=} opt_includeInstance Whether to include the JSPB instance
 *     for transitional soy proto support: http://goto/soy-param-migration
 * @return {!Object}
 */
proto.pb.OutboundMessage.prototype.toObject = function(opt_includeInstance) {
  return proto.pb.OutboundMessage.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Whether to include the JSPB
 *     instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.pb.OutboundMessage} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.pb.OutboundMessage.toObject = function(includeInstance, msg) {
  var f, obj = {
    dest: jspb.Message.getFieldWithDefault(msg, 1, ""),
    payload: msg.getPayload_asB64(),
    destsList: jspb.Message.getRepeatedField(msg, 3),
    maxHoldingSeconds: jspb.Message.getFieldWithDefault(msg, 4, 0),
    nonce: jspb.Message.getFieldWithDefault(msg, 5, 0),
    blockHash: msg.getBlockHash_asB64(),
    signaturesList: msg.getSignaturesList_asB64()
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.pb.OutboundMessage}
 */
proto.pb.OutboundMessage.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.pb.OutboundMessage;
  return proto.pb.OutboundMessage.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.pb.OutboundMessage} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.pb.OutboundMessage}
 */
proto.pb.OutboundMessage.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setDest(value);
      break;
    case 2:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setPayload(value);
      break;
    case 3:
      var value = /** @type {string} */ (reader.readString());
      msg.addDests(value);
      break;
    case 4:
      var value = /** @type {number} */ (reader.readUint32());
      msg.setMaxHoldingSeconds(value);
      break;
    case 5:
      var value = /** @type {number} */ (reader.readUint32());
      msg.setNonce(value);
      break;
    case 6:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setBlockHash(value);
      break;
    case 7:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.addSignatures(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.pb.OutboundMessage.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.pb.OutboundMessage.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.pb.OutboundMessage} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.pb.OutboundMessage.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getDest();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getPayload_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      2,
      f
    );
  }
  f = message.getDestsList();
  if (f.length > 0) {
    writer.writeRepeatedString(
      3,
      f
    );
  }
  f = message.getMaxHoldingSeconds();
  if (f !== 0) {
    writer.writeUint32(
      4,
      f
    );
  }
  f = message.getNonce();
  if (f !== 0) {
    writer.writeUint32(
      5,
      f
    );
  }
  f = message.getBlockHash_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      6,
      f
    );
  }
  f = message.getSignaturesList_asU8();
  if (f.length > 0) {
    writer.writeRepeatedBytes(
      7,
      f
    );
  }
};


/**
 * optional string dest = 1;
 * @return {string}
 */
proto.pb.OutboundMessage.prototype.getDest = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/** @param {string} value */
proto.pb.OutboundMessage.prototype.setDest = function(value) {
  jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional bytes payload = 2;
 * @return {!(string|Uint8Array)}
 */
proto.pb.OutboundMessage.prototype.getPayload = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * optional bytes payload = 2;
 * This is a type-conversion wrapper around `getPayload()`
 * @return {string}
 */
proto.pb.OutboundMessage.prototype.getPayload_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getPayload()));
};


/**
 * optional bytes payload = 2;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getPayload()`
 * @return {!Uint8Array}
 */
proto.pb.OutboundMessage.prototype.getPayload_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getPayload()));
};


/** @param {!(string|Uint8Array)} value */
proto.pb.OutboundMessage.prototype.setPayload = function(value) {
  jspb.Message.setProto3BytesField(this, 2, value);
};


/**
 * repeated string dests = 3;
 * @return {!Array<string>}
 */
proto.pb.OutboundMessage.prototype.getDestsList = function() {
  return /** @type {!Array<string>} */ (jspb.Message.getRepeatedField(this, 3));
};


/** @param {!Array<string>} value */
proto.pb.OutboundMessage.prototype.setDestsList = function(value) {
  jspb.Message.setField(this, 3, value || []);
};


/**
 * @param {!string} value
 * @param {number=} opt_index
 */
proto.pb.OutboundMessage.prototype.addDests = function(value, opt_index) {
  jspb.Message.addToRepeatedField(this, 3, value, opt_index);
};


proto.pb.OutboundMessage.prototype.clearDestsList = function() {
  this.setDestsList([]);
};


/**
 * optional uint32 max_holding_seconds = 4;
 * @return {number}
 */
proto.pb.OutboundMessage.prototype.getMaxHoldingSeconds = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 4, 0));
};


/** @param {number} value */
proto.pb.OutboundMessage.prototype.setMaxHoldingSeconds = function(value) {
  jspb.Message.setProto3IntField(this, 4, value);
};


/**
 * optional uint32 nonce = 5;
 * @return {number}
 */
proto.pb.OutboundMessage.prototype.getNonce = function() {
  return /** @type {number} */ (jspb.Message.getFieldWithDefault(this, 5, 0));
};


/** @param {number} value */
proto.pb.OutboundMessage.prototype.setNonce = function(value) {
  jspb.Message.setProto3IntField(this, 5, value);
};


/**
 * optional bytes block_hash = 6;
 * @return {!(string|Uint8Array)}
 */
proto.pb.OutboundMessage.prototype.getBlockHash = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldWithDefault(this, 6, ""));
};


/**
 * optional bytes block_hash = 6;
 * This is a type-conversion wrapper around `getBlockHash()`
 * @return {string}
 */
proto.pb.OutboundMessage.prototype.getBlockHash_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getBlockHash()));
};


/**
 * optional bytes block_hash = 6;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getBlockHash()`
 * @return {!Uint8Array}
 */
proto.pb.OutboundMessage.prototype.getBlockHash_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getBlockHash()));
};


/** @param {!(string|Uint8Array)} value */
proto.pb.OutboundMessage.prototype.setBlockHash = function(value) {
  jspb.Message.setProto3BytesField(this, 6, value);
};


/**
 * repeated bytes signatures = 7;
 * @return {!(Array<!Uint8Array>|Array<string>)}
 */
proto.pb.OutboundMessage.prototype.getSignaturesList = function() {
  return /** @type {!(Array<!Uint8Array>|Array<string>)} */ (jspb.Message.getRepeatedField(this, 7));
};


/**
 * repeated bytes signatures = 7;
 * This is a type-conversion wrapper around `getSignaturesList()`
 * @return {!Array<string>}
 */
proto.pb.OutboundMessage.prototype.getSignaturesList_asB64 = function() {
  return /** @type {!Array<string>} */ (jspb.Message.bytesListAsB64(
      this.getSignaturesList()));
};


/**
 * repeated bytes signatures = 7;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getSignaturesList()`
 * @return {!Array<!Uint8Array>}
 */
proto.pb.OutboundMessage.prototype.getSignaturesList_asU8 = function() {
  return /** @type {!Array<!Uint8Array>} */ (jspb.Message.bytesListAsU8(
      this.getSignaturesList()));
};


/** @param {!(Array<!Uint8Array>|Array<string>)} value */
proto.pb.OutboundMessage.prototype.setSignaturesList = function(value) {
  jspb.Message.setField(this, 7, value || []);
};


/**
 * @param {!(string|Uint8Array)} value
 * @param {number=} opt_index
 */
proto.pb.OutboundMessage.prototype.addSignatures = function(value, opt_index) {
  jspb.Message.addToRepeatedField(this, 7, value, opt_index);
};


proto.pb.OutboundMessage.prototype.clearSignaturesList = function() {
  this.setSignaturesList([]);
};



/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.pb.InboundMessage = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.pb.InboundMessage, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  proto.pb.InboundMessage.displayName = 'proto.pb.InboundMessage';
}


if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto suitable for use in Soy templates.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     com.google.apps.jspb.JsClassTemplate.JS_RESERVED_WORDS.
 * @param {boolean=} opt_includeInstance Whether to include the JSPB instance
 *     for transitional soy proto support: http://goto/soy-param-migration
 * @return {!Object}
 */
proto.pb.InboundMessage.prototype.toObject = function(opt_includeInstance) {
  return proto.pb.InboundMessage.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Whether to include the JSPB
 *     instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.pb.InboundMessage} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.pb.InboundMessage.toObject = function(includeInstance, msg) {
  var f, obj = {
    src: jspb.Message.getFieldWithDefault(msg, 1, ""),
    payload: msg.getPayload_asB64(),
    prevSignature: msg.getPrevSignature_asB64()
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.pb.InboundMessage}
 */
proto.pb.InboundMessage.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.pb.InboundMessage;
  return proto.pb.InboundMessage.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.pb.InboundMessage} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.pb.InboundMessage}
 */
proto.pb.InboundMessage.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {string} */ (reader.readString());
      msg.setSrc(value);
      break;
    case 2:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setPayload(value);
      break;
    case 3:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setPrevSignature(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.pb.InboundMessage.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.pb.InboundMessage.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.pb.InboundMessage} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.pb.InboundMessage.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getSrc();
  if (f.length > 0) {
    writer.writeString(
      1,
      f
    );
  }
  f = message.getPayload_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      2,
      f
    );
  }
  f = message.getPrevSignature_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      3,
      f
    );
  }
};


/**
 * optional string src = 1;
 * @return {string}
 */
proto.pb.InboundMessage.prototype.getSrc = function() {
  return /** @type {string} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/** @param {string} value */
proto.pb.InboundMessage.prototype.setSrc = function(value) {
  jspb.Message.setProto3StringField(this, 1, value);
};


/**
 * optional bytes payload = 2;
 * @return {!(string|Uint8Array)}
 */
proto.pb.InboundMessage.prototype.getPayload = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * optional bytes payload = 2;
 * This is a type-conversion wrapper around `getPayload()`
 * @return {string}
 */
proto.pb.InboundMessage.prototype.getPayload_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getPayload()));
};


/**
 * optional bytes payload = 2;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getPayload()`
 * @return {!Uint8Array}
 */
proto.pb.InboundMessage.prototype.getPayload_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getPayload()));
};


/** @param {!(string|Uint8Array)} value */
proto.pb.InboundMessage.prototype.setPayload = function(value) {
  jspb.Message.setProto3BytesField(this, 2, value);
};


/**
 * optional bytes prev_signature = 3;
 * @return {!(string|Uint8Array)}
 */
proto.pb.InboundMessage.prototype.getPrevSignature = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldWithDefault(this, 3, ""));
};


/**
 * optional bytes prev_signature = 3;
 * This is a type-conversion wrapper around `getPrevSignature()`
 * @return {string}
 */
proto.pb.InboundMessage.prototype.getPrevSignature_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getPrevSignature()));
};


/**
 * optional bytes prev_signature = 3;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getPrevSignature()`
 * @return {!Uint8Array}
 */
proto.pb.InboundMessage.prototype.getPrevSignature_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getPrevSignature()));
};


/** @param {!(string|Uint8Array)} value */
proto.pb.InboundMessage.prototype.setPrevSignature = function(value) {
  jspb.Message.setProto3BytesField(this, 3, value);
};



/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.pb.Receipt = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, null, null);
};
goog.inherits(proto.pb.Receipt, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  proto.pb.Receipt.displayName = 'proto.pb.Receipt';
}


if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto suitable for use in Soy templates.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     com.google.apps.jspb.JsClassTemplate.JS_RESERVED_WORDS.
 * @param {boolean=} opt_includeInstance Whether to include the JSPB instance
 *     for transitional soy proto support: http://goto/soy-param-migration
 * @return {!Object}
 */
proto.pb.Receipt.prototype.toObject = function(opt_includeInstance) {
  return proto.pb.Receipt.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Whether to include the JSPB
 *     instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.pb.Receipt} msg The msg instance to transform.
 * @return {!Object}
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.pb.Receipt.toObject = function(includeInstance, msg) {
  var f, obj = {
    prevSignature: msg.getPrevSignature_asB64(),
    signature: msg.getSignature_asB64()
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.pb.Receipt}
 */
proto.pb.Receipt.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.pb.Receipt;
  return proto.pb.Receipt.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.pb.Receipt} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.pb.Receipt}
 */
proto.pb.Receipt.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setPrevSignature(value);
      break;
    case 2:
      var value = /** @type {!Uint8Array} */ (reader.readBytes());
      msg.setSignature(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.pb.Receipt.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.pb.Receipt.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.pb.Receipt} message
 * @param {!jspb.BinaryWriter} writer
 * @suppress {unusedLocalVariables} f is only used for nested messages
 */
proto.pb.Receipt.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getPrevSignature_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      1,
      f
    );
  }
  f = message.getSignature_asU8();
  if (f.length > 0) {
    writer.writeBytes(
      2,
      f
    );
  }
};


/**
 * optional bytes prev_signature = 1;
 * @return {!(string|Uint8Array)}
 */
proto.pb.Receipt.prototype.getPrevSignature = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldWithDefault(this, 1, ""));
};


/**
 * optional bytes prev_signature = 1;
 * This is a type-conversion wrapper around `getPrevSignature()`
 * @return {string}
 */
proto.pb.Receipt.prototype.getPrevSignature_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getPrevSignature()));
};


/**
 * optional bytes prev_signature = 1;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getPrevSignature()`
 * @return {!Uint8Array}
 */
proto.pb.Receipt.prototype.getPrevSignature_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getPrevSignature()));
};


/** @param {!(string|Uint8Array)} value */
proto.pb.Receipt.prototype.setPrevSignature = function(value) {
  jspb.Message.setProto3BytesField(this, 1, value);
};


/**
 * optional bytes signature = 2;
 * @return {!(string|Uint8Array)}
 */
proto.pb.Receipt.prototype.getSignature = function() {
  return /** @type {!(string|Uint8Array)} */ (jspb.Message.getFieldWithDefault(this, 2, ""));
};


/**
 * optional bytes signature = 2;
 * This is a type-conversion wrapper around `getSignature()`
 * @return {string}
 */
proto.pb.Receipt.prototype.getSignature_asB64 = function() {
  return /** @type {string} */ (jspb.Message.bytesAsB64(
      this.getSignature()));
};


/**
 * optional bytes signature = 2;
 * Note that Uint8Array is not supported on all browsers.
 * @see http://caniuse.com/Uint8Array
 * This is a type-conversion wrapper around `getSignature()`
 * @return {!Uint8Array}
 */
proto.pb.Receipt.prototype.getSignature_asU8 = function() {
  return /** @type {!Uint8Array} */ (jspb.Message.bytesAsU8(
      this.getSignature()));
};


/** @param {!(string|Uint8Array)} value */
proto.pb.Receipt.prototype.setSignature = function(value) {
  jspb.Message.setProto3BytesField(this, 2, value);
};


/**
 * @enum {number}
 */
proto.pb.ClientMessageType = {
  OUTBOUND_MESSAGE: 0,
  INBOUND_MESSAGE: 1,
  RECEIPT: 2
};

goog.object.extend(exports, proto.pb);