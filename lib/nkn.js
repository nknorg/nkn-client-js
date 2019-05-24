'use strict';

const Client = require('./client');
const consts = require('./const');
const crypto = require('./crypto');
const protocol = require('./protocol');

function nkn(options = {}) {
  let key = crypto.Key({
    seed: options.seed,
  });

  Object.keys(options).forEach(key => options[key] === undefined && delete options[key]);

  options = Object.assign({}, consts.defaultOptions, options);

  return Client(key, options.identifier, options);
}

module.exports = nkn;
module.exports.PayloadType = protocol.payloads.PayloadType;
