'use strict';

const tools = require('../crypto/tools');

module.exports.getPubkey = function (addr) {
  // TODO: get dest pk if dest is name rather than pk
  let s = addr.split('.');
  return tools.hexToBytes(s[s.length-1]);
}
