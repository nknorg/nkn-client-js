'use strict';

module.exports = {
  errCodes: {
    success: 0,
    wrongNode: 48001,
  },
  defaultOptions: {
    reconnectIntervalMin: 1000,
    reconnectIntervalMax: 64000,
    responseTimeout: 5,
    msgHoldingSeconds: 3600,
    encrypt: true,
    seedRpcServerAddr: 'http://devnet-seed-0001.nkn.org:30003',
  },
};
