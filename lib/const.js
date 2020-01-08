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
    seedRpcServerAddr: 'https://mainnet-rpc-node-0001.nkn.org/mainnet/api/wallet',
  },
};
