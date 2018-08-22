// Example of nkn-client-js for Node.js
// Usage: node node_example.js

const crypto = require('crypto');
const nkn = require('../lib/nkn');

// Use default seed rpc server:
const seedRpcServerAddr = undefined;
// Use local seed rpc server:
// const seedRpcServerAddr = 'http://127.0.0.1:30003';
const timeout = 5000;
var timeSent, timeReceived;

function generateMessage() {
  let fromClient = nkn({
    // neither of these are required, as shown in toClient below
    identifier: crypto.randomBytes(8).toString('hex'),
    privateKey: 'cd5fa29ed5b0e951f3d1bce5997458706186320f1dd89156a73d54ed752a7f37',
    seedRpcServerAddr: seedRpcServerAddr,
  });

  fromClient.on('connect', () => {
    try {
      let toClient = nkn({
        seedRpcServerAddr: seedRpcServerAddr,
      });
      toClient.on('connect', () => {
        try {
          fromClient.send(
            toClient.addr,
            'Hello world!',
            // For byte array:
            // Uint8Array.from([1,2,3,4,5]),
          ).then((data) => {
            timeReceived = new Date();
            console.log('Receive', '"' + data + '"', 'from', toClient.addr, 'after', timeReceived - timeSent, 'ms');
          }).catch((e) => {
            console.log('Catch: ', e);
          });
          timeSent = new Date();
          console.log('Send message from', fromClient.addr, 'to', toClient.addr);
          setTimeout(function () {
            try {
              toClient.close();
              if (timeReceived === undefined) {
                console.log('Message from', fromClient.nodeAddr, 'to', toClient.nodeAddr, 'timeout');
              }
            } catch (e) {
              console.error(e);
            }
          }, timeout);
        } catch (e) {
          console.error(e);
        }
      });
      toClient.on('message', (src, payload, payloadType) => {
        timeReceived = new Date();
        var type;
        if (payloadType === nkn.PayloadType.TEXT) {
          type = 'text';
        } else if (payloadType === nkn.PayloadType.BINARY) {
          type = 'binary';
        }
        console.log('Receive', type, 'message', '"' + payload + '"','from', src, 'after', timeReceived - timeSent, 'ms');
        // Send a text response
        return 'Well received!';
        // For byte array response:
        // return Uint8Array.from([1,2,3,4,5])
      });
      setTimeout(function () {
        try {
          fromClient.close();
        } catch (e) {
          console.error(e);
        }
      }, timeout);
    } catch (e) {
      console.error(e);
    }
  });
}

generateMessage();
