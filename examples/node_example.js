// Example of nkn-client-js for Node.js
// Usage: node node_example.js seedRpcServerAddr timeoutInMilliSeconds

const crypto = require('crypto');
const nkn = require('../lib/nkn');

// Never put private key in version control system like here!
const privateKey = 'cd5fa29ed5b0e951f3d1bce5997458706186320f1dd89156a73d54ed752a7f37';
const seedRpcServerAddr = process.argv[2];
const timeout = parseInt(process.argv[3]) || 5000;
const logPrefix = '[' + (process.argv[4] || '') + ']';
var timeSent, timeReceived;

function generateMessage() {
  let fromClient = nkn({
    // neither of these are required, as shown in toClient below
    identifier: crypto.randomBytes(8).toString('hex'),
    privateKey: privateKey,
    seedRpcServerAddr: seedRpcServerAddr,
  });

  fromClient.on('connect', () => {
    try {
      let toClient = nkn({
        identifier: crypto.randomBytes(8).toString('hex'),
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
            console.log(logPrefix, 'Receive', '"' + data + '"', 'from', toClient.addr, 'after', timeReceived - timeSent, 'ms');
          }).catch((e) => {
            console.log(logPrefix, 'Catch: ', e);
          });
          timeSent = new Date();
          console.log(logPrefix, 'Send message from', fromClient.addr, 'to', toClient.addr);
          setTimeout(function () {
            try {
              toClient.close();
              if (timeReceived === undefined) {
                console.log(logPrefix, 'Message from', fromClient.nodeAddr, 'to', toClient.nodeAddr, 'timeout');
              }
            } catch (e) {
              console.error(logPrefix, e);
            }
          }, timeout);
        } catch (e) {
          console.error(logPrefix, e);
        }
      });
      // can also be async (src, payload, payloadType) => {}
      toClient.on('message', (src, payload, payloadType) => {
        timeReceived = new Date();
        var type;
        if (payloadType === nkn.PayloadType.TEXT) {
          type = 'text';
        } else if (payloadType === nkn.PayloadType.BINARY) {
          type = 'binary';
        }
        console.log(logPrefix, 'Receive', type, 'message', '"' + payload + '"','from', src, 'after', timeReceived - timeSent, 'ms');
        // Send a text response
        return 'Well received!';
        // For byte array response:
        // return Uint8Array.from([1,2,3,4,5])
      });
      setTimeout(function () {
        try {
          fromClient.close();
        } catch (e) {
          console.error(logPrefix, e);
        }
      }, timeout);
    } catch (e) {
      console.error(logPrefix, e);
    }
  });
}

generateMessage();
