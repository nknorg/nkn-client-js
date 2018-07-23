// Example of nkn-client-js for Node.js
// Usage: node node_example.js

const crypto = require('crypto');
const nkn = require('../lib/nkn');

const timeout = 5000;
var timeSent, timeReceived;

function generateMessage() {
  let fromClient = nkn({
    // neither of these are required, as shown in toClient below
    identifier: crypto.randomBytes(8).toString('hex'),
    privateKey: 'cd5fa29ed5b0e951f3d1bce5997458706186320f1dd89156a73d54ed752a7f37',
  });

  fromClient.on('connect', () => {
    try {
      let toClient = nkn();
      toClient.on('connect', () => {
        try {
          fromClient.send(
            toClient.addr,
            'This is a generated message.',
          );
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
      toClient.on('message', (src, payload) => {
        timeReceived = new Date();
        console.log('Receive message from', src, 'after', timeReceived - timeSent, 'ms');
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
