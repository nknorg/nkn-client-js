[![CircleCI Status](https://circleci.com/gh/nknorg/nkn-client-js.svg?style=shield&circle-token=:circle-token)](https://circleci.com/gh/nknorg/nkn-client-js)

# nkn-client-js

JavaScript implementation of NKN client.

Send and receive data between any NKN clients without setting up a server.

Note: This is a **client** version of the NKN protocol, which can send and
receive data but **not** relay data (mining). For **node** implementation which
can mine NKN token by relaying data, please refer to
[nkn](https://github.com/nknorg/nkn/).

**Note: This repository is in the early development stage and may not have all
functions working properly. It should be used only for testing now.**

## Usage

For npm:

```shell
npm install nkn-client
```

And then in your code:

```javascript
const nkn = require('nkn-client');
```

For browser, use `dist/nkn.js` or `dist/nkn.min.js`.

Create a client with a generated key pair:

```javascript
const client = nkn();
```

Or with an identifier (used to distinguish different clients sharing the same
key pair):

```javascript
const client = nkn({
  identifier: 'any string',
});
```

Get client key pair:

```javascript
console.log(client.key.privateKey, client.key.publicKey);
```

Create a client using an existing private key:

```javascript
const client = nkn({
  identifier: 'any string',
  privateKey: 'cd5fa29ed5b0e951f3d1bce5997458706186320f1dd89156a73d54ed752a7f37',
});
```

Create a client using customized bootstrap RPC server (for getting node
address):

```javascript
const client = nkn({
  identifier: 'any string',
  seedRpcServerAddr: 'https://xxx',
});
```

Private key should be kept **SECRET**! Never put it in version control system
like here.

Get client identifier:

```javascript
console.log(client.identifier);
```

And client NKN address, which is used to receive data from other clients:

```javascript
console.log(client.addr);
```

Listen for connection established:

```javascript
client.on('connect', () => {
  console.log('Connection opened.');
});
```

Send data to other clients:

```javascript
client.send(
  'another client address',
  'some message',
);
```

Receive data from other clients:

```javascript
client.on('message', (src, payload) => {
  console.log(src, payload);
});
```
